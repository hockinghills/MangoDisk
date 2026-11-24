//! Administrator-rights process facts for the running-program inventory.
//!
//! Without root, other users' processes hide their program file, working folder, proportional
//! memory and environment. When the user asks for it, the scan runs this same executable through
//! `pkexec` in a helper mode that reads only those facts from `/proc` and prints them as JSON.
//!
//! The boundary is deliberately narrow: the helper takes no input besides its fixed argument,
//! never writes anything, does not follow paths inside other processes' file systems, and keeps
//! only [`ENVIRONMENT_KEYS`] from each environment. Everything else (package databases,
//! `systemctl --user`, the home folder) stays in the unprivileged scan.

use std::{collections::BTreeMap, ffi::OsString, fs, io::Write, path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

use super::proc_reader::{
    list_pids, parse_proportional_kb, parse_stat, read_environment, read_text, RawProcess,
};
use crate::{
    command::{
        run_controlled_command_with_log_policy, ControlledCommandError, ControlledCommandLimits,
        ControlledCommandLogPolicy, ControlledEnvironmentPolicy, ControlledExecutable,
    },
    PlatformCancellation, PlatformError, PlatformErrorCode, PlatformFailureReason, PlatformResult,
};

pub(crate) const HELPER_ARGUMENT: &str = "--mangodisk-running-programs-facts";
const HELPER_PREFIX: &str = "--mangodisk-running-programs-";
const SCHEMA_VERSION: u32 = 1;
const HELPER_USAGE_EXIT_CODE: i32 = 64;
const HELPER_FAILURE_EXIT_CODE: i32 = 70;
/// pkexec's documented exit codes: the dialog was dismissed, or authorization failed.
const PKEXEC_DISMISSED: i32 = 126;
const PKEXEC_NOT_AUTHORIZED: i32 = 127;
/// Long enough to read and answer the desktop's password dialog.
const AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(300);
const HELPER_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const PKEXEC_CANDIDATES: &[&str] = &["/usr/bin/pkexec", "/bin/pkexec"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ElevatedProcessFacts {
    pub pid: u32,
    pub start_ticks: u64,
    pub executable_link: Option<PathBuf>,
    pub working_directory: Option<PathBuf>,
    pub proportional_kb: Option<u64>,
    pub environment: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HelperOutput {
    schema_version: u32,
    processes: Vec<ElevatedProcessFacts>,
}

fn read_facts(pid: u32) -> Option<ElevatedProcessFacts> {
    let base = PathBuf::from(format!("/proc/{pid}"));
    let stat = parse_stat(&read_text(&base.join("stat"), 4096)?)?;
    Some(ElevatedProcessFacts {
        pid,
        start_ticks: stat.start_ticks,
        // read_link returns the link text; it never opens the target.
        executable_link: fs::read_link(base.join("exe")).ok(),
        working_directory: fs::read_link(base.join("cwd")).ok(),
        proportional_kb: read_text(&base.join("smaps_rollup"), 64 * 1024)
            .as_deref()
            .and_then(parse_proportional_kb),
        environment: read_environment(pid),
    })
}

/// Runs the helper when the executable was started with [`HELPER_ARGUMENT`]. Any other
/// argument with the helper prefix is refused so a malformed call never starts the GUI.
pub fn run_running_programs_helper_mode<I>(arguments: I) -> Option<i32>
where
    I: IntoIterator<Item = OsString>,
{
    let arguments: Vec<OsString> = arguments.into_iter().collect();
    let first = arguments.get(1).and_then(|value| value.to_str())?;
    if !first.starts_with(HELPER_PREFIX) {
        return None;
    }
    if first != HELPER_ARGUMENT || arguments.len() != 2 {
        return Some(HELPER_USAGE_EXIT_CODE);
    }
    let output = HelperOutput {
        schema_version: SCHEMA_VERSION,
        processes: list_pids().into_iter().filter_map(read_facts).collect(),
    };
    let Ok(json) = serde_json::to_vec(&output) else {
        return Some(HELPER_FAILURE_EXIT_CODE);
    };
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(&json)
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return Some(HELPER_FAILURE_EXIT_CODE);
    }
    Some(0)
}

fn parse_helper_output(stdout: &[u8]) -> PlatformResult<BTreeMap<u32, ElevatedProcessFacts>> {
    let output: HelperOutput = serde_json::from_slice(stdout).map_err(|error| {
        PlatformError::new(
            PlatformErrorCode::InvalidData,
            format!("running-programs helper output is invalid: {error}"),
        )
    })?;
    if output.schema_version != SCHEMA_VERSION {
        return Err(PlatformError::new(
            PlatformErrorCode::InvalidData,
            format!(
                "running-programs helper schema {} is not {SCHEMA_VERSION}",
                output.schema_version
            ),
        ));
    }
    let keep_known_keys = |mut facts: ElevatedProcessFacts| {
        facts
            .environment
            .retain(|key, _| super::proc_reader::ENVIRONMENT_KEYS.contains(&key.as_str()));
        facts
    };
    Ok(output
        .processes
        .into_iter()
        .map(|facts| (facts.pid, keep_known_keys(facts)))
        .collect())
}

fn pkexec_error(code: Option<i32>) -> PlatformError {
    match code {
        Some(PKEXEC_DISMISSED) => PlatformError::new(
            PlatformErrorCode::UserCancelled,
            "administrator authorization was dismissed",
        ),
        Some(PKEXEC_NOT_AUTHORIZED) => PlatformError::new(
            PlatformErrorCode::AccessDenied,
            "administrator authorization failed",
        ),
        other => PlatformError::operation_failed(format!(
            "running-programs helper exited with {other:?}"
        )),
    }
}

/// Asks for administrator rights through polkit and returns the helper's facts by pid, or
/// `None` when pkexec is not installed and the scan has to continue without them.
pub(super) fn capture_elevated_facts(
    cancellation: &PlatformCancellation,
) -> PlatformResult<Option<BTreeMap<u32, ElevatedProcessFacts>>> {
    let Some(pkexec) = PKEXEC_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
    else {
        log::warn!("running_programs_elevation_unavailable reason=pkexec_missing");
        return Ok(None);
    };
    // pkexec needs an absolute path, and the password dialog shows it to the user.
    let helper = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| PlatformError::io("resolve running-programs helper", &error))?;
    let executable = ControlledExecutable::capture(&pkexec).map_err(|error| {
        PlatformError::operation_failed(format!("pkexec cannot be run: {}", error.as_str()))
    })?;
    let helper_text = helper.to_string_lossy().into_owned();
    let output = run_controlled_command_with_log_policy(
        "running_programs.pkexec_helper",
        &executable,
        &[helper_text.as_str(), HELPER_ARGUMENT],
        // pkexec finds the session's polkit agent through the caller's session.
        ControlledEnvironmentPolicy::Inherit,
        ControlledCommandLimits {
            timeout: AUTHORIZATION_TIMEOUT,
            stdout_bytes: HELPER_OUTPUT_BYTES,
            stderr_bytes: 64 * 1024,
        },
        ControlledCommandLogPolicy::ExceptionalOnly,
        &|| cancellation.is_cancelled(),
    )
    .map_err(|error| match error {
        ControlledCommandError::Cancelled => PlatformError::new(
            PlatformErrorCode::UserCancelled,
            "running-program capture was cancelled",
        ),
        ControlledCommandError::TimedOut => PlatformError::new(
            PlatformErrorCode::OperationFailed,
            "administrator authorization timed out",
        )
        .with_failure_reason(PlatformFailureReason::TimedOut),
        other => PlatformError::operation_failed(format!(
            "running-programs helper did not run: {}",
            other.as_str()
        )),
    })?;
    if !output.status.success() {
        return Err(pkexec_error(output.status.code()));
    }
    parse_helper_output(&output.stdout).map(Some)
}

/// Fills facts the unprivileged read could not see. A pid whose start time differs is a
/// different process that reused the number, so its facts are ignored.
pub(super) fn apply_elevated_facts(
    process: &mut RawProcess,
    facts: &BTreeMap<u32, ElevatedProcessFacts>,
) {
    let Some(facts) = facts
        .get(&process.pid)
        .filter(|facts| facts.start_ticks == process.start_ticks)
    else {
        return;
    };
    if process.executable.is_none() {
        if let Some(link) = &facts.executable_link {
            let (path, replaced) = super::proc_reader::parse_executable_link(link);
            process.executable = Some(path);
            process.executable_replaced = replaced;
        }
    }
    if process.working_directory.is_none() {
        process.working_directory = facts.working_directory.clone();
    }
    if process.proportional_kb.is_none() {
        process.proportional_kb = facts.proportional_kb;
    }
    for (key, value) in &facts.environment {
        process
            .environment
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
    if process.appimage.is_none() {
        process.appimage =
            super::proc_reader::appimage_path(process.executable.as_deref(), &process.environment);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(pid: u32, start_ticks: u64) -> RawProcess {
        RawProcess {
            pid,
            parent_pid: 1,
            uid: 0,
            name: "daemon".into(),
            command_line: vec!["daemon".into()],
            executable: None,
            executable_replaced: false,
            working_directory: None,
            cgroup: None,
            started_at_ms: 0,
            start_ticks,
            cpu_ticks: 0,
            resident_kb: 100,
            proportional_kb: None,
            swap_kb: 0,
            environment: BTreeMap::new(),
            appimage: None,
            flatpak_id: None,
        }
    }

    fn facts(pid: u32, start_ticks: u64) -> ElevatedProcessFacts {
        ElevatedProcessFacts {
            pid,
            start_ticks,
            executable_link: Some(PathBuf::from("/usr/sbin/daemon (deleted)")),
            working_directory: Some(PathBuf::from("/var/lib/daemon")),
            proportional_kb: Some(42),
            environment: [("_".to_owned(), "/usr/sbin/daemon".to_owned())]
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn helper_facts_fill_only_missing_values_of_the_same_process() {
        let map: BTreeMap<u32, ElevatedProcessFacts> = [(10, facts(10, 500))].into_iter().collect();
        let mut process = raw(10, 500);
        apply_elevated_facts(&mut process, &map);
        assert_eq!(process.executable, Some(PathBuf::from("/usr/sbin/daemon")));
        assert!(process.executable_replaced);
        assert_eq!(process.proportional_kb, Some(42));
        assert_eq!(process.environment["_"], "/usr/sbin/daemon");

        let mut reused = raw(10, 999);
        apply_elevated_facts(&mut reused, &map);
        assert_eq!(reused.executable, None, "a reused pid gets no facts");

        let mut readable = raw(10, 500);
        readable.proportional_kb = Some(7);
        apply_elevated_facts(&mut readable, &map);
        assert_eq!(
            readable.proportional_kb,
            Some(7),
            "facts read without elevation are kept"
        );
    }

    #[test]
    fn helper_output_is_validated_and_limited_to_known_keys() {
        let mut process = facts(10, 500);
        process
            .environment
            .insert("AWS_SECRET_ACCESS_KEY".into(), "x".into());
        let json = serde_json::to_vec(&HelperOutput {
            schema_version: SCHEMA_VERSION,
            processes: vec![process],
        })
        .unwrap();
        let parsed = parse_helper_output(&json).expect("valid output");
        assert!(!parsed[&10]
            .environment
            .contains_key("AWS_SECRET_ACCESS_KEY"));
        let old = br#"{"schemaVersion":0,"processes":[]}"#;
        assert_eq!(
            parse_helper_output(old).unwrap_err().code(),
            PlatformErrorCode::InvalidData
        );
        assert_eq!(
            parse_helper_output(b"not json").unwrap_err().code(),
            PlatformErrorCode::InvalidData
        );
    }

    #[test]
    fn helper_mode_only_claims_its_own_arguments() {
        let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(run_running_programs_helper_mode(args(&["mangodisk"])), None);
        assert_eq!(
            run_running_programs_helper_mode(args(&["mangodisk", "--other"])),
            None
        );
        assert_eq!(
            run_running_programs_helper_mode(args(&[
                "mangodisk",
                "--mangodisk-running-programs-x"
            ])),
            Some(HELPER_USAGE_EXIT_CODE)
        );
        assert_eq!(
            run_running_programs_helper_mode(args(&["mangodisk", HELPER_ARGUMENT, "extra"])),
            Some(HELPER_USAGE_EXIT_CODE)
        );
    }

    #[test]
    fn pkexec_exit_codes_map_to_typed_errors() {
        assert_eq!(
            pkexec_error(Some(126)).code(),
            PlatformErrorCode::UserCancelled
        );
        assert_eq!(
            pkexec_error(Some(127)).code(),
            PlatformErrorCode::AccessDenied
        );
        assert_eq!(
            pkexec_error(Some(1)).code(),
            PlatformErrorCode::OperationFailed
        );
    }
}
