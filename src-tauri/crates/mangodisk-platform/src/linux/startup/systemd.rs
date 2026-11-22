//! systemd user and system services that start at login or boot.
//!
//! State comes from `systemctl` itself rather than from unit files, so presets, drop-ins and
//! `/etc` overrides are already applied. Switching a service on or off only changes whether it
//! starts next time (`systemctl enable|disable`); it never stops a running service. System
//! services are changed through `systemctl` without `sudo`: systemd asks polkit, and the
//! desktop's polkit agent shows its own password dialog.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

use super::{matches_any_prefix, modified_at_ms, resolve_program, same_mutation_facts};
use crate::{
    command::{
        run_controlled_command_with_log_policy, ControlledCommandError, ControlledCommandLimits,
        ControlledCommandLogPolicy, ControlledEnvironmentPolicy, ControlledExecutable,
    },
    PlatformCancellation, PlatformError, PlatformErrorCode, PlatformFailureReason, PlatformResult,
    PlatformStartupArtifact, PlatformStartupChangeRequest, PlatformStartupChangeResult,
    PlatformStartupConfiguredState, PlatformStartupControlCapability,
    PlatformStartupCoverageReason, PlatformStartupCoverageStatus, PlatformStartupDesiredState,
    PlatformStartupDiagnosticCode, PlatformStartupIdentityConfidence, PlatformStartupOwner,
    PlatformStartupRuntimeState, PlatformStartupScope, PlatformStartupSourceKind,
    PlatformStartupSourceResult, PlatformStartupSummarySource, PlatformStartupTarget,
    PlatformStartupTargetKind, PlatformStartupTrigger, PlatformStartupTrustState,
};

pub(super) const USER_SOURCE_ID: &str = "linux.systemd.user_services";
pub(super) const SYSTEM_SOURCE_ID: &str = "linux.systemd.system_services";

const QUERY_LIMITS: ControlledCommandLimits = ControlledCommandLimits {
    timeout: Duration::from_secs(20),
    stdout_bytes: 4 * 1024 * 1024,
    stderr_bytes: 64 * 1024,
};
/// Long enough for the user to read and answer a polkit password dialog.
const CHANGE_LIMITS: ControlledCommandLimits = ControlledCommandLimits {
    timeout: Duration::from_secs(180),
    stdout_bytes: 64 * 1024,
    stderr_bytes: 64 * 1024,
};
const SHOW_BATCH: usize = 128;
const SHOW_PROPERTIES: &str = "Id,Description,FragmentPath,ExecStart,UnitFileState,ActiveState";

/// Units the desktop session or the boot depends on. They stay visible but read-only here.
const SESSION_USER_UNIT_PREFIXES: &[&str] = &[
    "at-spi",
    "dbus",
    "dconf",
    "gnome-",
    "gvfs-",
    "kde",
    "kwin",
    "org.freedesktop.",
    "org.gnome.",
    "pipewire",
    "plasma-",
    "pulseaudio",
    "systemd-",
    "wireplumber",
    "xdg-",
];
const ESSENTIAL_SYSTEM_UNIT_PREFIXES: &[&str] = &[
    "accounts-daemon",
    "apparmor",
    "console-setup",
    "cryptsetup",
    "dbus",
    "display-manager",
    "gdm",
    "getty",
    "keyboard-setup",
    "kmod",
    "lightdm",
    "lvm2",
    "multipathd",
    "NetworkManager",
    "plymouth",
    "polkit",
    "rtkit-daemon",
    "sddm",
    "serial-getty",
    "setvtrgb",
    "systemd-",
    "udisks2",
    "upower",
    "wpa_supplicant",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnitScope {
    User,
    System,
}

impl UnitScope {
    fn source_id(self) -> &'static str {
        match self {
            Self::User => USER_SOURCE_ID,
            Self::System => SYSTEM_SOURCE_ID,
        }
    }

    fn scope_args(self) -> &'static [&'static str] {
        match self {
            Self::User => &["--user"],
            Self::System => &[],
        }
    }

    fn item_prefix(self) -> &'static str {
        match self {
            Self::User => "linux.systemd.user:",
            Self::System => "linux.systemd.system:",
        }
    }
}

/// One row of `systemctl list-unit-files`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnitFileRow {
    name: String,
    state: String,
    preset: Option<String>,
}

/// Properties from `systemctl show`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct UnitDetails {
    description: String,
    fragment_path: Option<PathBuf>,
    exec_argv: Vec<String>,
    active_state: String,
}

fn systemctl() -> Option<ControlledExecutable> {
    ["/usr/bin/systemctl", "/bin/systemctl"]
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .and_then(|path| ControlledExecutable::capture(path).ok())
}

fn run_systemctl(
    command_id: &'static str,
    executable: &ControlledExecutable,
    scope: UnitScope,
    args: &[&str],
    limits: ControlledCommandLimits,
    cancellation: &PlatformCancellation,
) -> Result<(bool, String), ControlledCommandError> {
    let mut all_args: Vec<&str> = scope.scope_args().to_vec();
    all_args.extend_from_slice(args);
    let output = run_controlled_command_with_log_policy(
        command_id,
        executable,
        &all_args,
        // `--user` needs the session's D-Bus address and runtime directory.
        ControlledEnvironmentPolicy::Inherit,
        limits,
        ControlledCommandLogPolicy::ExceptionalOnly,
        &|| cancellation.is_cancelled(),
    )?;
    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    ))
}

/// A unit name as systemd prints it. Anything else is rejected before it reaches `systemctl`.
fn is_valid_unit_name(name: &str) -> bool {
    name.len() <= 256
        && name.ends_with(".service")
        && !name.starts_with('-')
        && name.chars().all(|ch| {
            ch.is_ascii_alphanumeric() || matches!(ch, ':' | '_' | '.' | '@' | '-' | '\\')
        })
}

fn parse_unit_files(text: &str) -> Vec<UnitFileRow> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let state = fields.next()?;
            Some(UnitFileRow {
                name: name.to_string(),
                state: state.to_string(),
                preset: fields
                    .next()
                    .filter(|preset| *preset != "-")
                    .map(String::from),
            })
        })
        .filter(|row| is_valid_unit_name(&row.name))
        .collect()
}

/// Parses `systemctl show` output for several units; blocks are separated by blank lines.
fn parse_show(text: &str) -> BTreeMap<String, UnitDetails> {
    let mut units = BTreeMap::new();
    for block in text.split("\n\n") {
        let mut id = None;
        let mut details = UnitDetails::default();
        for line in block.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "Id" => id = Some(value.to_string()),
                "Description" => details.description = value.to_string(),
                "FragmentPath" if !value.is_empty() => {
                    details.fragment_path = Some(PathBuf::from(value))
                }
                "ExecStart" if details.exec_argv.is_empty() => {
                    details.exec_argv = parse_exec_argv(value)
                }
                "ActiveState" => details.active_state = value.to_string(),
                _ => {}
            }
        }
        if let Some(id) = id {
            units.insert(id, details);
        }
    }
    units
}

/// Extracts the command line from `ExecStart={ path=… ; argv[]=/usr/bin/x --flag ; … }`.
fn parse_exec_argv(value: &str) -> Vec<String> {
    value
        .split_once("argv[]=")
        .map(|(_, rest)| rest.split(" ;").next().unwrap_or_default())
        .unwrap_or_default()
        .split_whitespace()
        .map(String::from)
        .collect()
}

/// Which listed unit files count as startup items. Enabled units always do. A disabled unit is
/// shown when its vendor preset would enable it (someone switched it off) or when an
/// administrator or the user added it under `/etc` or the home folder; disabled package units
/// that were never on are not startup items. Templates (`name@.service`) have no instance to
/// switch and are left out.
fn is_startup_candidate(row: &UnitFileRow, fragment: Option<&Path>, home: Option<&Path>) -> bool {
    if row.name.contains("@.") {
        return false;
    }
    match row.state.as_str() {
        "enabled" | "enabled-runtime" => true,
        "disabled" => {
            row.preset.as_deref() == Some("enabled")
                || fragment.is_some_and(|path| {
                    path.starts_with("/etc") || home.is_some_and(|home| path.starts_with(home))
                })
        }
        _ => false,
    }
}

fn artifact(
    scope: UnitScope,
    row: &UnitFileRow,
    details: &UnitDetails,
    privileged: bool,
) -> PlatformStartupArtifact {
    let stem = row.name.trim_end_matches(".service");
    let protected = match scope {
        UnitScope::User => matches_any_prefix(stem, SESSION_USER_UNIT_PREFIXES),
        UnitScope::System => matches_any_prefix(stem, ESSENTIAL_SYSTEM_UNIT_PREFIXES),
    };
    let control_capability = if protected {
        PlatformStartupControlCapability::SystemManaged
    } else if row.state == "enabled-runtime" {
        // Enabled only until reboot, usually by another tool; `disable` would not undo it.
        PlatformStartupControlCapability::ViewOnly
    } else if scope == UnitScope::System && !privileged {
        PlatformStartupControlCapability::ElevationRequired
    } else {
        PlatformStartupControlCapability::Toggleable
    };
    let program = details.exec_argv.first().cloned().unwrap_or_default();
    let resolved = resolve_program(&program);
    let mut diagnostics = Vec::new();
    if !program.is_empty() && resolved.is_none() {
        diagnostics.push(PlatformStartupDiagnosticCode::MissingTarget);
    }
    PlatformStartupArtifact {
        provider_item_id: format!("{}{}", scope.item_prefix(), row.name),
        source_kind: PlatformStartupSourceKind::Service,
        scope: match scope {
            UnitScope::User => PlatformStartupScope::CurrentUser,
            UnitScope::System => PlatformStartupScope::System,
        },
        triggers: vec![match scope {
            UnitScope::User => PlatformStartupTrigger::UserLogon,
            UnitScope::System => PlatformStartupTrigger::Boot,
        }],
        display_name: if details.description.is_empty() {
            stem.to_string()
        } else {
            details.description.clone()
        },
        configuration_path: details.fragment_path.clone(),
        target: PlatformStartupTarget {
            kind: PlatformStartupTargetKind::Service,
            identity_key: row.name.clone(),
            path: resolved,
            executable_name: Path::new(&program)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()),
            arguments: details.exec_argv.iter().skip(1).cloned().collect(),
        },
        owner: PlatformStartupOwner {
            identity_key: None,
            name: None,
            publisher: None,
            summary: (!details.description.is_empty()).then(|| details.description.clone()),
            summary_source: if details.description.is_empty() {
                PlatformStartupSummarySource::SourceLabel
            } else {
                PlatformStartupSummarySource::ServiceDescription
            },
            version: None,
            icon_path: None,
            confidence: PlatformStartupIdentityConfidence::Probable,
        },
        configured_state: match row.state.as_str() {
            "enabled" | "enabled-runtime" => PlatformStartupConfiguredState::Enabled,
            "disabled" => PlatformStartupConfiguredState::Disabled,
            _ => PlatformStartupConfiguredState::Unknown,
        },
        runtime_state: match details.active_state.as_str() {
            "active" | "reloading" | "activating" => PlatformStartupRuntimeState::Running,
            "inactive" | "failed" | "deactivating" => PlatformStartupRuntimeState::Stopped,
            _ => PlatformStartupRuntimeState::Unknown,
        },
        control_capability,
        trust: if protected {
            PlatformStartupTrustState::System
        } else {
            PlatformStartupTrustState::Unknown
        },
        modified_at_ms: details.fragment_path.as_deref().and_then(modified_at_ms),
        diagnostics,
    }
}

fn is_privileged() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Reads unit files and their details, optionally for one unit only.
fn read_artifacts(
    executable: &ControlledExecutable,
    scope: UnitScope,
    only: Option<&str>,
    cancellation: &PlatformCancellation,
) -> Result<Vec<PlatformStartupArtifact>, ControlledCommandError> {
    let mut list_args = vec![
        "list-unit-files",
        "--type=service",
        "--no-legend",
        "--no-pager",
    ];
    if let Some(unit) = only {
        list_args.push("--");
        list_args.push(unit);
    }
    let (_, listing) = run_systemctl(
        "linux-startup-systemd-list",
        executable,
        scope,
        &list_args,
        QUERY_LIMITS,
        cancellation,
    )?;
    let rows: Vec<UnitFileRow> = parse_unit_files(&listing)
        .into_iter()
        .filter(|row| only.is_none_or(|unit| row.name == unit))
        .filter(|row| {
            matches!(
                row.state.as_str(),
                "enabled" | "enabled-runtime" | "disabled"
            )
        })
        .collect();
    let mut details = BTreeMap::new();
    for batch in rows.chunks(SHOW_BATCH) {
        let mut show_args = vec!["show", "--no-pager", "-p", SHOW_PROPERTIES, "--"];
        show_args.extend(batch.iter().map(|row| row.name.as_str()));
        let (_, text) = run_systemctl(
            "linux-startup-systemd-show",
            executable,
            scope,
            &show_args,
            QUERY_LIMITS,
            cancellation,
        )?;
        details.extend(parse_show(&text));
    }
    let home = dirs::home_dir();
    let privileged = is_privileged();
    Ok(rows
        .iter()
        .filter_map(|row| {
            let unit = details.get(&row.name)?;
            is_startup_candidate(row, unit.fragment_path.as_deref(), home.as_deref())
                .then(|| artifact(scope, row, unit, privileged))
        })
        .collect())
}

pub(super) fn scan(
    scope: UnitScope,
    cancellation: &PlatformCancellation,
) -> PlatformResult<PlatformStartupSourceResult> {
    let started = std::time::Instant::now();
    let Some(executable) = systemctl() else {
        return Ok(PlatformStartupSourceResult::unavailable(
            scope.source_id(),
            false,
            PlatformStartupCoverageReason::ApiUnavailable,
        ));
    };
    match read_artifacts(&executable, scope, None, cancellation) {
        Ok(items) => Ok(PlatformStartupSourceResult {
            source_id: scope.source_id().to_string(),
            required: false,
            status: PlatformStartupCoverageStatus::Complete,
            reason: None,
            items,
            elapsed_ms: started.elapsed().as_millis() as u64,
        }),
        Err(ControlledCommandError::Cancelled) => Err(PlatformError::new(
            PlatformErrorCode::UserCancelled,
            "startup scan was cancelled",
        )),
        Err(error) => {
            log::warn!(
                "linux_startup_source_read_failed source={} error={}",
                scope.source_id(),
                error.as_str()
            );
            Ok(PlatformStartupSourceResult::unavailable(
                scope.source_id(),
                false,
                PlatformStartupCoverageReason::StateUnavailable,
            ))
        }
    }
}

pub(super) fn change(
    scope: UnitScope,
    request: &PlatformStartupChangeRequest,
) -> PlatformResult<PlatformStartupChangeResult> {
    let unit = request
        .provider_item_id
        .strip_prefix(scope.item_prefix())
        .filter(|unit| is_valid_unit_name(unit))
        .ok_or_else(|| {
            PlatformError::new(PlatformErrorCode::InvalidData, "invalid service item id")
        })?;
    let verb = match request.desired_state {
        PlatformStartupDesiredState::Enabled => "enable",
        PlatformStartupDesiredState::Disabled => "disable",
        PlatformStartupDesiredState::Removed => {
            return Err(PlatformError::new(
                PlatformErrorCode::Unsupported,
                "services are switched off, not removed",
            ))
        }
    };
    let executable = systemctl().ok_or_else(|| {
        PlatformError::new(PlatformErrorCode::Unsupported, "systemctl is not available")
            .with_failure_reason(PlatformFailureReason::ToolUnavailable)
    })?;
    let never = PlatformCancellation::new(|| false);
    let current = read_artifacts(&executable, scope, Some(unit), &never)
        .map_err(command_error)?
        .into_iter()
        .next()
        .ok_or_else(|| PlatformError::item_changed("service is no longer a startup item"))?;
    if !same_mutation_facts(&current, &request.expected_artifact) {
        return Err(PlatformError::item_changed(
            "service changed after preflight",
        ));
    }
    if !matches!(
        current.control_capability,
        PlatformStartupControlCapability::Toggleable
            | PlatformStartupControlCapability::ElevationRequired
    ) {
        return Err(PlatformError::new(
            PlatformErrorCode::Unsupported,
            "service cannot be switched here",
        ));
    }

    let (succeeded, _) = run_systemctl(
        "linux-startup-systemd-change",
        &executable,
        scope,
        &[verb, "--", unit],
        CHANGE_LIMITS,
        &never,
    )
    .map_err(|error| command_error(error).with_possible_side_effects())?;
    let (_, state_text) = run_systemctl(
        "linux-startup-systemd-verify",
        &executable,
        scope,
        &["is-enabled", "--", unit],
        QUERY_LIMITS,
        &never,
    )
    .map_err(|error| command_error(error).with_possible_side_effects())?;
    let configured_state = match state_text.trim() {
        "enabled" | "enabled-runtime" => PlatformStartupConfiguredState::Enabled,
        "disabled" => PlatformStartupConfiguredState::Disabled,
        _ => PlatformStartupConfiguredState::Unknown,
    };
    let expected = match request.desired_state {
        PlatformStartupDesiredState::Enabled => PlatformStartupConfiguredState::Enabled,
        _ => PlatformStartupConfiguredState::Disabled,
    };
    log::info!(
        "linux_startup_service_changed scope={:?} unit={} verb={} exit_success={} verified={}",
        scope,
        crate::diagnostics::text(unit),
        verb,
        succeeded,
        configured_state == expected
    );
    if !succeeded && configured_state != expected {
        // For system services a failed `systemctl` almost always means the polkit dialog was
        // cancelled or the password was refused.
        let code = if scope == UnitScope::System && !is_privileged() {
            PlatformErrorCode::AccessDenied
        } else {
            PlatformErrorCode::OperationFailed
        };
        return Err(PlatformError::new(
            code,
            format!("systemctl {verb} did not complete"),
        ));
    }
    Ok(PlatformStartupChangeResult {
        previous_state: current.configured_state,
        configured_state,
        verified: configured_state == expected,
    })
}

fn command_error(error: ControlledCommandError) -> PlatformError {
    match error {
        ControlledCommandError::Cancelled => {
            PlatformError::new(PlatformErrorCode::UserCancelled, "systemctl was cancelled")
        }
        ControlledCommandError::TimedOut => PlatformError::operation_failed("systemctl timed out")
            .with_failure_reason(PlatformFailureReason::TimedOut),
        other => PlatformError::operation_failed(format!("systemctl failed: {}", other.as_str())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, state: &str, preset: Option<&str>) -> UnitFileRow {
        UnitFileRow {
            name: name.to_string(),
            state: state.to_string(),
            preset: preset.map(String::from),
        }
    }

    #[test]
    fn unit_file_listing_is_parsed_and_unsafe_names_are_dropped() {
        let rows = parse_unit_files(
            "clamav-daemon.service enabled enabled\nfoo.service disabled -\n-rf.service enabled enabled\nbad name.service enabled\n",
        );
        assert_eq!(
            rows,
            vec![
                row("clamav-daemon.service", "enabled", Some("enabled")),
                row("foo.service", "disabled", None)
            ]
        );
    }

    #[test]
    fn show_output_yields_description_command_and_state() {
        let units = parse_show(
            "Id=omniroute.service\nDescription=OmniRoute\nFragmentPath=/home/u/.config/systemd/user/omniroute.service\n\
             ExecStart={ path=/usr/bin/node ; argv[]=/usr/bin/node /opt/omniroute serve ; ignore_errors=no ; start_time=[n/a] }\n\
             UnitFileState=enabled\nActiveState=active\n\nId=other.service\nDescription=\nActiveState=inactive\n",
        );
        let omniroute = &units["omniroute.service"];
        assert_eq!(
            omniroute.exec_argv,
            vec!["/usr/bin/node", "/opt/omniroute", "serve"]
        );
        assert_eq!(omniroute.active_state, "active");
        assert_eq!(units["other.service"].fragment_path, None);
    }

    #[test]
    fn only_enabled_or_deliberately_disabled_units_are_startup_items() {
        let home = Path::new("/home/u");
        assert!(is_startup_candidate(
            &row("a.service", "enabled", None),
            None,
            Some(home)
        ));
        assert!(is_startup_candidate(
            &row("a.service", "disabled", Some("enabled")),
            None,
            Some(home)
        ));
        assert!(is_startup_candidate(
            &row("a.service", "disabled", Some("disabled")),
            Some(Path::new("/etc/systemd/system/a.service")),
            Some(home)
        ));
        assert!(!is_startup_candidate(
            &row("a.service", "disabled", Some("disabled")),
            Some(Path::new("/usr/lib/systemd/system/a.service")),
            Some(home)
        ));
        assert!(!is_startup_candidate(
            &row("getty@.service", "enabled", None),
            None,
            Some(home)
        ));
        assert!(!is_startup_candidate(
            &row("a.service", "static", None),
            None,
            Some(home)
        ));
    }

    #[test]
    fn system_services_need_authorization_and_essential_ones_are_read_only() {
        let details = UnitDetails {
            description: "ClamAV daemon".into(),
            exec_argv: vec!["/bin/sh".into()],
            active_state: "active".into(),
            ..UnitDetails::default()
        };
        let clamd = artifact(
            UnitScope::System,
            &row("clamav-daemon.service", "enabled", None),
            &details,
            false,
        );
        assert_eq!(
            clamd.control_capability,
            PlatformStartupControlCapability::ElevationRequired
        );
        assert_eq!(clamd.runtime_state, PlatformStartupRuntimeState::Running);
        let network = artifact(
            UnitScope::System,
            &row("NetworkManager.service", "enabled", None),
            &details,
            false,
        );
        assert_eq!(
            network.control_capability,
            PlatformStartupControlCapability::SystemManaged
        );
        let mine = artifact(
            UnitScope::User,
            &row("omniroute.service", "enabled", None),
            &details,
            false,
        );
        assert_eq!(
            mine.control_capability,
            PlatformStartupControlCapability::Toggleable
        );
        let session = artifact(
            UnitScope::User,
            &row("plasma-kwin_wayland.service", "enabled", None),
            &details,
            false,
        );
        assert_eq!(
            session.control_capability,
            PlatformStartupControlCapability::SystemManaged
        );
        let runtime = artifact(
            UnitScope::User,
            &row("foo.service", "enabled-runtime", None),
            &details,
            false,
        );
        assert_eq!(
            runtime.control_capability,
            PlatformStartupControlCapability::ViewOnly
        );
    }

    #[test]
    fn unit_names_are_validated_before_reaching_systemctl() {
        assert!(is_valid_unit_name("cloudflared-openmuse-helicone.service"));
        assert!(is_valid_unit_name("postgresql@17-main.service"));
        assert!(!is_valid_unit_name("--now.service"));
        assert!(!is_valid_unit_name("a;b.service"));
        assert!(!is_valid_unit_name("a.socket"));
    }

    #[test]
    #[ignore = "requires a systemd user manager"]
    fn host_user_services_can_be_listed() {
        let result = scan(UnitScope::User, &PlatformCancellation::new(|| false)).unwrap();
        assert_eq!(result.status, PlatformStartupCoverageStatus::Complete);
    }
}
