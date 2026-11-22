//! Linux running-program inventory: `/proc` facts, the program file each process runs, how that
//! program was installed, and the service units seen in process control groups.
//!
//! Everything here is read-only. External tools (package managers, container engines and
//! `systemctl`) are run through the controlled command runner with bounded output and time.

mod file_facts;
mod origin;
mod packages;
mod proc_reader;
mod python_packages;
mod target;

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    command::{
        run_controlled_command_with_log_policy, ControlledCommandLimits,
        ControlledCommandLogPolicy, ControlledEnvironmentPolicy, ControlledExecutable,
    },
    PlatformCancellation, PlatformError, PlatformErrorCode, PlatformMemoryTotals,
    PlatformProcessRecord, PlatformResult, PlatformRunningProgramsRequest,
    PlatformRunningProgramsSnapshot, PlatformServiceUnitFacts, PlatformServiceUnitScope,
    PlatformUnitFileOrigin,
};

const TOOL_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_CPU_SAMPLE_MS: u64 = 5_000;
const UNIT_QUERY_BATCH: usize = 128;

pub(super) struct ToolOutput {
    pub success: bool,
    pub stdout: String,
}

/// Runs a read-only system tool. Failures are reported as `None`: every caller treats a missing
/// answer as "unknown" rather than guessing.
pub(super) fn run_tool(
    command_id: &'static str,
    executable: &Path,
    args: &[&str],
    timeout: Duration,
    cancellation: &PlatformCancellation,
) -> Option<ToolOutput> {
    // Container engines and `systemctl --user` need the session's runtime directory and bus.
    let environment = if command_id.contains("docker")
        || command_id.contains("podman")
        || command_id.contains("systemctl")
    {
        ControlledEnvironmentPolicy::Inherit
    } else {
        ControlledEnvironmentPolicy::Isolated
    };
    let executable = ControlledExecutable::capture(executable).ok()?;
    let output = run_controlled_command_with_log_policy(
        command_id,
        &executable,
        args,
        environment,
        ControlledCommandLimits {
            timeout,
            stdout_bytes: TOOL_OUTPUT_BYTES,
            stderr_bytes: 64 * 1024,
        },
        ControlledCommandLogPolicy::ExceptionalOnly,
        &|| cancellation.is_cancelled(),
    )
    .ok()?;
    Some(ToolOutput {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| u64::try_from(since.as_millis()).ok())
        .unwrap_or(0)
}

fn cancelled() -> PlatformError {
    PlatformError::new(
        PlatformErrorCode::UserCancelled,
        "running-program capture was cancelled",
    )
}

fn wait(duration: Duration, cancellation: &PlatformCancellation) -> PlatformResult<()> {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        std::thread::sleep(
            Duration::from_millis(50).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    Ok(())
}

pub(super) fn capture_running_programs(
    request: &PlatformRunningProgramsRequest,
    cancellation: &PlatformCancellation,
) -> PlatformResult<PlatformRunningProgramsSnapshot> {
    let boot_seconds = proc_reader::boot_time_seconds()
        .ok_or_else(|| PlatformError::operation_failed("boot time is missing from /proc/stat"))?;
    let ticks_per_second = proc_reader::clock_ticks_per_second();
    let own_pid = std::process::id();
    let mut processes: Vec<proc_reader::RawProcess> = proc_reader::list_pids()
        .into_iter()
        .filter(|pid| *pid != own_pid)
        .filter_map(|pid| proc_reader::read_process(pid, boot_seconds, ticks_per_second))
        .collect();
    if cancellation.is_cancelled() {
        return Err(cancelled());
    }
    let sample = Duration::from_millis(request.cpu_sample_ms.min(MAX_CPU_SAMPLE_MS));
    let sample_started = Instant::now();
    wait(sample, cancellation)?;
    let elapsed = sample_started.elapsed().as_secs_f64();
    let mut cpu_now = BTreeMap::new();
    for process in &mut processes {
        if let Some(ticks) = proc_reader::read_cpu_ticks(process.pid) {
            if elapsed > 0.0 && ticks >= process.cpu_ticks {
                let seconds = (ticks - process.cpu_ticks) as f64 / ticks_per_second as f64;
                cpu_now.insert(process.pid, seconds / elapsed * 100.0);
            }
            process.cpu_ticks = ticks;
        }
    }

    let home = dirs::home_dir();
    let resolved: Vec<target::ResolvedTarget> = processes
        .iter()
        .map(|process| target::resolve_target(process, home.as_deref()))
        .collect();
    let mut owners = packages::PackageOwners::detect();
    // One batched ownership query for every system path is much faster than one per process.
    let system_paths: BTreeSet<PathBuf> = resolved
        .iter()
        .filter_map(|resolved| resolved.target.path.clone())
        .filter(|path| file_facts::is_system_path(path))
        .collect();
    owners.look_up(system_paths, cancellation);
    let mut classifier = origin::OriginClassifier::new(home.clone(), owners);
    let mut records = Vec::with_capacity(processes.len());
    for (process, resolved) in processes.into_iter().zip(resolved) {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let origin = classifier.classify(&process, &resolved, cancellation);
        records.push(PlatformProcessRecord {
            pid: process.pid,
            parent_pid: process.parent_pid,
            uid: process.uid,
            cpu_seconds: process.cpu_ticks as f64 / ticks_per_second as f64,
            cpu_percent_now: cpu_now.get(&process.pid).copied().unwrap_or(0.0),
            name: process.name,
            command_line: process.command_line,
            executable_path: resolved.executable.or(process.executable),
            executable_replaced: process.executable_replaced,
            working_directory: process.working_directory,
            cgroup: process.cgroup,
            started_at_ms: process.started_at_ms,
            resident_kb: process.resident_kb,
            proportional_kb: process.proportional_kb,
            swap_kb: process.swap_kb,
            target: resolved.target,
            origin,
        });
    }
    let units = service_units(
        &records,
        home.as_deref(),
        &mut classifier.owners,
        cancellation,
    );
    Ok(PlatformRunningProgramsSnapshot {
        captured_at_ms: now_ms(),
        // SAFETY: geteuid has no preconditions and cannot fail.
        elevated: unsafe { libc::geteuid() } == 0,
        home_directory: home,
        memory: memory_totals(),
        processes: records,
        units,
    })
}

fn parse_meminfo(text: &str) -> BTreeMap<String, u64> {
    text.lines()
        .filter_map(|line| {
            let (key, rest) = line.split_once(':')?;
            Some((
                key.to_owned(),
                rest.split_whitespace().next()?.parse().ok()?,
            ))
        })
        .collect()
}

/// `orig_data_size compr_data_size mem_used_total …` in bytes.
fn parse_zram_mm_stat(text: &str) -> Option<(u64, u64)> {
    let fields: Vec<u64> = text
        .split_whitespace()
        .filter_map(|field| field.parse().ok())
        .collect();
    Some((*fields.first()?, *fields.get(2)?))
}

fn memory_totals() -> PlatformMemoryTotals {
    let info = parse_meminfo(
        &proc_reader::read_text(Path::new("/proc/meminfo"), 64 * 1024).unwrap_or_default(),
    );
    let value = |key: &str| info.get(key).copied().unwrap_or(0);
    let mut totals = PlatformMemoryTotals {
        total_kb: value("MemTotal"),
        available_kb: value("MemAvailable"),
        swap_total_kb: value("SwapTotal"),
        swap_free_kb: value("SwapFree"),
        ..Default::default()
    };
    let swaps = proc_reader::read_text(Path::new("/proc/swaps"), 64 * 1024).unwrap_or_default();
    for device in swaps
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
    {
        let Some(name) = device
            .strip_prefix("/dev/")
            .filter(|name| name.starts_with("zram"))
        else {
            continue;
        };
        let stat =
            proc_reader::read_text(&Path::new("/sys/block").join(name).join("mm_stat"), 4096);
        if let Some((original, used)) = stat.as_deref().and_then(parse_zram_mm_stat) {
            *totals.compressed_swap_used_kb.get_or_insert(0) += original / 1024;
            *totals.compressed_swap_ram_kb.get_or_insert(0) += used / 1024;
        }
    }
    totals
}

/// The service unit a control-group path belongs to, skipping the per-user manager itself.
fn cgroup_service_unit(cgroup: &str) -> Option<(PlatformServiceUnitScope, String)> {
    let parts: Vec<&str> = cgroup.split('/').filter(|part| !part.is_empty()).collect();
    let user_manager = parts
        .iter()
        .position(|part| part.starts_with("user@") && part.ends_with(".service"));
    let start = user_manager.map_or(0, |index| index + 1);
    let unit = parts[start..]
        .iter()
        .rev()
        .find(|part| part.ends_with(".service"))?;
    let scope = if user_manager.is_some() {
        PlatformServiceUnitScope::User
    } else if parts.first() == Some(&"system.slice")
        || parts
            .first()
            .is_some_and(|part| part.starts_with("system-"))
    {
        PlatformServiceUnitScope::System
    } else {
        return None;
    };
    Some((scope, (*unit).to_owned()))
}

fn parse_show(text: &str) -> Vec<BTreeMap<String, String>> {
    text.split("\n\n")
        .map(|block| {
            block
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect::<BTreeMap<_, _>>()
        })
        .filter(|block| block.contains_key("Id"))
        .collect()
}

fn unit_name_is_safe(name: &str) -> bool {
    name.len() <= 256
        && name.ends_with(".service")
        && !name.starts_with('-')
        && name.chars().all(|ch| {
            ch.is_ascii_alphanumeric() || matches!(ch, ':' | '_' | '.' | '@' | '-' | '\\')
        })
}

fn service_units(
    records: &[PlatformProcessRecord],
    home: Option<&Path>,
    owners: &mut packages::PackageOwners,
    cancellation: &PlatformCancellation,
) -> Vec<PlatformServiceUnitFacts> {
    // SAFETY: getuid has no preconditions and cannot fail.
    let own_uid = unsafe { libc::getuid() };
    let mut wanted: BTreeMap<PlatformServiceUnitScope, BTreeSet<String>> = BTreeMap::new();
    for record in records {
        let Some((scope, unit)) = record.cgroup.as_deref().and_then(cgroup_service_unit) else {
            continue;
        };
        // `systemctl --user` reaches only the current user's manager.
        if scope == PlatformServiceUnitScope::User && record.uid != own_uid {
            continue;
        }
        if unit_name_is_safe(&unit) {
            wanted.entry(scope).or_default().insert(unit);
        }
    }
    let Some(systemctl) = ["/usr/bin/systemctl", "/bin/systemctl"]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
    else {
        return Vec::new();
    };
    let mut units = Vec::new();
    for (scope, names) in wanted {
        let names: Vec<String> = names.into_iter().collect();
        for batch in names.chunks(UNIT_QUERY_BATCH) {
            let mut args: Vec<&str> = Vec::new();
            if scope == PlatformServiceUnitScope::User {
                args.push("--user");
            }
            args.extend([
                "show",
                "--no-pager",
                "-p",
                "Id,FragmentPath,UnitFileState",
                "--",
            ]);
            args.extend(batch.iter().map(String::as_str));
            let Some(output) = run_tool(
                "running_programs.systemctl_show",
                &systemctl,
                &args,
                Duration::from_secs(20),
                cancellation,
            ) else {
                continue;
            };
            for block in parse_show(&output.stdout) {
                let fragment = block
                    .get("FragmentPath")
                    .filter(|path| !path.is_empty())
                    .map(PathBuf::from);
                units.push(PlatformServiceUnitFacts {
                    scope,
                    name: block["Id"].clone(),
                    fragment_modified_ms: fragment.as_deref().and_then(file_facts::modified_ms),
                    fragment_origin: unit_file_origin(
                        fragment.as_deref(),
                        home,
                        owners,
                        cancellation,
                    ),
                    fragment_path: fragment,
                    unit_file_state: block
                        .get("UnitFileState")
                        .filter(|state| !state.is_empty())
                        .cloned(),
                });
            }
        }
    }
    units
}

fn unit_file_origin(
    fragment: Option<&Path>,
    home: Option<&Path>,
    owners: &mut packages::PackageOwners,
    cancellation: &PlatformCancellation,
) -> PlatformUnitFileOrigin {
    let Some(fragment) = fragment else {
        return PlatformUnitFileOrigin::Generated;
    };
    if fragment.starts_with("/run") {
        return PlatformUnitFileOrigin::Generated;
    }
    if home.is_some_and(|home| fragment.starts_with(home)) {
        return PlatformUnitFileOrigin::AddedToHome;
    }
    if let Some(package) = owners.owner(fragment, cancellation) {
        return PlatformUnitFileOrigin::Package(package);
    }
    if fragment.starts_with("/etc") {
        return PlatformUnitFileOrigin::AddedToEtc;
    }
    PlatformUnitFileOrigin::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroups_name_their_service_unit_and_scope() {
        assert_eq!(
            cgroup_service_unit("/system.slice/docker.service"),
            Some((
                PlatformServiceUnitScope::System,
                "docker.service".to_owned()
            ))
        );
        assert_eq!(
            cgroup_service_unit("/system.slice/system-getty.slice/getty@tty1.service"),
            Some((
                PlatformServiceUnitScope::System,
                "getty@tty1.service".to_owned()
            ))
        );
        assert_eq!(
            cgroup_service_unit(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/syncthing.service"
            ),
            Some((
                PlatformServiceUnitScope::User,
                "syncthing.service".to_owned()
            ))
        );
        assert_eq!(
            cgroup_service_unit("/user.slice/user-1000.slice/user@1000.service/init.scope"),
            None
        );
        assert_eq!(
            cgroup_service_unit("/user.slice/user-1000.slice/session-2.scope"),
            None
        );
    }

    #[test]
    fn systemctl_show_blocks_are_split() {
        let text = "Id=a.service\nFragmentPath=/usr/lib/systemd/system/a.service\nUnitFileState=enabled\n\nId=b.service\nFragmentPath=\nUnitFileState=\n";
        let blocks = parse_show(text);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[1]["FragmentPath"], "");
    }

    #[test]
    fn zram_and_meminfo_are_parsed() {
        assert_eq!(
            parse_zram_mm_stat("4096000 1024000 1200000 0 1500000 10 0 0 0"),
            Some((4_096_000, 1_200_000))
        );
        let info = parse_meminfo("MemTotal:  16000 kB\nSwapFree:  10 kB\n");
        assert_eq!(info["MemTotal"], 16_000);
    }

    #[test]
    #[ignore = "reads the live /proc of the machine running the tests"]
    fn live_capture_reads_this_machine() {
        let snapshot = capture_running_programs(
            &PlatformRunningProgramsRequest { cpu_sample_ms: 200 },
            &PlatformCancellation::new(|| false),
        )
        .expect("capture succeeds");
        assert!(!snapshot.processes.is_empty());
        assert!(snapshot.memory.total_kb > 0);
    }
}
