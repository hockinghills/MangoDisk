//! Reads per-process facts from `/proc`.
//!
//! Every file is optional: another user's process hides its program file, working directory,
//! environment and proportional memory, and any process can exit between two reads. Missing
//! facts stay empty instead of being guessed.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

/// Set on kernel threads in `/proc/<pid>/stat` flags.
const PF_KTHREAD: u64 = 0x0020_0000;
const COMMAND_LINE_BYTES: u64 = 64 * 1024;
const ENVIRONMENT_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub(super) struct RawProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub uid: u32,
    pub name: String,
    pub command_line: Vec<String>,
    pub executable: Option<PathBuf>,
    pub executable_replaced: bool,
    pub working_directory: Option<PathBuf>,
    pub cgroup: Option<String>,
    pub started_at_ms: u64,
    pub cpu_ticks: u64,
    pub resident_kb: u64,
    pub proportional_kb: Option<u64>,
    pub swap_kb: u64,
    /// `APPIMAGE` from the environment, read only for processes running from an AppImage mount.
    pub appimage: Option<PathBuf>,
    /// Application id from the sandbox's `.flatpak-info`.
    pub flatpak_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StatFields {
    pub name: String,
    pub state: char,
    pub parent_pid: u32,
    pub flags: u64,
    pub cpu_ticks: u64,
    pub start_ticks: u64,
}

/// Parses `/proc/<pid>/stat`. The name is enclosed in parentheses and may itself contain
/// spaces or parentheses, so fields are counted from the last `)`.
pub(super) fn parse_stat(text: &str) -> Option<StatFields> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    if close < open {
        return None;
    }
    let name = text[open + 1..close].to_owned();
    let fields: Vec<&str> = text.get(close + 2..)?.split_whitespace().collect();
    if fields.len() < 20 {
        return None;
    }
    let number = |index: usize| fields[index].parse::<u64>().ok();
    Some(StatFields {
        name,
        state: fields[0].chars().next()?,
        parent_pid: u32::try_from(number(1)?).ok()?,
        flags: number(6)?,
        cpu_ticks: number(11)?.saturating_add(number(12)?),
        start_ticks: number(19)?,
    })
}

/// Prefers the unified (v2) hierarchy and falls back to the systemd v1 hierarchy.
pub(super) fn parse_cgroup(text: &str) -> Option<String> {
    let mut unified = None;
    let mut legacy = None;
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            unified = Some(path.to_owned());
        } else if let Some((_, path)) = line.split_once(":name=systemd:") {
            legacy = Some(path.to_owned());
        }
    }
    let usable = |value: &Option<String>| {
        value
            .as_deref()
            .is_some_and(|path| path != "/" && !path.is_empty())
    };
    if usable(&unified) {
        unified
    } else if usable(&legacy) {
        legacy
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct StatusFields {
    pub uid: Option<u32>,
    pub resident_kb: u64,
    pub swap_kb: u64,
}

pub(super) fn parse_status(text: &str) -> StatusFields {
    let mut fields = StatusFields::default();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        match words.next() {
            Some("Uid:") => fields.uid = words.next().and_then(|value| value.parse().ok()),
            Some("VmRSS:") => {
                fields.resident_kb = words.next().and_then(|v| v.parse().ok()).unwrap_or(0)
            }
            Some("VmSwap:") => {
                fields.swap_kb = words.next().and_then(|v| v.parse().ok()).unwrap_or(0)
            }
            _ => {}
        }
    }
    fields
}

pub(super) fn parse_command_line(raw: &[u8]) -> Vec<String> {
    let mut parts: Vec<String> = raw
        .split(|byte| *byte == 0)
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    while parts.last().is_some_and(String::is_empty) {
        parts.pop();
    }
    parts
}

/// Splits a `/proc/<pid>/exe` target into the path and whether the file was replaced.
pub(super) fn parse_executable_link(target: &Path) -> (PathBuf, bool) {
    let text = target.to_string_lossy();
    match text.strip_suffix(" (deleted)") {
        Some(path) => (PathBuf::from(path), true),
        None => (target.to_path_buf(), false),
    }
}

pub(super) fn parse_proportional_kb(rollup: &str) -> Option<u64> {
    rollup.lines().find_map(|line| {
        line.strip_prefix("Pss:")
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse().ok())
    })
}

pub(super) fn read_bounded(path: &Path, limit: u64) -> Option<Vec<u8>> {
    let file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

pub(super) fn read_text(path: &Path, limit: u64) -> Option<String> {
    read_bounded(path, limit).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Reads one variable from a process environment, which is only readable for your own processes.
pub(super) fn environment_value(pid: u32, name: &str) -> Option<String> {
    let bytes = read_bounded(
        Path::new(&format!("/proc/{pid}/environ")),
        ENVIRONMENT_BYTES,
    )?;
    let prefix = format!("{name}=");
    bytes.split(|byte| *byte == 0).find_map(|item| {
        let item = String::from_utf8_lossy(item);
        item.strip_prefix(&prefix).map(str::to_owned)
    })
}

pub(super) fn boot_time_seconds() -> Option<u64> {
    let text = read_text(Path::new("/proc/stat"), 1 << 20)?;
    text.lines()
        .find_map(|line| line.strip_prefix("btime "))
        .and_then(|value| value.trim().parse().ok())
}

pub(super) fn clock_ticks_per_second() -> u64 {
    // SAFETY: sysconf has no preconditions and only reads a process-wide constant.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    u64::try_from(ticks)
        .ok()
        .filter(|ticks| *ticks > 0)
        .unwrap_or(100)
}

pub(super) fn read_cpu_ticks(pid: u32) -> Option<u64> {
    let text = read_text(Path::new(&format!("/proc/{pid}/stat")), 4096)?;
    parse_stat(&text).map(|stat| stat.cpu_ticks)
}

/// Reads one process. Returns `None` for kernel threads, zombies and processes that exited.
pub(super) fn read_process(
    pid: u32,
    boot_seconds: u64,
    ticks_per_second: u64,
) -> Option<RawProcess> {
    let base = PathBuf::from(format!("/proc/{pid}"));
    let stat = parse_stat(&read_text(&base.join("stat"), 4096)?)?;
    if stat.flags & PF_KTHREAD != 0
        || pid == 2
        || stat.parent_pid == 2
        || matches!(stat.state, 'Z' | 'X')
    {
        return None;
    }
    let status = parse_status(&read_text(&base.join("status"), 64 * 1024).unwrap_or_default());
    let command_line = read_bounded(&base.join("cmdline"), COMMAND_LINE_BYTES)
        .map(|raw| parse_command_line(&raw))
        .unwrap_or_default();
    let (executable, executable_replaced) = match fs::read_link(base.join("exe")) {
        Ok(target) => {
            let (path, replaced) = parse_executable_link(&target);
            (Some(path), replaced)
        }
        Err(_) => (None, false),
    };
    let working_directory = fs::read_link(base.join("cwd")).ok();
    let proportional_kb = read_text(&base.join("smaps_rollup"), 64 * 1024)
        .as_deref()
        .and_then(parse_proportional_kb);
    let cgroup = read_text(&base.join("cgroup"), 64 * 1024)
        .as_deref()
        .and_then(parse_cgroup);
    let appimage = executable
        .as_deref()
        .filter(|path| path.to_string_lossy().contains("/.mount_"))
        .and_then(|_| environment_value(pid, "APPIMAGE"))
        .map(PathBuf::from);
    let flatpak_id = cgroup
        .as_deref()
        .filter(|path| path.contains("flatpak"))
        .and_then(|_| read_text(&base.join("root/.flatpak-info"), 64 * 1024))
        .and_then(|info| {
            info.lines()
                .find_map(|line| line.strip_prefix("name="))
                .map(|name| name.trim().to_owned())
        })
        .filter(|name| !name.is_empty());
    let started_seconds = boot_seconds as f64 + stat.start_ticks as f64 / ticks_per_second as f64;
    Some(RawProcess {
        pid,
        parent_pid: stat.parent_pid,
        uid: status.uid.unwrap_or(u32::MAX),
        name: stat.name,
        command_line,
        executable,
        executable_replaced,
        working_directory,
        cgroup,
        started_at_ms: (started_seconds * 1000.0) as u64,
        cpu_ticks: stat.cpu_ticks,
        resident_kb: status.resident_kb,
        proportional_kb,
        swap_kb: status.swap_kb,
        appimage,
        flatpak_id,
    })
}

pub(super) fn list_pids() -> Vec<u32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable();
    pids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parsing_counts_fields_after_the_last_parenthesis() {
        let text = "1234 (Web (Content)) S 1000 1234 1234 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 30 0 98765 1000 200";
        let stat = parse_stat(text).expect("valid stat line");
        assert_eq!(stat.name, "Web (Content)");
        assert_eq!(stat.state, 'S');
        assert_eq!(stat.parent_pid, 1000);
        assert_eq!(stat.cpu_ticks, 300);
        assert_eq!(stat.start_ticks, 98765);
    }

    #[test]
    fn truncated_stat_is_rejected() {
        assert!(parse_stat("12 (short) S 1").is_none());
    }

    #[test]
    fn cgroup_prefers_unified_hierarchy_over_legacy() {
        let text = "12:cpu:/x\n1:name=systemd:/user.slice/legacy.scope\n0::/user.slice/user-1000.slice/app.slice/app-x.scope\n";
        assert_eq!(
            parse_cgroup(text).as_deref(),
            Some("/user.slice/user-1000.slice/app.slice/app-x.scope")
        );
        let legacy_only = "1:name=systemd:/system.slice/cron.service\n0::/\n";
        assert_eq!(
            parse_cgroup(legacy_only).as_deref(),
            Some("/system.slice/cron.service")
        );
        assert_eq!(parse_cgroup("0::/\n"), None);
    }

    #[test]
    fn status_reads_real_uid_and_memory() {
        let text = "Name:\tx\nUid:\t1000\t1000\t1000\t1000\nVmRSS:\t  2048 kB\nVmSwap:\t  16 kB\n";
        let fields = parse_status(text);
        assert_eq!(fields.uid, Some(1000));
        assert_eq!(fields.resident_kb, 2048);
        assert_eq!(fields.swap_kb, 16);
    }

    #[test]
    fn command_line_drops_trailing_empty_arguments() {
        assert_eq!(
            parse_command_line(b"python3\0-m\0http.server\0\0"),
            ["python3", "-m", "http.server"]
        );
        assert!(parse_command_line(b"").is_empty());
    }

    #[test]
    fn replaced_executables_are_detected() {
        let (path, replaced) = parse_executable_link(Path::new("/usr/bin/app (deleted)"));
        assert_eq!(path, PathBuf::from("/usr/bin/app"));
        assert!(replaced);
        assert!(!parse_executable_link(Path::new("/usr/bin/app")).1);
    }

    #[test]
    fn proportional_memory_comes_from_smaps_rollup() {
        let rollup = "00400000-7fff [rollup]\nRss:  100 kB\nPss:  42 kB\nPss_Anon: 10 kB\n";
        assert_eq!(parse_proportional_kb(rollup), Some(42));
    }
}
