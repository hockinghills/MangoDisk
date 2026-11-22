//! Filesystem facts used to identify where a program came from: dates, git clones, Go build
//! information and loose-binary names.

use std::{
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use super::proc_reader::read_text;

const SYSTEM_PREFIXES: &[&str] = &[
    "/usr/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib64/",
    "/opt/",
    "/etc/",
    "/libexec/",
];
/// 1980-01-01: archives and some package formats zero or fake older dates.
const PLAUSIBLE_DATE_MS: u64 = 315_532_800_000;
const GO_BINARY_LIMIT: u64 = 400 * 1024 * 1024;

pub(super) fn is_system_path(path: &Path) -> bool {
    let text = path.to_string_lossy();
    SYSTEM_PREFIXES
        .iter()
        .any(|prefix| text.starts_with(prefix))
}

pub(super) fn canonical(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub(super) fn modified_ms(path: &Path) -> Option<u64> {
    metadata_modified_ms(&fs::metadata(path).ok()?)
}

pub(super) fn link_modified_ms(path: &Path) -> Option<u64> {
    metadata_modified_ms(&fs::symlink_metadata(path).ok()?)
}

fn metadata_modified_ms(metadata: &fs::Metadata) -> Option<u64> {
    let since = metadata.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(since.as_millis()).ok()
}

/// When a file arrived here. The change time records when it was written to this disk, while
/// archives keep (or zero) the original modification time.
pub(super) fn landed_at_ms(path: &Path) -> Option<u64> {
    let metadata = fs::metadata(path).ok()?;
    let changed = u64::try_from(metadata.ctime())
        .ok()
        .map(|seconds| seconds * 1000);
    [changed, metadata_modified_ms(&metadata)]
        .into_iter()
        .flatten()
        .find(|value| *value > PLAUSIBLE_DATE_MS)
}

/// Walks up from `start` looking for `marker`, stopping at (and excluding) `stops` and `/`.
pub(super) fn find_upwards(start: &Path, marker: &str, stops: &[&Path]) -> Option<PathBuf> {
    let mut current = if start.is_dir() {
        start
    } else {
        start.parent()?
    };
    loop {
        if current == Path::new("/") || stops.contains(&current) {
            return None;
        }
        if current.join(marker).exists() {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
}

fn is_versionish(segment: &str) -> bool {
    let body = segment.strip_prefix('v').unwrap_or(segment);
    let numeric_end = body
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .unwrap_or(body.len());
    let (numeric, suffix) = body.split_at(numeric_end);
    let parts: Vec<&str> = numeric.split('.').collect();
    parts.len() >= 2
        && parts.iter().all(|part| !part.is_empty())
        && (suffix.is_empty()
            || (suffix.starts_with(['-', '+', '.', '_'])
                && suffix[1..]
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '.')
                && suffix.len() > 1))
}

const GENERIC_DIRS: &[&str] = &[
    "bin", "sbin", "versions", "version", "current", "latest", "stable", "libexec", "lib", "app",
    "dist", "build", "release", "releases", "target", "out", "usr", "local", "share", "opt",
    ".local",
];

/// Names a loose binary: `~/.local/share/tool/versions/2.1.3` is `tool` 2.1.3, not "2.1.3".
pub(super) fn program_name(path: &Path, home: Option<&Path>) -> (String, Option<String>) {
    let base = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut parts: Vec<String> = path
        .iter()
        .filter(|part| *part != "/")
        .map(|part| part.to_string_lossy().into_owned())
        .collect();
    let mut version = None;
    while let Some(last) = parts.last() {
        let versionish = is_versionish(last);
        if !versionish && !GENERIC_DIRS.contains(&last.as_str()) {
            break;
        }
        if versionish && version.is_none() {
            version = Some(last.clone());
        }
        parts.pop();
    }
    let home_name = home
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned());
    match parts.last() {
        Some(name) if Some(name) != home_name.as_ref() => {
            let version = if *name != base { version } else { None };
            (name.clone(), version)
        }
        _ => (base, None),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GitDateSource {
    FirstLogEntry,
    FolderDate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GitClone {
    pub root: PathBuf,
    pub remote: Option<String>,
    pub cloned_at_ms: Option<u64>,
    pub date_source: GitDateSource,
    pub last_activity_ms: Option<u64>,
}

fn remote_url(config: &str) -> Option<String> {
    let mut section = "";
    let mut first = None;
    for line in config.lines().map(str::trim) {
        if line.starts_with('[') {
            section = line;
        } else if section.starts_with("[remote") {
            if let Some(value) = line
                .strip_prefix("url")
                .and_then(|rest| rest.trim_start().strip_prefix('='))
            {
                let value = value.trim().to_owned();
                if section.contains("\"origin\"") {
                    return Some(value);
                }
                first.get_or_insert(value);
            }
        }
    }
    first
}

/// The timestamp of a reflog line: `<old> <new> Name <email> 1700000000 +0100\tmessage`.
fn reflog_seconds(line: &str) -> Option<u64> {
    let (head, _) = line.split_once('\t').unwrap_or((line, ""));
    let after = &head[head.rfind("> ")? + 2..];
    after.split_whitespace().next()?.parse().ok()
}

/// Git facts for a clone containing `path`. A repository at the home folder itself is a dotfiles
/// repository, not an install.
pub(super) fn git_clone(path: &Path, home: Option<&Path>) -> Option<GitClone> {
    let stops: Vec<&Path> = home.into_iter().collect();
    let root = find_upwards(path, ".git", &stops)?;
    let mut git_dir = root.join(".git");
    if git_dir.is_file() {
        let text = read_text(&git_dir, 4096)?;
        let target = text.trim().strip_prefix("gitdir:")?.trim().to_owned();
        git_dir = root.join(target);
    }
    let remote = read_text(&git_dir.join("config"), 256 * 1024)
        .as_deref()
        .and_then(remote_url);
    let mut cloned_at_ms = None;
    let mut last_activity_ms = None;
    let mut date_source = GitDateSource::FolderDate;
    if let Some(log) = read_text(&git_dir.join("logs/HEAD"), 4 * 1024 * 1024) {
        let lines: Vec<&str> = log.lines().filter(|line| !line.trim().is_empty()).collect();
        if let Some(seconds) = lines.first().and_then(|line| reflog_seconds(line)) {
            cloned_at_ms = Some(seconds * 1000);
            date_source = GitDateSource::FirstLogEntry;
        }
        last_activity_ms = lines
            .last()
            .and_then(|line| reflog_seconds(line))
            .map(|s| s * 1000);
    }
    if cloned_at_ms.is_none() {
        cloned_at_ms = modified_ms(&git_dir.join("description")).or_else(|| modified_ms(&git_dir));
    }
    if let Some(fetched) = modified_ms(&git_dir.join("FETCH_HEAD")) {
        if last_activity_ms.is_none_or(|last| fetched > last) {
            last_activity_ms = Some(fetched);
        }
    }
    Some(GitClone {
        root,
        remote,
        cloned_at_ms,
        date_source,
        last_activity_ms,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GoBuild {
    pub module: Option<String>,
    pub version: Option<String>,
}

/// Reads the module path and version a Go binary was built from, or `None` if it is not Go.
pub(super) fn go_build(path: &Path) -> Option<GoBuild> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > GO_BINARY_LIMIT {
        return None;
    }
    let mut data = Vec::new();
    fs::File::open(path).ok()?.read_to_end(&mut data).ok()?;
    find_bytes(&data, b"\xff Go buildinf:")?;
    Some(parse_go_modinfo(&data))
}

pub(super) fn parse_go_modinfo(data: &[u8]) -> GoBuild {
    let unknown = GoBuild {
        module: None,
        version: None,
    };
    let Some(start) = find_bytes(data, b"\nmod\t") else {
        return unknown;
    };
    let rest = &data[start + 5..];
    let end = rest
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(rest.len())
        .min(1024);
    let line = String::from_utf8_lossy(&rest[..end]);
    let mut fields = line.split('\t');
    let module = fields
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let version = fields
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    GoBuild { module, version }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
pub(super) fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CivilTime {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

/// Parses `YYYY-MM-DD HH:MM:SS`, tolerating repeated spaces between the fields.
pub(super) fn parse_civil(text: &str) -> Option<CivilTime> {
    let mut words = text.split_whitespace();
    let mut date = words.next()?.split('-');
    let mut time = words.next()?.split(':');
    let civil = CivilTime {
        year: date.next()?.parse().ok()?,
        month: date.next()?.parse().ok()?,
        day: date.next()?.parse().ok()?,
        hour: time.next()?.parse().ok()?,
        minute: time.next()?.parse().ok()?,
        second: time.next()?.get(..2)?.parse().ok()?,
    };
    ((1..=12).contains(&civil.month) && (1..=31).contains(&civil.day) && civil.hour < 24)
        .then_some(civil)
}

pub(super) fn civil_utc_ms(civil: CivilTime) -> Option<u64> {
    let days = days_from_civil(civil.year, civil.month, civil.day);
    let seconds = days * 86_400
        + i64::from(civil.hour) * 3600
        + i64::from(civil.minute) * 60
        + i64::from(civil.second);
    u64::try_from(seconds).ok().map(|seconds| seconds * 1000)
}

/// Interprets a civil time in the machine's local time zone, as apt and dpkg logs record it.
pub(super) fn civil_local_ms(civil: CivilTime) -> Option<u64> {
    // SAFETY: `tm` is fully initialized before mktime reads it, and mktime only normalizes it.
    let seconds = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        tm.tm_year = i32::try_from(civil.year - 1900).ok()?;
        tm.tm_mon = i32::try_from(civil.month).ok()? - 1;
        tm.tm_mday = i32::try_from(civil.day).ok()?;
        tm.tm_hour = i32::try_from(civil.hour).ok()?;
        tm.tm_min = i32::try_from(civil.minute).ok()?;
        tm.tm_sec = i32::try_from(civil.second).ok()?;
        tm.tm_isdst = -1;
        libc::mktime(&mut tm)
    };
    u64::try_from(seconds).ok().map(|seconds| seconds * 1000)
}

/// Parses Docker's `CreatedAt` (`2024-05-01 12:00:00 +0200 CEST`).
pub(super) fn parse_container_created(text: &str) -> Option<u64> {
    let civil = parse_civil(text)?;
    let utc = civil_utc_ms(civil)?;
    let offset = text
        .split_whitespace()
        .nth(2)
        .filter(|word| word.starts_with(['+', '-']) && word.len() == 5);
    let Some(offset) = offset else {
        return Some(utc);
    };
    let sign: i64 = if offset.starts_with('-') { -1 } else { 1 };
    let hours: i64 = offset[1..3].parse().ok()?;
    let minutes: i64 = offset[3..5].parse().ok()?;
    let shifted = i64::try_from(utc).ok()? - sign * (hours * 3600 + minutes * 60) * 1000;
    u64::try_from(shifted).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_folders_name_the_program_above_them() {
        let home = Path::new("/home/a");
        assert_eq!(
            program_name(
                Path::new("/home/a/.local/share/tool/versions/2.1.3"),
                Some(home)
            ),
            ("tool".to_owned(), Some("2.1.3".to_owned()))
        );
        assert_eq!(
            program_name(Path::new("/opt/app/bin/app"), Some(home)),
            ("app".to_owned(), None)
        );
        assert_eq!(
            program_name(Path::new("/home/a/bin/run"), Some(home)),
            ("run".to_owned(), None)
        );
    }

    #[test]
    fn versionish_segments() {
        assert!(is_versionish("2.1.3"));
        assert!(is_versionish("v1.20"));
        assert!(is_versionish("1.2.3-beta.1"));
        assert!(!is_versionish("3"));
        assert!(!is_versionish("tool"));
        assert!(!is_versionish("1.2-"));
    }

    #[test]
    fn origin_remote_wins_over_other_remotes() {
        let config = "[core]\n\tbare = false\n[remote \"fork\"]\n\turl = https://example.test/fork.git\n[remote \"origin\"]\n\turl = https://example.test/origin.git\n";
        assert_eq!(
            remote_url(config).as_deref(),
            Some("https://example.test/origin.git")
        );
    }

    #[test]
    fn reflog_lines_yield_their_timestamp() {
        let line = "0000 abcd A Person <a@example.test> 1700000000 +0100\tclone: from https://example.test/x.git";
        assert_eq!(reflog_seconds(line), Some(1_700_000_000));
    }

    #[test]
    fn go_module_info_is_parsed() {
        let data = b"junk\xff Go buildinf:...path\tgithub.com/x/tool/cmd/tool\nmod\tgithub.com/x/tool\tv1.4.0\th1:abc=\n";
        let build = parse_go_modinfo(data);
        assert_eq!(build.module.as_deref(), Some("github.com/x/tool"));
        assert_eq!(build.version.as_deref(), Some("v1.4.0"));
    }

    #[test]
    fn civil_dates_convert_to_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        let civil = parse_civil("2024-01-02  03:04:05").expect("valid date");
        assert_eq!(civil_utc_ms(civil), Some(1_704_164_645_000));
        assert_eq!(
            parse_container_created("2024-01-02 05:04:05 +0200 EET"),
            Some(1_704_164_645_000)
        );
        assert!(parse_civil("yesterday").is_none());
    }
}
