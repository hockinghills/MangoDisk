//! Distro package ownership and install history.
//!
//! Ownership comes from the package manager itself (`dpkg -S`, `rpm -qf`, `pacman -Qqo`). On
//! Debian-family systems the apt history logs say who asked for a package and when, which is a
//! better install date than the package database (that one moves on every upgrade).

use std::{
    collections::{BTreeSet, HashMap},
    io::{BufRead, Read},
    path::{Path, PathBuf},
    time::Duration,
};

use super::{
    file_facts::{civil_local_ms, modified_ms, parse_civil},
    package_index::{clean_description, PackageIndex},
    proc_reader::{read_bounded, read_text},
    run_tool,
};
use crate::{PlatformCancellation, PlatformPackageManager, PlatformPackageRequest};

const APT_HISTORY_DIR: &str = "/var/log/apt";
const DPKG_INFO_DIR: &str = "/var/lib/dpkg/info";
const APT_HISTORY_BYTES: u64 = 64 * 1024 * 1024;
/// Packages named in one transaction beyond which it is a desktop install, upgrade or script.
const BULK_TRANSACTION_PACKAGES: usize = 8;
/// Installs within this window of each other count toward a burst.
const BURST_WINDOW_MS: u64 = 20 * 60 * 1000;
const BURST_TRANSACTIONS: usize = 6;

/// Desktop packages that Ubuntu-family installers mark as manually installed even though they
/// came with the system; for these the apt-mark answer is not evidence of a request.
const DESKTOP_BUNDLED_PREFIXES: &[&str] = &[
    "plasma-",
    "kde",
    "kwin",
    "kf6-",
    "libkf",
    "breeze",
    "kio",
    "kscreen",
    "kwallet",
    "kactivit",
    "kinfocenter",
    "systemsettings",
    "khelpcenter",
    "kmenuedit",
    "dolphin",
    "konsole",
    "kate",
    "kwrite",
    "okular",
    "gwenview",
    "spectacle",
    "kdeconnect",
    "partitionmanager",
    "kcalc",
    "elisa",
    "haruna",
    "sddm",
    "gnome-",
    "nautilus",
    "gedit",
    "evince",
    "eog",
    "totem",
    "tracker",
    "localsearch",
    "evolution",
    "ubuntu-",
    "kubuntu-",
    "xdg-",
    "xwayland",
    "pipewire",
    "wireplumber",
];

fn is_desktop_bundled(package: &str) -> bool {
    package == "ark"
        || DESKTOP_BUNDLED_PREFIXES
            .iter()
            .any(|prefix| package.starts_with(prefix))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AptRequest {
    Asked,
    Bulk,
    Dependency,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AptRecord {
    at_ms: u64,
    command: String,
    request: AptRequest,
    burst: bool,
}

#[derive(Debug, Clone, Default)]
struct AptHistory {
    records: HashMap<String, AptRecord>,
    starts_at_ms: Option<u64>,
}

#[derive(Debug, Clone)]
struct Transaction {
    at_ms: u64,
    asked: BTreeSet<String>,
    automatic: BTreeSet<String>,
    command: String,
}

/// Splits `pkg:amd64 (1.2-3, automatic), other:amd64 (4.5)` into names and details.
fn parse_install_field(field: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut rest = field.trim();
    while let Some(open) = rest.find(" (") {
        let Some(close) = rest[open..].find(')') else {
            break;
        };
        let name = rest[..open].trim().trim_start_matches(',').trim();
        let name = name.split(':').next().unwrap_or(name);
        let detail = &rest[open + 2..open + close];
        if !name.is_empty() {
            entries.push((name.to_owned(), detail.to_owned()));
        }
        rest = rest[open + close + 1..].trim_start_matches([',', ' ']);
    }
    entries
}

/// Packages named on an `apt install` command line, including local `.deb` files.
fn named_on_command_line(command: &str) -> BTreeSet<String> {
    let words: Vec<&str> = command.split_whitespace().collect();
    let Some(install) = words.iter().position(|word| *word == "install") else {
        return BTreeSet::new();
    };
    words[install + 1..]
        .iter()
        .filter(|word| !word.starts_with('-'))
        .map(|word| {
            if word.ends_with(".deb") {
                let file = word.rsplit('/').next().unwrap_or(word);
                file.split('_').next().unwrap_or(file).to_owned()
            } else {
                word.split('=')
                    .next()
                    .unwrap_or(word)
                    .split(':')
                    .next()
                    .unwrap_or(word)
                    .to_owned()
            }
        })
        .collect()
}

fn parse_apt_transactions(text: &str) -> Vec<Transaction> {
    let mut transactions = Vec::new();
    for block in text.split("\n\n") {
        let fields: HashMap<&str, &str> = block
            .lines()
            .filter_map(|line| line.trim().split_once(": "))
            .collect();
        let Some(at_ms) = fields
            .get("Start-Date")
            .and_then(|date| parse_civil(date))
            .and_then(civil_local_ms)
        else {
            continue;
        };
        let command = fields.get("Commandline").copied().unwrap_or("");
        let entries = parse_install_field(fields.get("Install").copied().unwrap_or(""));
        // apt marks what was asked for as non-automatic, which also covers local .deb files whose
        // file name differs from the package name and installs made through Discover.
        let mut asked = named_on_command_line(command);
        asked.extend(
            entries
                .iter()
                .filter(|(_, detail)| !detail.contains("automatic"))
                .map(|(name, _)| name.clone()),
        );
        let automatic: BTreeSet<String> = entries
            .iter()
            .filter(|(_, detail)| detail.contains("automatic"))
            .map(|(name, _)| name.clone())
            .collect();
        let command = if command.starts_with("packagekit")
            || (command.is_empty() && fields.contains_key("Requested-By"))
        {
            "PackageKit".to_owned()
        } else {
            command.to_owned()
        };
        if !asked.is_empty() || !automatic.is_empty() {
            transactions.push(Transaction {
                at_ms,
                asked,
                automatic,
                command,
            });
        }
    }
    transactions
}

fn build_apt_history(mut transactions: Vec<Transaction>) -> AptHistory {
    transactions.sort_by_key(|transaction| transaction.at_ms);
    let asked_times: Vec<u64> = transactions
        .iter()
        .filter(|transaction| !transaction.asked.is_empty())
        .map(|transaction| transaction.at_ms)
        .collect();
    let mut history = AptHistory {
        starts_at_ms: transactions.first().map(|t| t.at_ms),
        ..Default::default()
    };
    for transaction in &transactions {
        let burst = asked_times
            .iter()
            .filter(|time| time.abs_diff(transaction.at_ms) <= BURST_WINDOW_MS)
            .count()
            >= BURST_TRANSACTIONS;
        let bulk = transaction.asked.len() > BULK_TRANSACTION_PACKAGES || burst;
        let asked_kind = if bulk {
            AptRequest::Bulk
        } else {
            AptRequest::Asked
        };
        let dependencies = transaction
            .automatic
            .difference(&transaction.asked)
            .map(|name| (name, AptRequest::Dependency));
        for (name, request) in transaction
            .asked
            .iter()
            .map(|name| (name, asked_kind))
            .chain(dependencies)
        {
            match history.records.get_mut(name) {
                None => {
                    history.records.insert(
                        name.clone(),
                        AptRecord {
                            at_ms: transaction.at_ms,
                            command: transaction.command.clone(),
                            request,
                            burst,
                        },
                    );
                }
                // Asked for later by name: the original date stays, the request is upgraded.
                Some(record)
                    if request == AptRequest::Asked && record.request != AptRequest::Asked =>
                {
                    record.request = AptRequest::Asked;
                }
                Some(_) => {}
            }
        }
    }
    history
}

fn read_maybe_gzip(path: &Path) -> Option<String> {
    let bytes = read_bounded(path, APT_HISTORY_BYTES)?;
    if path.extension().is_some_and(|extension| extension == "gz") {
        let mut text = String::new();
        flate2::read::GzDecoder::new(bytes.as_slice())
            .take(APT_HISTORY_BYTES)
            .read_to_string(&mut text)
            .ok()?;
        Some(text)
    } else {
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
}

fn load_apt_history() -> AptHistory {
    let Ok(entries) = std::fs::read_dir(APT_HISTORY_DIR) else {
        return AptHistory::default();
    };
    let transactions = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("history.log"))
        })
        .filter_map(|path| read_maybe_gzip(&path))
        .flat_map(|text| parse_apt_transactions(&text))
        .collect();
    build_apt_history(transactions)
}

/// What the package database and history say about one package.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct PackageFacts {
    pub installed_at_ms: Option<u64>,
    /// The date is when someone asked for it rather than the last install or upgrade.
    pub from_history: bool,
    pub request: Option<PlatformPackageRequest>,
    pub install_command: Option<String>,
    pub install_burst: bool,
    pub description: Option<String>,
    pub required_by: Option<u32>,
    pub essential: bool,
}

pub(super) struct PackageOwners {
    manager: Option<(PlatformPackageManager, PathBuf)>,
    owners: HashMap<PathBuf, Option<String>>,
    apt: Option<AptHistory>,
    manual: Option<BTreeSet<String>>,
    index: Option<PackageIndex>,
    system_installed_ms: Option<u64>,
}

fn executable_in(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

impl PackageOwners {
    pub(super) fn detect() -> Self {
        let manager = if Path::new("/var/lib/dpkg/status").exists() {
            executable_in(&["/usr/bin/dpkg", "/bin/dpkg"])
                .map(|path| (PlatformPackageManager::Dpkg, path))
        } else if Path::new("/var/lib/pacman/local").is_dir() {
            executable_in(&["/usr/bin/pacman"]).map(|path| (PlatformPackageManager::Pacman, path))
        } else {
            executable_in(&["/usr/bin/rpm", "/bin/rpm"])
                .map(|path| (PlatformPackageManager::Rpm, path))
        };
        let system_installed_ms = modified_ms(Path::new("/var/log/installer"))
            .or_else(|| modified_ms(Path::new("/etc/machine-id")));
        Self {
            manager,
            owners: HashMap::new(),
            apt: None,
            manual: None,
            index: None,
            system_installed_ms,
        }
    }

    pub(super) fn manager(&self) -> Option<PlatformPackageManager> {
        self.manager.as_ref().map(|(manager, _)| *manager)
    }

    /// Looks up many paths at once; `dpkg -S` answers a whole batch in one call.
    pub(super) fn look_up(
        &mut self,
        paths: impl IntoIterator<Item = PathBuf>,
        cancellation: &PlatformCancellation,
    ) {
        let pending: BTreeSet<PathBuf> = paths
            .into_iter()
            .filter(|path| !self.owners.contains_key(path))
            .collect();
        let Some((manager, executable)) = self.manager.clone() else {
            self.owners
                .extend(pending.into_iter().map(|path| (path, None)));
            return;
        };
        let found = match manager {
            PlatformPackageManager::Dpkg => {
                scan_dpkg_lists(Path::new(DPKG_INFO_DIR), &pending, cancellation)
            }
            PlatformPackageManager::Rpm | PlatformPackageManager::Pacman => {
                per_path_owners(manager, &executable, &pending, cancellation)
            }
        };
        for path in pending {
            let owner = found.get(&path).cloned();
            self.owners.insert(path, owner);
        }
    }

    pub(super) fn owner(
        &mut self,
        path: &Path,
        cancellation: &PlatformCancellation,
    ) -> Option<String> {
        if !self.owners.contains_key(path) {
            self.look_up([path.to_path_buf()], cancellation);
        }
        self.owners.get(path).cloned().flatten()
    }

    pub(super) fn facts(
        &mut self,
        package: &str,
        cancellation: &PlatformCancellation,
    ) -> PackageFacts {
        let mut facts = PackageFacts::default();
        let manager = self.manager();
        if manager == Some(PlatformPackageManager::Dpkg) {
            let apt = self.apt.get_or_insert_with(load_apt_history);
            if let Some(record) = apt.records.get(package) {
                facts.installed_at_ms = Some(record.at_ms);
                facts.from_history = true;
                facts.install_command =
                    Some(record.command.clone()).filter(|command| !command.is_empty());
                facts.install_burst = record.burst;
            }
        }
        if facts.installed_at_ms.is_none() {
            facts.installed_at_ms = self.database_date(package, cancellation);
        }
        facts.request = self.request(package, cancellation);
        match manager {
            Some(PlatformPackageManager::Dpkg | PlatformPackageManager::Pacman) => {
                let index = self.index.get_or_insert_with(|| {
                    if manager == Some(PlatformPackageManager::Dpkg) {
                        PackageIndex::load_dpkg()
                    } else {
                        PackageIndex::load_pacman()
                    }
                });
                facts.description = index.description(package);
                facts.required_by = index.required_by(package);
                facts.essential = index.is_essential(package);
            }
            Some(PlatformPackageManager::Rpm) => {
                facts.description = self.rpm_summary(package, cancellation);
            }
            None => {}
        }
        facts
    }

    fn rpm_summary(&self, package: &str, cancellation: &PlatformCancellation) -> Option<String> {
        let (_, executable) = self.manager.as_ref()?;
        let output = run_tool(
            "running_programs.rpm_summary",
            executable,
            &["-q", "--qf", "%{SUMMARY}\n", "--", package],
            Duration::from_secs(15),
            cancellation,
        )?;
        output
            .success
            .then(|| output.stdout.lines().next().and_then(clean_description))
            .flatten()
    }

    fn request(
        &mut self,
        package: &str,
        cancellation: &PlatformCancellation,
    ) -> Option<PlatformPackageRequest> {
        let manager = self.manager()?;
        if manager == PlatformPackageManager::Dpkg {
            let apt = self.apt.get_or_insert_with(load_apt_history);
            match apt.records.get(package).map(|record| record.request) {
                Some(AptRequest::Asked) => return Some(PlatformPackageRequest::Requested),
                Some(AptRequest::Bulk) => return Some(PlatformPackageRequest::BulkInstall),
                Some(AptRequest::Dependency) => return Some(PlatformPackageRequest::Dependency),
                None => {}
            }
            let covers_install = apt
                .starts_at_ms
                .zip(self.system_installed_ms)
                .is_some_and(|(start, installed)| start <= installed + 3 * 86_400_000);
            if covers_install {
                // Never asked for since the system was installed.
                return Some(PlatformPackageRequest::CameWithSystem);
            }
            if is_desktop_bundled(package) {
                return None;
            }
        }
        if self.manual.is_none() {
            self.manual = Some(self.manual_packages(manager, cancellation));
        }
        let manual = self.manual.as_ref()?;
        if manual.is_empty() {
            return None;
        }
        Some(if manual.contains(package) {
            PlatformPackageRequest::Requested
        } else {
            PlatformPackageRequest::Dependency
        })
    }

    fn manual_packages(
        &self,
        manager: PlatformPackageManager,
        cancellation: &PlatformCancellation,
    ) -> BTreeSet<String> {
        let (command_id, executable, args): (_, _, &[&str]) = match manager {
            PlatformPackageManager::Dpkg => (
                "running_programs.apt_mark",
                executable_in(&["/usr/bin/apt-mark"]),
                &["showmanual"],
            ),
            PlatformPackageManager::Pacman => (
                "running_programs.pacman_explicit",
                executable_in(&["/usr/bin/pacman"]),
                &["-Qqe"],
            ),
            PlatformPackageManager::Rpm => return BTreeSet::new(),
        };
        let Some(output) = executable.and_then(|path| {
            run_tool(
                command_id,
                &path,
                args,
                Duration::from_secs(30),
                cancellation,
            )
        }) else {
            return BTreeSet::new();
        };
        let mut manual: BTreeSet<String> = output
            .stdout
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        if manager == PlatformPackageManager::Dpkg {
            // Ubuntu's installer marks everything on the install image as manual; drop those.
            if let Some(initial) =
                read_maybe_gzip(Path::new("/var/log/installer/initial-status.gz"))
            {
                for line in initial.lines() {
                    if let Some(name) = line.strip_prefix("Package: ") {
                        manual.remove(name.trim());
                    }
                }
            }
        }
        manual
    }

    fn database_date(&self, package: &str, cancellation: &PlatformCancellation) -> Option<u64> {
        let (manager, executable) = self.manager.as_ref()?;
        match manager {
            PlatformPackageManager::Dpkg => {
                let exact = Path::new(DPKG_INFO_DIR).join(format!("{package}.list"));
                if let Some(date) = modified_ms(&exact) {
                    return Some(date);
                }
                let prefix = format!("{package}:");
                std::fs::read_dir(DPKG_INFO_DIR)
                    .ok()?
                    .filter_map(Result::ok)
                    .find_map(|entry| {
                        let name = entry.file_name();
                        let name = name.to_str()?;
                        (name.starts_with(&prefix) && name.ends_with(".list"))
                            .then(|| modified_ms(&entry.path()))
                            .flatten()
                    })
            }
            PlatformPackageManager::Rpm => {
                let output = run_tool(
                    "running_programs.rpm_install_time",
                    executable,
                    &["-q", "--qf", "%{INSTALLTIME}\n", "--", package],
                    Duration::from_secs(15),
                    cancellation,
                )?;
                output
                    .stdout
                    .lines()
                    .next()?
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .map(|seconds| seconds * 1000)
            }
            PlatformPackageManager::Pacman => {
                let prefix = format!("{package}-");
                std::fs::read_dir("/var/lib/pacman/local")
                    .ok()?
                    .filter_map(Result::ok)
                    .find_map(|entry| {
                        let name = entry.file_name();
                        if !name.to_str()?.starts_with(&prefix) {
                            return None;
                        }
                        let desc = read_text(&entry.path().join("desc"), 256 * 1024)?;
                        parse_pacman_install_date(&desc, package)
                    })
            }
        }
    }
}

fn parse_pacman_install_date(desc: &str, package: &str) -> Option<u64> {
    let mut lines = desc.lines();
    let mut name_matches = false;
    let mut date = None;
    while let Some(line) = lines.next() {
        match line {
            "%NAME%" => name_matches = lines.next() == Some(package),
            "%INSTALLDATE%" => {
                date = lines
                    .next()
                    .and_then(|value| value.trim().parse::<u64>().ok())
            }
            _ => {}
        }
    }
    date.filter(|_| name_matches).map(|seconds| seconds * 1000)
}

/// Merged-/usr systems record files under either `/bin` or `/usr/bin`.
fn merged_usr_alternate(path: &Path) -> PathBuf {
    match path.strip_prefix("/usr") {
        Ok(rest) => Path::new("/").join(rest),
        Err(_) => Path::new("/usr").join(path.strip_prefix("/").unwrap_or(path)),
    }
}

/// Package name of a `/var/lib/dpkg/info/<package>[:<arch>].list` file.
fn dpkg_list_package(file_name: &str) -> Option<&str> {
    let stem = file_name.strip_suffix(".list")?;
    let package = stem.split(':').next().unwrap_or(stem);
    (!package.is_empty()).then_some(package)
}

/// Finds owners by reading dpkg's per-package file lists once. `dpkg -S` matches every argument
/// as a pattern against every installed file, which takes minutes for a few hundred paths on a
/// large system; one pass over the lists with a set lookup takes about a second.
fn scan_dpkg_lists(
    info_dir: &Path,
    paths: &BTreeSet<PathBuf>,
    cancellation: &PlatformCancellation,
) -> HashMap<PathBuf, String> {
    let mut wanted: HashMap<PathBuf, PathBuf> = HashMap::new();
    for path in paths {
        wanted.insert(merged_usr_alternate(path), path.clone());
    }
    // Exact paths win over their merged-/usr alternates.
    for path in paths {
        wanted.insert(path.clone(), path.clone());
    }
    let mut found = HashMap::new();
    let Ok(entries) = std::fs::read_dir(info_dir) else {
        return found;
    };
    for entry in entries.filter_map(Result::ok) {
        if cancellation.is_cancelled() || found.len() == paths.len() {
            break;
        }
        let file_name = entry.file_name();
        let Some(package) = file_name.to_str().and_then(dpkg_list_package) else {
            continue;
        };
        let Ok(file) = std::fs::File::open(entry.path()) else {
            continue;
        };
        for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
            if let Some(original) = wanted.get(Path::new(&line)) {
                let exact = Path::new(&line) == original.as_path();
                let slot = found
                    .entry(original.clone())
                    .or_insert_with(|| package.to_owned());
                if exact {
                    *slot = package.to_owned();
                }
            }
        }
    }
    found
}

fn per_path_owners(
    manager: PlatformPackageManager,
    executable: &Path,
    paths: &BTreeSet<PathBuf>,
    cancellation: &PlatformCancellation,
) -> HashMap<PathBuf, String> {
    let query = |path: &Path| -> Option<String> {
        [path.to_path_buf(), merged_usr_alternate(path)]
            .iter()
            .find_map(|candidate| {
                let candidate = candidate.to_string_lossy();
                let (command_id, args): (_, Vec<&str>) = match manager {
                    PlatformPackageManager::Rpm => (
                        "running_programs.rpm_owner",
                        vec!["-qf", "--qf", "%{NAME}\n", "--", &candidate],
                    ),
                    _ => (
                        "running_programs.pacman_owner",
                        vec!["-Qqo", "--", &candidate],
                    ),
                };
                let output = run_tool(
                    command_id,
                    executable,
                    &args,
                    Duration::from_secs(15),
                    cancellation,
                )?;
                if !output.success {
                    return None;
                }
                output
                    .stdout
                    .lines()
                    .next()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.contains(' '))
                    .map(str::to_owned)
            })
    };
    let paths: Vec<&PathBuf> = paths.iter().collect();
    let mut found = HashMap::new();
    std::thread::scope(|scope| {
        let workers: Vec<_> = paths
            .chunks(paths.len().div_ceil(8).max(1))
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .filter_map(|path| query(path).map(|owner| ((*path).clone(), owner)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for worker in workers {
            if let Ok(results) = worker.join() {
                found.extend(results);
            }
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const HISTORY: &str = "\nStart-Date: 2025-01-10  10:00:00\nCommandline: apt install ripgrep\nRequested-By: me (1000)\nInstall: ripgrep:amd64 (14.1.0-1), libpcre2:amd64 (10.42, automatic)\nEnd-Date: 2025-01-10  10:00:05\n\nStart-Date: 2025-02-01  09:00:00\nCommandline: apt install ./tool_1.0_amd64.deb\nInstall: tool-cli:amd64 (1.0)\nEnd-Date: 2025-02-01  09:00:03\n\nStart-Date: 2025-03-01  09:00:00\nCommandline: packagekit role='install-packages'\nInstall: libpcre2:amd64 (10.42)\nEnd-Date: 2025-03-01  09:00:03\n";

    #[test]
    fn install_field_splits_names_and_details() {
        let entries = parse_install_field("a:amd64 (1.0, automatic), b (2.0)");
        assert_eq!(
            entries,
            vec![
                ("a".to_owned(), "1.0, automatic".to_owned()),
                ("b".to_owned(), "2.0".to_owned())
            ]
        );
    }

    #[test]
    fn apt_history_records_who_asked_and_keeps_the_first_date() {
        let history = build_apt_history(parse_apt_transactions(HISTORY));
        let ripgrep = &history.records["ripgrep"];
        assert_eq!(ripgrep.request, AptRequest::Asked);
        assert_eq!(ripgrep.command, "apt install ripgrep");
        // A local .deb whose file name differs from the package is still a request.
        assert_eq!(history.records["tool-cli"].request, AptRequest::Asked);
        let pcre = &history.records["libpcre2"];
        assert_eq!(pcre.request, AptRequest::Asked, "asked for later by name");
        assert_eq!(pcre.at_ms, ripgrep.at_ms, "first install date is kept");
        assert_eq!(pcre.command, "apt install ripgrep");
        assert!(!history.records["libpcre2"].burst);
    }

    #[test]
    fn bursts_of_installs_are_marked() {
        let blocks: String = (0..6)
            .map(|minute| format!("Start-Date: 2025-04-01  10:{minute:02}:00\nCommandline: apt install pkg{minute}\nInstall: pkg{minute}:amd64 (1)\n\n"))
            .collect();
        let history = build_apt_history(parse_apt_transactions(&blocks));
        assert!(history.records["pkg0"].burst);
        assert_eq!(history.records["pkg0"].request, AptRequest::Bulk);
    }

    #[test]
    fn dpkg_lists_map_paths_and_merged_usr_alternates_to_packages() {
        let dir = std::env::temp_dir().join(format!("md-dpkg-info-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("python3.12-minimal:amd64.list"),
            "/.\n/usr\n/usr/bin/python3.12\n",
        )
        .unwrap();
        std::fs::write(dir.join("coreutils.list"), "/bin/sleep\n").unwrap();
        std::fs::write(dir.join("coreutils.md5sums"), "/usr/bin/python3.12\n").unwrap();
        let paths: BTreeSet<PathBuf> = ["/usr/bin/python3.12", "/usr/bin/sleep", "/opt/tool/run"]
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let found = scan_dpkg_lists(&dir, &paths, &PlatformCancellation::new(|| false));
        assert_eq!(
            found[Path::new("/usr/bin/python3.12")],
            "python3.12-minimal"
        );
        assert_eq!(found[Path::new("/usr/bin/sleep")], "coreutils");
        assert!(!found.contains_key(Path::new("/opt/tool/run")));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn merged_usr_alternates_both_ways() {
        assert_eq!(
            merged_usr_alternate(Path::new("/usr/bin/x")),
            PathBuf::from("/bin/x")
        );
        assert_eq!(
            merged_usr_alternate(Path::new("/sbin/y")),
            PathBuf::from("/usr/sbin/y")
        );
    }

    #[test]
    fn pacman_desc_install_date_requires_the_matching_name() {
        let desc = "%NAME%\nripgrep\n\n%VERSION%\n14-1\n\n%INSTALLDATE%\n1700000000\n";
        assert_eq!(
            parse_pacman_install_date(desc, "ripgrep"),
            Some(1_700_000_000_000)
        );
        assert_eq!(parse_pacman_install_date(desc, "rip"), None);
    }
}
