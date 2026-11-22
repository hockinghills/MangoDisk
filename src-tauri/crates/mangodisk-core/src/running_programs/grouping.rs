//! Turns per-process facts into one row per program.
//!
//! Helper processes are counted against the program that runs them: everything a systemd service
//! starts, an app's library helpers and inline code, and distro tools a side-installed program
//! launches. A distro binary run by a service someone added becomes a row named after that
//! service, so `python3` started by `my-bot.service` is not merged with every other Python.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
};

use mangodisk_platform::{
    PlatformProcessRecord, PlatformServiceUnitFacts, PlatformServiceUnitScope,
    PlatformUnitFileOrigin,
};

use super::{
    conversion::{self, path_text},
    launch::{
        parse_cgroup_launch, refine_launch, ProcessLink, CRON_UNITS, EDITORS, MULTIPLEXERS,
        ROOT_PARENTS, SHELLS, TERMINALS,
    },
    models::{
        ProgramDateSource, ProgramLaunch, ProgramLaunchKind, ProgramOrigin, ProgramOriginFact,
        ProgramOriginKind, ProgramPackageRequest, ProgramProcess, ProgramSafetyClass,
        RunningProgram,
    },
    redaction::redact_command_line,
};

const HELPER_PREFIXES: &[&str] = &[
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/libexec/",
    "/lib/",
    "/lib64/",
];
/// Below this average CPU use since start (percent of one core) a long-running program is quiet.
const QUIET_AVERAGE_CPU: f64 = 0.2;
const QUIET_CURRENT_CPU: f64 = 0.5;
const QUIET_MIN_UPTIME_MS: u64 = 6 * 3600 * 1000;

const CORE_NAMES: &[&str] = &[
    "systemd",
    "dbus-daemon",
    "dbus-broker",
    "dbus-broker-launch",
    "kwin_wayland",
    "kwin_wayland_wrapper",
    "kwin_x11",
    "plasmashell",
    "ksmserver",
    "kded5",
    "kded6",
    "kglobalaccel5",
    "kglobalacceld",
    "Xwayland",
    "Xorg",
    "X",
    "sddm",
    "sddm-helper",
    "startplasma-wayland",
    "startplasma-x11",
    "plasma_session",
    "pipewire",
    "pipewire-pulse",
    "wireplumber",
    "pulseaudio",
    "polkit-kde-authentication-agent-1",
    "polkit-kde-auth",
    "polkitd",
    "kactivitymanagerd",
    "org_kde_powerdevil",
    "powerdevil",
    "kscreen_backend_launcher",
    "NetworkManager",
    "wpa_supplicant",
    "iwd",
    "udisksd",
    "upowerd",
    "accounts-daemon",
    "rtkit-daemon",
    "agetty",
    "login",
    "(sd-pam)",
    "kwalletd5",
    "kwalletd6",
    "ksecretd",
    "xdg-desktop-portal",
    "xdg-desktop-portal-kde",
    "xdg-desktop-portal-gtk",
    "xdg-document-portal",
    "xdg-permission-store",
    "gvfsd",
    "at-spi-bus-launcher",
    "at-spi2-registryd",
    "plasma-kwin_wayland",
    "kwin_wayland-wrapper",
    "bluetoothd",
    "chronyd",
    "avahi-daemon",
    "cupsd",
    "thermald",
    "irqbalance",
    "power-profiles-daemon",
    "tuned",
    "auditd",
    "firewalld",
    "ModemManager",
    "smartd",
    "colord",
    "geoclue",
    "switcheroo-control",
    "fprintd",
    "iio-sensor-proxy",
    "low-memory-monitor",
    "zram-generator",
    "systemd-oomd",
    "earlyoom",
    "lightdm",
    "gdm",
    "sshd",
];
const CORE_PREFIXES: &[&str] = &[
    "systemd-", "kworker", "xdg-", "at-spi", "gvfs", "ibus", "fcitx", "sddm", "dbus-",
];
const CORE_PACKAGES: &[&str] = &[
    "plasma-workspace",
    "plasma-workspace-wayland",
    "plasma-desktop",
    "kwin-wayland",
    "kwin-x11",
    "kwin",
    "sddm",
    "pipewire",
    "pipewire-bin",
    "pipewire-pulse",
    "wireplumber",
    "systemd",
    "systemd-sysv",
    "dbus",
    "dbus-daemon",
    "dbus-broker",
    "dbus-user-session",
    "xwayland",
    "xserver-xorg-core",
    "kded",
    "kf6-kded",
    "kded6",
    "kglobalacceld",
    "powerdevil",
    "polkit-kde-agent-1",
    "xdg-desktop-portal",
    "xdg-desktop-portal-kde",
    "xdg-desktop-portal-gtk",
    "plasma-integration",
    "kscreen",
    "libkscreen-bin",
    "network-manager",
    "networkmanager",
    "policykit-1",
    "polkitd",
    "udisks2",
    "upower",
    "accountsservice",
    "rtkit",
    "bluez",
    "kactivitymanagerd",
    "plasma-activities",
    "kde-cli-tools",
    "at-spi2-core",
    "gvfs",
    "gvfs-daemons",
    "xdg-dbus-proxy",
    "kwallet6",
    "libkf6wallet-bin",
    "kwalletmanager",
    "kwallet",
    "plasma-nm",
    "plasma-pa",
    "kinit",
    "ibus",
    "fcitx5",
    "plasma5support",
    "libplasma",
    "kio",
    "kf6-kio",
    "libkf6kiocore6",
    "kio-extras",
    "ksystemstats",
];
/// Desktop components that the desktop's own settings can switch off.
const OPTIONAL_NAMES: &[&str] = &[
    "baloo_file",
    "baloo_file_extractor",
    "baloorunner",
    "akonadiserver",
    "akonadi_control",
    "kdeconnectd",
    "DiscoverNotifier",
    "plasma-discover",
    "xembedsniproxy",
    "kaccess",
    "plasma-browser-integration-host",
    "tracker-miner-fs-3",
    "localsearch-3",
    "localsearch",
    "evolution-data-server",
    "evolution-source-registry",
    "evolution-addressbook-factory",
    "evolution-calendar-factory",
    "goa-daemon",
    "packagekitd",
    "fwupd",
    "kded6",
    "ksystemstats",
    "kalendarac",
    "merkuro-calendar",
    "org.kde.merkuro.contact",
    "kmail",
    "snapd",
    "drkonqi-coredump-launcher",
    "drkonqi-coredump-processor",
    "drkonqi",
    "intel_gpu_top",
    "mount.ntfs-3g",
    "mount.ntfs",
    "dockerd",
    "containerd",
    "ollama",
    "cupsd",
];
const LAUNCHED_BY_USER: &[ProgramLaunchKind] = &[
    ProgramLaunchKind::Autostart,
    ProgramLaunchKind::UserService,
    ProgramLaunchKind::AppLaunched,
    ProgramLaunchKind::Terminal,
    ProgramLaunchKind::Child,
    ProgramLaunchKind::OnDemand,
];

struct Entry {
    record: PlatformProcessRecord,
    origin: ProgramOrigin,
    folded_from: Option<String>,
    launch: Option<ProgramLaunch>,
}

impl Entry {
    fn program_path(&self) -> Option<&Path> {
        self.record
            .executable_path
            .as_deref()
            .or(self.record.target.path.as_deref())
    }
}

fn base_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
}

fn starts_with_any(path: &Path, prefixes: &[&str]) -> bool {
    let text = path.to_string_lossy();
    prefixes.iter().any(|prefix| text.starts_with(prefix))
}

fn fold(entry: &mut Entry, into: &ProgramOrigin) {
    entry
        .folded_from
        .get_or_insert_with(|| entry.origin.name.clone());
    entry.origin = into.clone();
}

/// Counts distro tools (sleep, curl, ffmpeg…) against the side-installed program that started
/// them, and library helpers against the program that spawned them.
fn fold_children(entries: &mut [Entry], index: &HashMap<u32, usize>) {
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by_key(|position| {
        (
            entries[*position].record.started_at_ms,
            entries[*position].record.pid,
        )
    });
    for position in order {
        let entry = &entries[position];
        if entry.origin.kind != ProgramOriginKind::SystemPackage
            || SHELLS.contains(&entry.record.name.as_str())
        {
            continue;
        }
        let Some(&parent_position) = index.get(&entry.record.parent_pid) else {
            continue;
        };
        let parent = &entries[parent_position];
        if parent.origin.kind == ProgramOriginKind::Container {
            continue;
        }
        let helper = entry
            .program_path()
            .is_some_and(|path| starts_with_any(path, HELPER_PREFIXES))
            || entry.origin.name.starts_with("lib");
        let parent_name = parent.record.name.as_str();
        let own_app = !ROOT_PARENTS.contains(&parent_name)
            && !SHELLS.contains(&parent_name)
            && !TERMINALS.contains(&parent_name)
            && parent.record.pid != 1;
        if parent.origin.kind.is_side_install() || (helper && own_app) {
            let into = parent.origin.clone();
            fold(&mut entries[position], &into);
        }
    }
}

/// Everything a systemd service runs belongs to that service's program (a monitoring agent and
/// its plugins, a mail server and its workers). App scopes keep only their own helpers.
fn fold_by_cgroup(entries: &mut [Entry], home: Option<&Path>) {
    let mut members: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (position, entry) in entries.iter().enumerate() {
        if let Some(cgroup) = &entry.record.cgroup {
            members.entry(cgroup.clone()).or_default().push(position);
        }
    }
    for (cgroup, positions) in members {
        if positions.len() < 2 {
            continue;
        }
        let last = cgroup
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("");
        let service =
            last.ends_with(".service") && !last.starts_with("user@") && !CRON_UNITS.contains(&last);
        let app_scope = last.starts_with("app-") && last.ends_with(".scope");
        if !(service || app_scope) || last.starts_with("docker-") || last.starts_with("libpod-") {
            continue;
        }
        let Some(&anchor) = positions.iter().min_by_key(|position| {
            (
                entries[**position].record.started_at_ms,
                entries[**position].record.pid,
            )
        }) else {
            continue;
        };
        let anchor_names = [
            entries[anchor].record.name.as_str(),
            entries[anchor]
                .record
                .executable_path
                .as_deref()
                .map(base_name)
                .unwrap_or(""),
        ];
        // A terminal or editor runs whatever you start inside it; those stay separate programs.
        let hosts_other_programs = anchor_names.iter().any(|name| {
            TERMINALS.contains(name)
                || MULTIPLEXERS.contains(name)
                || EDITORS.contains(name)
                || SHELLS.contains(name)
                || ROOT_PARENTS.contains(name)
        });
        let into = entries[anchor].origin.clone();
        if hosts_other_programs || into.kind == ProgramOriginKind::Container {
            continue;
        }
        let into_key = into.group_key();
        let app_stem = entries[anchor]
            .record
            .name
            .to_lowercase()
            .split(['-', '_', '.', ' '])
            .next()
            .unwrap_or("")
            .to_owned();
        for position in positions {
            if position == anchor || entries[position].origin.group_key() == into_key {
                continue;
            }
            let entry = &entries[position];
            let path = entry.program_path().map(Path::to_path_buf);
            let helper = path
                .as_deref()
                .is_some_and(|path| starts_with_any(path, HELPER_PREFIXES));
            // Binaries an app unpacked into a folder named after it (~/.app/bin/tool).
            let own_folder = app_stem.len() >= 4
                && path
                    .as_deref()
                    .zip(home)
                    .and_then(|(path, home)| path.strip_prefix(home).ok().map(Path::to_path_buf))
                    .is_some_and(|relative: PathBuf| {
                        relative.parent().is_some_and(|parent| {
                            parent.iter().any(|part| {
                                part.to_string_lossy()
                                    .trim_start_matches('.')
                                    .to_lowercase()
                                    .starts_with(&app_stem)
                            })
                        })
                    });
            if service || helper || entry.record.target.inline || own_folder {
                fold(&mut entries[position], &into);
            }
        }
    }
}

fn unit_stem(unit: &str) -> &str {
    unit.strip_suffix(".service").unwrap_or(unit)
}

/// Names a distro program run by a service someone added after that service.
fn name_added_services(entries: &mut [Entry], units: &[PlatformServiceUnitFacts]) {
    let facts: HashMap<(PlatformServiceUnitScope, &str), &PlatformServiceUnitFacts> = units
        .iter()
        .map(|unit| ((unit.scope, unit.name.as_str()), unit))
        .collect();
    let mut renamed: HashMap<String, ProgramOrigin> = HashMap::new();
    for entry in entries.iter_mut() {
        if !matches!(
            entry.origin.kind,
            ProgramOriginKind::SystemPackage | ProgramOriginKind::Unknown
        ) {
            continue;
        }
        let Some(launch) = &entry.launch else {
            continue;
        };
        let scope = match launch.kind {
            ProgramLaunchKind::UserService => PlatformServiceUnitScope::User,
            ProgramLaunchKind::SystemService => PlatformServiceUnitScope::System,
            _ => continue,
        };
        let Some(unit) = launch.unit.clone() else {
            continue;
        };
        let Some(details) = facts.get(&(scope, unit.as_str())) else {
            continue;
        };
        let added = matches!(
            details.fragment_origin,
            PlatformUnitFileOrigin::AddedToEtc | PlatformUnitFileOrigin::AddedToHome
        );
        // snapd writes its own units to /etc/systemd/system/snap.*.service.
        let by_snapd = details
            .fragment_path
            .as_deref()
            .is_some_and(|path| base_name(path).starts_with("snap."));
        if !added || by_snapd {
            continue;
        }
        let stem = unit_stem(&unit);
        let exe_name = entry
            .record
            .executable_path
            .as_deref()
            .map(base_name)
            .unwrap_or("");
        if stem == entry.origin.name || stem == entry.record.name || stem == exe_name {
            continue;
        }
        let key = format!("{scope:?}:{unit}");
        let package = (entry.origin.kind == ProgramOriginKind::SystemPackage)
            .then(|| entry.origin.name.clone());
        let program = entry.record.name.clone();
        let origin = renamed.entry(key.clone()).or_insert_with(|| {
            let mut facts_list = vec![ProgramOriginFact::ServiceRunsProgram { program, package }];
            if let Some(path) = &details.fragment_path {
                facts_list.push(ProgramOriginFact::ServiceFile {
                    path: path_text(path),
                    origin: conversion::unit_file_origin(&details.fragment_origin),
                });
            }
            ProgramOrigin {
                kind: ProgramOriginKind::AddedService,
                name: stem.to_owned(),
                version: None,
                installed_at_ms: details.fragment_modified_ms,
                date_source: details
                    .fragment_modified_ms
                    .map(|_| ProgramDateSource::UnitFileDate),
                source_url: None,
                location: Some(format!("unit:{key}")),
                package_manager: None,
                package_request: None,
                install_command: None,
                install_burst: false,
                container: None,
                facts: facts_list,
            }
        });
        entry.origin = origin.clone();
    }
}

fn safety_class(
    name: &str,
    own_names: &HashSet<String>,
    origin: &ProgramOrigin,
    launch_kinds: &HashSet<ProgramLaunchKind>,
) -> ProgramSafetyClass {
    let mut names = own_names.clone();
    names.insert(name.to_owned());
    let system_package = origin.kind == ProgramOriginKind::SystemPackage;
    let core = names.iter().any(|name| CORE_NAMES.contains(&name.as_str()))
        || own_names
            .iter()
            .any(|name| CORE_PREFIXES.iter().any(|prefix| name.starts_with(prefix)))
        || (system_package && CORE_PACKAGES.contains(&origin.name.as_str()));
    if core {
        return ProgramSafetyClass::Core;
    }
    if origin.kind.is_side_install() {
        return ProgramSafetyClass::Yours;
    }
    if names
        .iter()
        .any(|name| OPTIONAL_NAMES.contains(&name.as_str()))
    {
        return ProgramSafetyClass::Optional;
    }
    let requested = origin.package_request == Some(ProgramPackageRequest::Requested);
    if system_package
        && !requested
        && launch_kinds.len() == 1
        && launch_kinds.contains(&ProgramLaunchKind::Session)
    {
        return ProgramSafetyClass::Core;
    }
    if names.iter().any(|name| SHELLS.contains(&name.as_str())) {
        return ProgramSafetyClass::System;
    }
    if system_package
        && requested
        && launch_kinds
            .iter()
            .any(|kind| LAUNCHED_BY_USER.contains(kind))
    {
        return ProgramSafetyClass::Yours;
    }
    ProgramSafetyClass::System
}

pub(super) struct GroupingInput {
    pub processes: Vec<PlatformProcessRecord>,
    pub units: Vec<PlatformServiceUnitFacts>,
    pub home: Option<PathBuf>,
    pub now_ms: u64,
}

pub(super) fn group_programs(input: GroupingInput) -> Vec<RunningProgram> {
    let mut entries: Vec<Entry> = input
        .processes
        .into_iter()
        .map(|mut record| {
            let origin = conversion::origin(std::mem::replace(
                &mut record.origin,
                mangodisk_platform::PlatformProgramOrigin::new(
                    mangodisk_platform::PlatformProgramOriginKind::Unknown,
                    String::new(),
                ),
            ));
            Entry {
                record,
                origin,
                folded_from: None,
                launch: None,
            }
        })
        .collect();
    let index: HashMap<u32, usize> = entries
        .iter()
        .enumerate()
        .map(|(position, entry)| (entry.record.pid, position))
        .collect();
    fold_children(&mut entries, &index);
    fold_by_cgroup(&mut entries, input.home.as_deref());

    let group_of: HashMap<u32, String> = entries
        .iter()
        .map(|entry| (entry.record.pid, entry.origin.group_key()))
        .collect();
    let launches: Vec<ProgramLaunch> = {
        let table: HashMap<u32, ProcessLink<'_>> = entries
            .iter()
            .map(|entry| {
                (
                    entry.record.pid,
                    ProcessLink {
                        pid: entry.record.pid,
                        parent_pid: entry.record.parent_pid,
                        name: entry.record.name.as_str(),
                    },
                )
            })
            .collect();
        entries
            .iter()
            .map(|entry| {
                refine_launch(
                    parse_cgroup_launch(entry.record.cgroup.as_deref()),
                    entry.record.pid,
                    &table,
                    &group_of,
                )
            })
            .collect()
    };
    for (entry, launch) in entries.iter_mut().zip(launches) {
        entry.launch = Some(launch);
    }
    name_added_services(&mut entries, &input.units);

    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<Entry>> = HashMap::new();
    for entry in entries {
        let key = entry.origin.group_key();
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(entry);
    }
    let mut programs: Vec<RunningProgram> = order
        .into_iter()
        .filter_map(|key| {
            groups
                .remove(&key)
                .map(|members| build_program(key, members, input.now_ms))
        })
        .collect();
    programs.sort_by(|left, right| {
        (right.memory_kb + right.swap_kb)
            .cmp(&(left.memory_kb + left.swap_kb))
            .then_with(|| left.name.cmp(&right.name))
    });
    programs
}

fn build_program(id: String, members: Vec<Entry>, now_ms: u64) -> RunningProgram {
    let origin = members[0].origin.clone();
    let mut launches: Vec<ProgramLaunch> = Vec::new();
    for launch in members.iter().filter_map(|entry| entry.launch.clone()) {
        if !launches.contains(&launch) {
            launches.push(launch);
        }
    }
    // Only the program's own processes say what it is; a folded plugin named like a system
    // component must not make the program look like part of the system.
    let own: Vec<&Entry> = {
        let own: Vec<&Entry> = members
            .iter()
            .filter(|entry| entry.folded_from.is_none())
            .collect();
        if own.is_empty() {
            members.iter().collect()
        } else {
            own
        }
    };
    let mut own_names: HashSet<String> = HashSet::new();
    for entry in &own {
        own_names.insert(entry.record.name.clone());
        if let Some(path) = &entry.record.executable_path {
            own_names.insert(base_name(path).to_owned());
        }
        if let Some(argv0) = entry
            .record
            .command_line
            .first()
            .filter(|argv0| !argv0.is_empty())
        {
            own_names.insert(base_name(Path::new(argv0)).to_owned());
        }
    }
    own_names.remove("");
    let launch_kinds: HashSet<ProgramLaunchKind> =
        launches.iter().map(|launch| launch.kind).collect();
    let safety = safety_class(&origin.name, &own_names, &origin, &launch_kinds);

    let first_name = members[0].record.name.clone();
    let single_name = members.iter().all(|entry| entry.record.name == first_name);
    let (name, package_name) = if origin.kind == ProgramOriginKind::SystemPackage
        && origin.name != first_name
        && single_name
    {
        (first_name, Some(origin.name.clone()))
    } else {
        (origin.name.clone(), None)
    };

    let memory_is_proportional = members
        .iter()
        .all(|entry| entry.record.proportional_kb.is_some());
    let memory_kb = members
        .iter()
        .map(|entry| {
            entry
                .record
                .proportional_kb
                .unwrap_or(entry.record.resident_kb)
        })
        .sum();
    let swap_kb = members.iter().map(|entry| entry.record.swap_kb).sum();
    let cpu_percent_now = members
        .iter()
        .map(|entry| entry.record.cpu_percent_now)
        .sum();
    let cpu_seconds: f64 = members.iter().map(|entry| entry.record.cpu_seconds).sum();
    let started_at_ms = members
        .iter()
        .map(|entry| entry.record.started_at_ms)
        .min()
        .unwrap_or(now_ms);
    let uptime_ms = now_ms.saturating_sub(started_at_ms).max(1000);
    let cpu_percent_average = cpu_seconds / (uptime_ms as f64 / 1000.0) * 100.0;
    let quiet_since_start = uptime_ms > QUIET_MIN_UPTIME_MS
        && cpu_percent_average < QUIET_AVERAGE_CPU
        && cpu_percent_now < QUIET_CURRENT_CPU;
    let executable_replaced = members.iter().any(|entry| entry.record.executable_replaced);

    let mut processes: Vec<ProgramProcess> = members
        .into_iter()
        .map(|entry| ProgramProcess {
            pid: entry.record.pid,
            parent_pid: entry.record.parent_pid,
            uid: entry.record.uid,
            command_line: redact_command_line(&entry.record.command_line),
            executable_path: entry.record.executable_path.as_deref().map(path_text),
            working_directory: entry.record.working_directory.as_deref().map(path_text),
            started_at_ms: entry.record.started_at_ms,
            cpu_percent_now: entry.record.cpu_percent_now,
            memory_kb: entry
                .record
                .proportional_kb
                .unwrap_or(entry.record.resident_kb),
            memory_is_proportional: entry.record.proportional_kb.is_some(),
            swap_kb: entry.record.swap_kb,
            folded_from: entry.folded_from,
            inline_code: entry.record.target.inline,
            name: entry.record.name,
        })
        .collect();
    processes.sort_by(|left, right| {
        (right.memory_kb + right.swap_kb).cmp(&(left.memory_kb + left.swap_kb))
    });

    RunningProgram {
        id,
        name,
        package_name,
        origin,
        safety,
        launches,
        processes,
        memory_kb,
        memory_is_proportional,
        swap_kb,
        cpu_percent_now,
        cpu_percent_average,
        cpu_seconds,
        started_at_ms,
        quiet_since_start,
        executable_replaced,
    }
}

#[cfg(test)]
#[path = "grouping_tests.rs"]
mod tests;
