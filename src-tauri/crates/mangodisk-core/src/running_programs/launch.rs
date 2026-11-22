//! Works out what started a process from its control group, then refines that with the parent
//! chain (a terminal, an ssh login, another program).

use std::collections::{HashMap, HashSet};

use super::models::{ProgramLaunch, ProgramLaunchKind as Kind, ProgramUnitScope as Scope};

pub(super) const SHELLS: &[&str] = &[
    "bash", "sh", "dash", "zsh", "fish", "ksh", "mksh", "tcsh", "csh", "nu",
];
pub(super) const TERMINALS: &[&str] = &[
    "konsole",
    "yakuake",
    "kitty",
    "alacritty",
    "wezterm-gui",
    "wezterm",
    "foot",
    "gnome-terminal-",
    "gnome-terminal-server",
    "xterm",
    "urxvt",
    "terminator",
    "tilix",
    "xfce4-terminal",
    "ghostty",
    "kgx",
    "ptyxis-agent",
    "qterminal",
    "lxterminal",
    "sakura",
    "st",
    "tabby",
    "warp",
    "cool-retro-term",
    "terminology",
    "rio",
    "contour",
];
pub(super) const MULTIPLEXERS: &[&str] = &[
    "tmux",
    "tmux: server",
    "screen",
    "SCREEN",
    "zellij",
    "byobu",
];
pub(super) const EDITORS: &[&str] = &[
    "code",
    "codium",
    "cursor",
    "windsurf",
    "zed",
    "kate",
    "idea",
    "pycharm",
    "webstorm",
    "clion",
    "goland",
    "rustrover",
    "nvim",
    "vim",
    "emacs",
    "java",
];
/// Session and init processes that start almost everything; being their child says nothing.
pub(super) const ROOT_PARENTS: &[&str] = &[
    "systemd",
    "init",
    "kdeinit5",
    "kdeinit6",
    "plasmashell",
    "ksmserver",
    "startplasma-wayland",
    "startplasma-x11",
    "plasma_session",
    "kwin_wayland",
    "kwin_wayland_wrapper",
    "sddm-helper",
    "(sd-pam)",
];
pub(super) const CRON_UNITS: &[&str] = &[
    "cron.service",
    "cronie.service",
    "crond.service",
    "fcron.service",
    "atd.service",
];

pub(super) fn is_terminal(name: &str) -> bool {
    TERMINALS.contains(&name) || name.starts_with("gnome-terminal")
}

pub(super) fn is_multiplexer(name: &str) -> bool {
    MULTIPLEXERS.contains(&name) || name.starts_with("tmux")
}

fn launch(kind: Kind) -> ProgramLaunch {
    ProgramLaunch {
        kind,
        unit: None,
        scope: None,
        desktop_name: None,
        background_slice: false,
        terminal: None,
        multiplexer: None,
        spawned_by: None,
        spawned_by_editor: false,
    }
}

fn unit_launch(kind: Kind, unit: &str, scope: Scope) -> ProgramLaunch {
    ProgramLaunch {
        unit: Some(unit.to_owned()),
        scope: Some(scope),
        ..launch(kind)
    }
}

/// Reverses systemd's `\xNN` unit-name escaping.
pub(super) fn unescape_unit(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && bytes.get(index + 1) == Some(&b'x') {
            if let Some(value) = text
                .get(index + 2..index + 4)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            {
                out.push(value);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Strips a trailing `-<random>` instance suffix from a scope name.
fn strip_instance(name: &str) -> &str {
    match name.rsplit_once('-') {
        Some((stem, random))
            if !stem.is_empty()
                && !random.is_empty()
                && random.chars().all(|ch| ch.is_ascii_alphanumeric()) =>
        {
            stem
        }
        _ => name,
    }
}

fn desktop_name(raw: &str) -> String {
    let name = unescape_unit(raw);
    ["gnome-", "kde-", "cosmic-"]
        .iter()
        .find_map(|prefix| name.strip_prefix(prefix))
        .map(str::to_owned)
        .unwrap_or(name)
}

fn is_session_scope(cgroup: &str) -> bool {
    let parts: Vec<&str> = cgroup.split('/').filter(|part| !part.is_empty()).collect();
    parts.len() >= 3
        && parts[0] == "user.slice"
        && parts[1].starts_with("user-")
        && parts[1].ends_with(".slice")
        && parts[2].starts_with("session-")
        && parts[2].ends_with(".scope")
}

pub(super) fn parse_cgroup_launch(cgroup: Option<&str>) -> ProgramLaunch {
    let Some(cgroup) = cgroup.filter(|cgroup| !cgroup.is_empty() && *cgroup != "/") else {
        return launch(Kind::Unknown);
    };
    let segments: Vec<&str> = cgroup.split('/').filter(|part| !part.is_empty()).collect();
    let last = segments.last().copied().unwrap_or("");
    if segments.iter().any(|segment| segment.starts_with("user@")) {
        if let Some(user) = user_manager_launch(&segments, last) {
            return user;
        }
    }
    if is_session_scope(cgroup) {
        return launch(Kind::LoginSession);
    }
    if cgroup.starts_with("/system.slice/") {
        // Template units live in their own slice: /system.slice/system-cups.slice/cups.service.
        let unit = segments
            .iter()
            .rev()
            .find(|segment| {
                segment.ends_with(".service")
                    || segment.ends_with(".scope")
                    || segment.ends_with(".socket")
            })
            .copied()
            .unwrap_or_else(|| segments.get(1).copied().unwrap_or(last));
        let kind = if CRON_UNITS[..4].contains(&unit) {
            Kind::Cron
        } else if unit.starts_with("docker-") || unit.starts_with("libpod-") {
            Kind::Container
        } else {
            Kind::SystemService
        };
        return unit_launch(kind, unit, Scope::System);
    }
    if cgroup == "/init.scope" {
        return launch(Kind::Init);
    }
    if cgroup.contains("/lxc.payload.") || cgroup.starts_with("/machine.slice/") {
        let unit = if cgroup.starts_with("/machine.slice/") {
            last
        } else {
            segments.first().copied().unwrap_or(last)
        };
        return unit_launch(Kind::Container, unit, Scope::System);
    }
    launch(Kind::Unknown)
}

fn user_manager_launch(segments: &[&str], last: &str) -> Option<ProgramLaunch> {
    let user = |kind| unit_launch(kind, last, Scope::User);
    if let Some(name) = last
        .strip_prefix("app-")
        .and_then(|rest| rest.strip_suffix("@autostart.service"))
    {
        return Some(ProgramLaunch {
            desktop_name: Some(unescape_unit(name)),
            ..user(Kind::Autostart)
        });
    }
    if last.starts_with("app-flatpak-") && last.ends_with(".scope") {
        return Some(user(Kind::AppLaunched));
    }
    if let Some(rest) = last
        .strip_prefix("app-")
        .and_then(|rest| rest.strip_suffix(".scope"))
    {
        return Some(ProgramLaunch {
            desktop_name: Some(desktop_name(strip_instance(rest))),
            ..user(Kind::AppLaunched)
        });
    }
    if let Some(rest) = last
        .strip_prefix("app-")
        .and_then(|rest| rest.strip_suffix(".service"))
    {
        // Apps launched as transient services (KDE_APPLICATIONS_AS_SERVICE and similar).
        let name = rest.split_once('@').map_or(rest, |(name, _)| name);
        return Some(ProgramLaunch {
            desktop_name: Some(unescape_unit(name)),
            ..user(Kind::AppLaunched)
        });
    }
    if let Some(rest) = last
        .strip_prefix("dbus-")
        .and_then(|rest| rest.strip_suffix(".service"))
    {
        // dbus-:1.2-org.kde.kded6@0.service → org.kde.kded6
        let rest = match rest.strip_prefix(':') {
            Some(bus) => bus.split_once('-').map_or(bus, |(_, name)| name),
            None => rest,
        };
        let name = rest.split_once('@').map_or(rest, |(name, _)| name);
        return Some(ProgramLaunch {
            desktop_name: Some(unescape_unit(name)),
            ..user(Kind::OnDemand)
        });
    }
    if last.ends_with(".service") || last.ends_with(".socket") || last.ends_with(".timer") {
        if last.starts_with("user@") {
            return None;
        }
        if segments.contains(&"session.slice") {
            return Some(user(Kind::Session));
        }
        return Some(ProgramLaunch {
            background_slice: segments.contains(&"background.slice"),
            ..user(Kind::UserService)
        });
    }
    if last == "init.scope" {
        return Some(ProgramLaunch {
            scope: Some(Scope::User),
            ..launch(Kind::Session)
        });
    }
    if last.starts_with("run-") && last.ends_with(".scope") {
        return Some(user(Kind::Transient));
    }
    if last.starts_with("tmux") {
        return Some(ProgramLaunch {
            multiplexer: Some("tmux".into()),
            ..user(Kind::Terminal)
        });
    }
    for terminal in ["vte", "ptyxis", "gnome-terminal", "kgx", "wezterm", "kitty"] {
        if last
            .strip_prefix(terminal)
            .is_some_and(|rest| rest.starts_with("-spawn-"))
        {
            return Some(ProgramLaunch {
                terminal: Some(terminal.into()),
                ..user(Kind::Terminal)
            });
        }
    }
    last.ends_with(".scope").then(|| user(Kind::AppLaunched))
}

/// The minimal process facts launch refinement needs.
pub(super) struct ProcessLink<'a> {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: &'a str,
}

fn parent_chain<'a>(pid: u32, table: &HashMap<u32, ProcessLink<'a>>) -> Vec<&'a str> {
    let mut chain = Vec::new();
    let mut seen = HashSet::new();
    let mut current = table
        .get(&pid)
        .and_then(|process| table.get(&process.parent_pid));
    while let Some(process) = current {
        if !seen.insert(process.pid) || chain.len() >= 12 {
            break;
        }
        chain.push(process.name);
        if process.pid == 1 {
            break;
        }
        current = table.get(&process.parent_pid);
    }
    chain
}

/// Refines a cgroup launch with the parent chain. `group_of` maps pids to program identities so
/// "spawned by another program" is only reported across programs.
pub(super) fn refine_launch(
    mut launch: ProgramLaunch,
    pid: u32,
    table: &HashMap<u32, ProcessLink<'_>>,
    group_of: &HashMap<u32, String>,
) -> ProgramLaunch {
    let Some(process) = table.get(&pid) else {
        return launch;
    };
    if launch.unit.as_deref() == Some("plasma-plasmashell.service") && process.name != "plasmashell"
    {
        launch.kind = Kind::Widget;
    }
    if launch.kind == Kind::Cron && matches!(process.name, "cron" | "crond" | "cronie" | "fcron") {
        launch.kind = Kind::SystemService;
    }
    let chain = parent_chain(pid, table);
    let terminal = chain
        .iter()
        .find(|name| is_terminal(name))
        .map(|name| (*name).to_owned());
    let multiplexer = chain
        .iter()
        .find(|name| is_multiplexer(name))
        .map(|name| (*name).to_owned());
    if chain.iter().any(|name| name.starts_with("sshd")) {
        launch.kind = Kind::Ssh;
    } else if terminal.is_some()
        && matches!(
            launch.kind,
            Kind::AppLaunched | Kind::LoginSession | Kind::Unknown | Kind::Session
        )
    {
        launch.kind = Kind::Terminal;
        launch.terminal = terminal;
        launch.multiplexer = multiplexer;
    } else if multiplexer.is_some()
        && matches!(
            launch.kind,
            Kind::AppLaunched | Kind::LoginSession | Kind::Unknown | Kind::UserService
        )
    {
        launch.kind = Kind::Terminal;
        launch.multiplexer = multiplexer;
    }
    if let Some(parent) = table.get(&process.parent_pid) {
        let ordinary_parent = !ROOT_PARENTS.contains(&parent.name)
            && !SHELLS.contains(&parent.name)
            && !TERMINALS.contains(&parent.name)
            && !MULTIPLEXERS.contains(&parent.name);
        let theirs = group_of.get(&parent.pid);
        if ordinary_parent && theirs.is_some() && group_of.get(&pid) != theirs {
            launch.spawned_by = Some(parent.name.to_owned());
            launch.spawned_by_editor = EDITORS.contains(&parent.name);
            if matches!(
                launch.kind,
                Kind::AppLaunched | Kind::Unknown | Kind::LoginSession | Kind::Terminal
            ) {
                launch.kind = Kind::Child;
            }
        }
    }
    launch
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "/user.slice/user-1000.slice/user@1000.service";

    fn parse(path: &str) -> ProgramLaunch {
        parse_cgroup_launch(Some(path))
    }

    #[test]
    fn user_manager_units_are_classified() {
        let autostart = parse(&format!(
            "{USER}/app.slice/app-org.kde.kdeconnect.daemon@autostart.service"
        ));
        assert_eq!(autostart.kind, Kind::Autostart);
        assert_eq!(
            autostart.desktop_name.as_deref(),
            Some("org.kde.kdeconnect.daemon")
        );
        let app = parse(&format!("{USER}/app.slice/app-org.kde.konsole-12345.scope"));
        assert_eq!(app.kind, Kind::AppLaunched);
        assert_eq!(app.desktop_name.as_deref(), Some("org.kde.konsole"));
        let dbus = parse(&format!(
            "{USER}/app.slice/dbus-:1.2-org.kde.kalendarac@0.service"
        ));
        assert_eq!(dbus.kind, Kind::OnDemand);
        assert_eq!(dbus.desktop_name.as_deref(), Some("org.kde.kalendarac"));
        assert_eq!(
            parse(&format!("{USER}/session.slice/plasma-kwin_wayland.service")).kind,
            Kind::Session
        );
        let background = parse(&format!("{USER}/background.slice/syncthing.service"));
        assert_eq!(background.kind, Kind::UserService);
        assert!(background.background_slice);
        assert_eq!(parse(&format!("{USER}/init.scope")).kind, Kind::Session);
        assert_eq!(
            parse(&format!("{USER}/app.slice/run-r0123.scope")).kind,
            Kind::Transient
        );
        assert_eq!(
            parse(&format!("{USER}/app.slice/vte-spawn-0123.scope"))
                .terminal
                .as_deref(),
            Some("vte")
        );
    }

    #[test]
    fn system_cgroups_are_classified() {
        let cups = parse("/system.slice/system-cups.slice/cups.service");
        assert_eq!(cups.kind, Kind::SystemService);
        assert_eq!(cups.unit.as_deref(), Some("cups.service"));
        assert_eq!(parse("/system.slice/cron.service").kind, Kind::Cron);
        assert_eq!(
            parse("/system.slice/docker-0123456789ab.scope").kind,
            Kind::Container
        );
        assert_eq!(
            parse("/user.slice/user-1000.slice/session-3.scope").kind,
            Kind::LoginSession
        );
        assert_eq!(parse("/init.scope").kind, Kind::Init);
        assert_eq!(
            parse("/lxc.payload.web/system.slice/nginx.service").kind,
            Kind::Container
        );
        assert_eq!(parse_cgroup_launch(None).kind, Kind::Unknown);
    }

    fn table(entries: &[(u32, u32, &'static str)]) -> HashMap<u32, ProcessLink<'static>> {
        entries
            .iter()
            .map(|(pid, parent_pid, name)| {
                (
                    *pid,
                    ProcessLink {
                        pid: *pid,
                        parent_pid: *parent_pid,
                        name,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn terminals_and_ssh_override_the_cgroup() {
        let processes = table(&[
            (1, 0, "systemd"),
            (10, 1, "konsole"),
            (11, 10, "zsh"),
            (12, 11, "tmux: client"),
            (13, 11, "htop"),
            (20, 1, "sshd"),
            (21, 20, "bash"),
            (22, 21, "top"),
        ]);
        let groups: HashMap<u32, String> = HashMap::new();
        let base = parse(&format!("{USER}/app.slice/app-org.kde.konsole-1.scope"));
        let refined = refine_launch(base.clone(), 13, &processes, &groups);
        assert_eq!(refined.kind, Kind::Terminal);
        assert_eq!(refined.terminal.as_deref(), Some("konsole"));
        assert_eq!(
            refine_launch(
                parse("/user.slice/user-1000.slice/session-3.scope"),
                22,
                &processes,
                &groups
            )
            .kind,
            Kind::Ssh
        );
    }

    #[test]
    fn a_different_program_parent_is_reported() {
        let processes = table(&[(1, 0, "systemd"), (10, 1, "code"), (11, 10, "node")]);
        let groups: HashMap<u32, String> = [(10, "editor".to_owned()), (11, "server".to_owned())]
            .into_iter()
            .collect();
        let refined = refine_launch(
            parse(&format!("{USER}/app.slice/app-code-1.scope")),
            11,
            &processes,
            &groups,
        );
        assert_eq!(refined.kind, Kind::Child);
        assert_eq!(refined.spawned_by.as_deref(), Some("code"));
        assert!(refined.spawned_by_editor);
    }
}
