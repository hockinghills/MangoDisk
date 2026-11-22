//! XDG autostart entries (`~/.config/autostart` and `$XDG_CONFIG_DIRS/autostart`).
//!
//! The user directory has the highest priority: an entry there replaces a system entry with the
//! same file name. Switching an entry off never edits or deletes files outside the user
//! directory. For a system entry it writes a user copy with `Hidden=true`, which is what the KDE
//! and GNOME autostart settings do; switching it back on sets `Hidden=false` in that copy.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use super::{
    ensure_not_cancelled, matches_any_prefix, modified_at_ms, read_bounded_text, resolve_program,
    same_mutation_facts,
};
use crate::{
    PlatformCancellation, PlatformError, PlatformErrorCode, PlatformResult,
    PlatformStartupArtifact, PlatformStartupChangeRequest, PlatformStartupChangeResult,
    PlatformStartupConfiguredState, PlatformStartupControlCapability,
    PlatformStartupCoverageReason, PlatformStartupCoverageStatus, PlatformStartupDesiredState,
    PlatformStartupDiagnosticCode, PlatformStartupIdentityConfidence, PlatformStartupOwner,
    PlatformStartupRuntimeState, PlatformStartupScope, PlatformStartupSourceKind,
    PlatformStartupSourceResult, PlatformStartupSummarySource, PlatformStartupTarget,
    PlatformStartupTargetKind, PlatformStartupTrigger, PlatformStartupTrustState,
};

pub(super) const SOURCE_ID: &str = "linux.xdg_autostart";
const ITEM_PREFIX: &str = "linux.xdg_autostart:";

/// Entries the desktop session depends on. They stay visible but cannot be switched off here.
const SESSION_ENTRY_PREFIXES: &[&str] = &[
    "at-spi",
    "gmenudbusmenuproxy",
    "gnome-keyring",
    "org.freedesktop.",
    "org.kde.kded",
    "org.kde.plasmashell",
    "pam_kwallet",
    "pipewire",
    "polkit-",
    "pulseaudio",
    "xdg-user-dirs",
    "xembedsniproxy",
];

/// Autostart directories in priority order. The first one is the user's.
struct AutostartDirs {
    user: Option<PathBuf>,
    system: Vec<PathBuf>,
}

impl AutostartDirs {
    fn current() -> Self {
        let system_config_dirs = std::env::var_os("XDG_CONFIG_DIRS")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| OsString::from("/etc/xdg"));
        Self {
            user: dirs::config_dir().map(|dir| dir.join("autostart")),
            system: std::env::split_paths(&system_config_dirs)
                .filter(|dir| dir.is_absolute())
                .map(|dir| dir.join("autostart"))
                .collect(),
        }
    }

    fn in_priority_order(&self) -> impl Iterator<Item = (&PathBuf, bool)> {
        self.user
            .iter()
            .map(|dir| (dir, true))
            .chain(self.system.iter().map(|dir| (dir, false)))
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct DesktopEntry {
    name: Option<String>,
    exec: Option<String>,
    hidden: bool,
    gnome_disabled: bool,
    only_show_in: Vec<String>,
    not_show_in: Vec<String>,
}

impl DesktopEntry {
    fn is_switched_off(&self) -> bool {
        self.hidden || self.gnome_disabled
    }

    fn shows_in(&self, desktops: &[String]) -> bool {
        let allowed = self.only_show_in.is_empty()
            || desktops
                .iter()
                .any(|desktop| self.only_show_in.contains(desktop));
        allowed
            && !desktops
                .iter()
                .any(|desktop| self.not_show_in.contains(desktop))
    }
}

/// Reads only the `[Desktop Entry]` group; `[Desktop Action …]` groups have their own `Name=`.
fn parse_desktop_entry(content: &str) -> DesktopEntry {
    let mut entry = DesktopEntry::default();
    let mut in_main_group = false;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_main_group = line == "[Desktop Entry]";
            continue;
        }
        if !in_main_group || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "Name" => entry.name = Some(value.to_string()),
            "Exec" => entry.exec = Some(value.to_string()),
            "Hidden" => entry.hidden = value.eq_ignore_ascii_case("true"),
            "X-GNOME-Autostart-enabled" => {
                entry.gnome_disabled = value.eq_ignore_ascii_case("false")
            }
            "OnlyShowIn" => entry.only_show_in = split_list(value),
            "NotShowIn" => entry.not_show_in = split_list(value),
            _ => {}
        }
    }
    entry
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(';')
        .filter(|item| !item.is_empty())
        .map(String::from)
        .collect()
}

/// Splits an `Exec=` line into words, dropping desktop field codes such as `%u` and `%F`.
fn exec_words(exec: &str) -> Vec<String> {
    let words = shell_words(exec);
    words
        .into_iter()
        .filter(|word| !(word.len() == 2 && word.starts_with('%')))
        .collect()
}

/// Minimal quoting rules from the desktop entry specification: double quotes group words and a
/// backslash escapes the next character inside them.
fn shell_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '\\' if in_quotes => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ch if ch.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            ch => current.push(ch),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// One file name with every directory that defines it, highest priority first.
struct EntryLayers {
    file_name: String,
    layers: Vec<(PathBuf, bool, DesktopEntry)>,
}

fn read_layers(
    dirs: &AutostartDirs,
    cancellation: &PlatformCancellation,
) -> PlatformResult<(BTreeMap<String, EntryLayers>, bool)> {
    let mut entries: BTreeMap<String, EntryLayers> = BTreeMap::new();
    let mut read_failure = false;
    for (dir, is_user) in dirs.in_priority_order() {
        ensure_not_cancelled(cancellation)?;
        let listing = match fs::read_dir(dir) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                read_failure = true;
                log::warn!(
                    "linux_startup_source_read_failed source={SOURCE_ID} path={} error_kind={:?} os_code={:?}",
                    crate::diagnostics::text(&dir.display().to_string()),
                    error.kind(),
                    error.raw_os_error()
                );
                continue;
            }
        };
        for item in listing {
            ensure_not_cancelled(cancellation)?;
            let Ok(item) = item else {
                read_failure = true;
                continue;
            };
            let path = item.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("desktop") {
                continue;
            }
            let Some(file_name) = item.file_name().to_str().map(String::from) else {
                continue;
            };
            let Some(content) = read_bounded_text(&path) else {
                read_failure = true;
                continue;
            };
            entries
                .entry(file_name.clone())
                .or_insert_with(|| EntryLayers {
                    file_name,
                    layers: Vec::new(),
                })
                .layers
                .push((path, is_user, parse_desktop_entry(&content)));
        }
    }
    Ok((entries, read_failure))
}

fn current_desktops() -> Vec<String> {
    std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .split(':')
        .filter(|desktop| !desktop.is_empty())
        .map(String::from)
        .collect()
}

fn artifact_from_layers(
    entry: &EntryLayers,
    desktops: &[String],
    user_dir_available: bool,
) -> Option<PlatformStartupArtifact> {
    let (effective_path, effective_is_user, effective) = entry.layers.first()?;
    // A user file that only says `Hidden=true` hides a system entry; describe the entry with the
    // first layer that still has a name and a command.
    let described = entry
        .layers
        .iter()
        .map(|(_, _, layer)| layer)
        .find(|layer| layer.name.is_some() && layer.exec.is_some())?;
    if !described.shows_in(desktops) {
        return None;
    }
    let words = exec_words(described.exec.as_deref().unwrap_or_default());
    let program = words.first().cloned().unwrap_or_default();
    let resolved = resolve_program(&program);
    let stem = entry.file_name.trim_end_matches(".desktop");
    let session_entry = matches_any_prefix(stem, SESSION_ENTRY_PREFIXES);
    let control_capability = if session_entry {
        PlatformStartupControlCapability::SystemManaged
    } else if user_dir_available {
        PlatformStartupControlCapability::Toggleable
    } else {
        PlatformStartupControlCapability::ViewOnly
    };
    let mut diagnostics = Vec::new();
    if resolved.is_none() {
        diagnostics.push(PlatformStartupDiagnosticCode::MissingTarget);
    }
    Some(PlatformStartupArtifact {
        provider_item_id: format!("{ITEM_PREFIX}{}", entry.file_name),
        source_kind: PlatformStartupSourceKind::AutostartEntry,
        scope: PlatformStartupScope::CurrentUser,
        triggers: vec![PlatformStartupTrigger::UserLogon],
        display_name: described.name.clone().unwrap_or_default(),
        configuration_path: Some(effective_path.clone()),
        target: PlatformStartupTarget {
            kind: PlatformStartupTargetKind::Executable,
            identity_key: resolved
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| program.clone()),
            path: resolved,
            executable_name: Path::new(&program)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()),
            arguments: words.into_iter().skip(1).collect(),
        },
        owner: PlatformStartupOwner {
            identity_key: None,
            name: None,
            publisher: None,
            summary: None,
            summary_source: PlatformStartupSummarySource::SourceLabel,
            version: None,
            icon_path: None,
            confidence: PlatformStartupIdentityConfidence::Unresolved,
        },
        configured_state: if effective.is_switched_off() {
            PlatformStartupConfiguredState::Disabled
        } else {
            PlatformStartupConfiguredState::Enabled
        },
        runtime_state: PlatformStartupRuntimeState::Unknown,
        control_capability,
        trust: if session_entry && !effective_is_user {
            PlatformStartupTrustState::System
        } else {
            PlatformStartupTrustState::Unknown
        },
        modified_at_ms: modified_at_ms(effective_path),
        diagnostics,
    })
}

pub(super) fn scan(
    cancellation: &PlatformCancellation,
) -> PlatformResult<PlatformStartupSourceResult> {
    scan_dirs(&AutostartDirs::current(), &current_desktops(), cancellation)
}

fn scan_dirs(
    dirs: &AutostartDirs,
    desktops: &[String],
    cancellation: &PlatformCancellation,
) -> PlatformResult<PlatformStartupSourceResult> {
    let started = std::time::Instant::now();
    let (entries, read_failure) = read_layers(dirs, cancellation)?;
    let items = entries
        .values()
        .filter_map(|entry| artifact_from_layers(entry, desktops, dirs.user.is_some()))
        .collect();
    Ok(PlatformStartupSourceResult {
        source_id: SOURCE_ID.to_string(),
        required: false,
        status: if read_failure {
            PlatformStartupCoverageStatus::Partial
        } else {
            PlatformStartupCoverageStatus::Complete
        },
        reason: read_failure.then_some(PlatformStartupCoverageReason::AccessDenied),
        items,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

pub(super) fn change(
    request: &PlatformStartupChangeRequest,
) -> PlatformResult<PlatformStartupChangeResult> {
    change_in(&AutostartDirs::current(), &current_desktops(), request)
}

fn change_in(
    dirs: &AutostartDirs,
    desktops: &[String],
    request: &PlatformStartupChangeRequest,
) -> PlatformResult<PlatformStartupChangeResult> {
    let file_name = request
        .provider_item_id
        .strip_prefix(ITEM_PREFIX)
        .filter(|name| is_plain_desktop_file_name(name))
        .ok_or_else(|| {
            PlatformError::new(PlatformErrorCode::InvalidData, "invalid autostart item id")
        })?;
    let user_dir = dirs.user.as_ref().ok_or_else(|| {
        PlatformError::new(
            PlatformErrorCode::Unsupported,
            "no user autostart directory",
        )
    })?;
    let never = PlatformCancellation::new(|| false);
    let (entries, _) = read_layers(dirs, &never)?;
    let layers = entries
        .get(file_name)
        .ok_or_else(|| PlatformError::item_changed("autostart entry no longer exists"))?;
    let current = artifact_from_layers(layers, desktops, true)
        .ok_or_else(|| PlatformError::item_changed("autostart entry no longer applies"))?;
    if !same_mutation_facts(&current, &request.expected_artifact) {
        return Err(PlatformError::item_changed(
            "autostart entry changed after preflight",
        ));
    }
    if current.control_capability != PlatformStartupControlCapability::Toggleable {
        return Err(PlatformError::new(
            PlatformErrorCode::Unsupported,
            "autostart entry cannot be switched here",
        ));
    }
    let hidden = match request.desired_state {
        PlatformStartupDesiredState::Enabled => false,
        PlatformStartupDesiredState::Disabled => true,
        PlatformStartupDesiredState::Removed => {
            return Err(PlatformError::new(
                PlatformErrorCode::Unsupported,
                "autostart entries are switched off, not removed",
            ))
        }
    };

    let user_path = user_dir.join(file_name);
    // The user's own file is the base when it exists; otherwise copy the system entry so its
    // name and command stay intact in the override.
    let base_path = layers
        .layers
        .iter()
        .find(|(path, is_user, _)| *is_user && path == &user_path)
        .or_else(|| layers.layers.iter().find(|(_, is_user, _)| !*is_user))
        .map(|(path, _, _)| path.clone())
        .ok_or_else(|| PlatformError::item_changed("autostart entry has no readable file"))?;
    let base = read_bounded_text(&base_path)
        .ok_or_else(|| PlatformError::item_changed("autostart entry could not be read"))?;
    let mut updated = set_desktop_entry_key(&base, "Hidden", if hidden { "true" } else { "false" });
    if !hidden && parse_desktop_entry(&updated).gnome_disabled {
        updated = set_desktop_entry_key(&updated, "X-GNOME-Autostart-enabled", "true");
    }
    write_user_entry(user_dir, &user_path, &updated)?;

    let (entries, _) =
        read_layers(dirs, &never).map_err(PlatformError::with_possible_side_effects)?;
    let verified_state = entries
        .get(file_name)
        .and_then(|layers| artifact_from_layers(layers, desktops, true))
        .map(|artifact| artifact.configured_state)
        .unwrap_or(PlatformStartupConfiguredState::Unknown);
    let expected = if hidden {
        PlatformStartupConfiguredState::Disabled
    } else {
        PlatformStartupConfiguredState::Enabled
    };
    log::info!(
        "linux_startup_autostart_changed file_name={} hidden={} verified={}",
        crate::diagnostics::text(file_name),
        hidden,
        verified_state == expected
    );
    Ok(PlatformStartupChangeResult {
        previous_state: current.configured_state,
        configured_state: verified_state,
        verified: verified_state == expected,
    })
}

fn is_plain_desktop_file_name(name: &str) -> bool {
    name.ends_with(".desktop")
        && !name.starts_with('.')
        && !name.contains('/')
        && !name.contains('\0')
}

/// Sets one key in the `[Desktop Entry]` group, replacing an existing value or adding the key
/// right after the group header. Every other line is kept as it was.
fn set_desktop_entry_key(content: &str, key: &str, value: &str) -> String {
    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    let mut in_main_group = false;
    let mut header_index = None;
    let mut replaced = false;
    for (index, line) in lines.iter_mut().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_main_group = trimmed == "[Desktop Entry]";
            if in_main_group && header_index.is_none() {
                header_index = Some(index);
            }
            continue;
        }
        if in_main_group
            && trimmed
                .split_once('=')
                .is_some_and(|(existing, _)| existing.trim() == key)
        {
            *line = format!("{key}={value}");
            replaced = true;
        }
    }
    if !replaced {
        match header_index {
            Some(index) => lines.insert(index + 1, format!("{key}={value}")),
            None => {
                lines.insert(0, format!("{key}={value}"));
                lines.insert(0, "[Desktop Entry]".to_string());
            }
        }
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// Writes the user entry through a temporary file and a rename, refusing to follow a symlink.
fn write_user_entry(user_dir: &Path, user_path: &Path, content: &str) -> PlatformResult<()> {
    fs::create_dir_all(user_dir)
        .map_err(|error| PlatformError::io("create autostart directory", &error))?;
    if fs::symlink_metadata(user_dir).is_ok_and(|metadata| metadata.file_type().is_symlink())
        || fs::symlink_metadata(user_path).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(PlatformError::invalid_path(
            "autostart path is a symbolic link",
        ));
    }
    let temporary = user_dir.join(format!(
        ".{}.mangodisk-{}",
        user_path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let write = || -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, user_path)
    };
    write().map_err(|error| {
        let _ = fs::remove_file(&temporary);
        PlatformError::io("write autostart entry", &error).with_possible_side_effects()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        root: PathBuf,
        dirs: AutostartDirs,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("mangodisk-xdg-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            let user = root.join("user/autostart");
            let system = root.join("system/autostart");
            fs::create_dir_all(&system).unwrap();
            Self {
                root,
                dirs: AutostartDirs {
                    user: Some(user),
                    system: vec![system],
                },
            }
        }

        fn system_file(&self, name: &str, content: &str) {
            fs::write(self.dirs.system[0].join(name), content).unwrap();
        }

        fn user_file(&self, name: &str, content: &str) {
            let user = self.dirs.user.as_ref().unwrap();
            fs::create_dir_all(user).unwrap();
            fs::write(user.join(name), content).unwrap();
        }

        fn scan(&self) -> PlatformStartupSourceResult {
            scan_dirs(
                &self.dirs,
                &["KDE".to_string()],
                &PlatformCancellation::new(|| false),
            )
            .unwrap()
        }

        fn change(
            &self,
            item: &PlatformStartupArtifact,
            desired: PlatformStartupDesiredState,
        ) -> PlatformResult<PlatformStartupChangeResult> {
            change_in(
                &self.dirs,
                &["KDE".to_string()],
                &PlatformStartupChangeRequest {
                    provider_item_id: item.provider_item_id.clone(),
                    source_id: SOURCE_ID.to_string(),
                    expected_artifact: item.clone(),
                    desired_state: desired,
                },
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    const SYSTEM_ENTRY: &str = "[Desktop Entry]\nName=Example\nExec=/bin/sh -c true %U\n[Desktop Action New]\nName=Other\n";

    #[test]
    fn a_hidden_user_copy_reports_the_system_entry_as_disabled() {
        let fixture = Fixture::new("hidden");
        fixture.system_file("example.desktop", SYSTEM_ENTRY);
        fixture.user_file("example.desktop", "[Desktop Entry]\nHidden=true\n");
        let result = fixture.scan();
        assert_eq!(result.items.len(), 1);
        let item = &result.items[0];
        assert_eq!(item.display_name, "Example");
        assert_eq!(
            item.configured_state,
            PlatformStartupConfiguredState::Disabled
        );
        assert_eq!(item.target.arguments, vec!["-c", "true"]);
    }

    #[test]
    fn switching_a_system_entry_off_and_on_only_writes_the_user_copy() {
        let fixture = Fixture::new("toggle");
        fixture.system_file("example.desktop", SYSTEM_ENTRY);
        let item = fixture.scan().items.remove(0);
        assert_eq!(
            item.control_capability,
            PlatformStartupControlCapability::Toggleable
        );

        let result = fixture
            .change(&item, PlatformStartupDesiredState::Disabled)
            .unwrap();
        assert!(result.verified);
        assert_eq!(
            result.configured_state,
            PlatformStartupConfiguredState::Disabled
        );
        assert_eq!(
            fs::read_to_string(fixture.dirs.system[0].join("example.desktop")).unwrap(),
            SYSTEM_ENTRY
        );
        let user_copy =
            fs::read_to_string(fixture.dirs.user.as_ref().unwrap().join("example.desktop"))
                .unwrap();
        assert!(user_copy.starts_with("[Desktop Entry]\nHidden=true\nName=Example\n"));

        let disabled = fixture.scan().items.remove(0);
        let result = fixture
            .change(&disabled, PlatformStartupDesiredState::Enabled)
            .unwrap();
        assert!(result.verified);
        assert_eq!(
            result.configured_state,
            PlatformStartupConfiguredState::Enabled
        );
    }

    #[test]
    fn drift_after_preflight_is_rejected() {
        let fixture = Fixture::new("drift");
        fixture.system_file("example.desktop", SYSTEM_ENTRY);
        let item = fixture.scan().items.remove(0);
        fixture.user_file(
            "example.desktop",
            "[Desktop Entry]\nName=Example\nExec=/bin/sh -c other\n",
        );
        let error = fixture
            .change(&item, PlatformStartupDesiredState::Disabled)
            .unwrap_err();
        assert_eq!(error.code(), PlatformErrorCode::ItemChanged);
    }

    #[test]
    fn gnome_disabled_entries_are_enabled_by_clearing_both_switches() {
        let fixture = Fixture::new("gnome");
        fixture.user_file(
            "tool.desktop",
            "[Desktop Entry]\nName=Tool\nExec=/bin/sh\nX-GNOME-Autostart-enabled=false\n",
        );
        let item = fixture.scan().items.remove(0);
        assert_eq!(
            item.configured_state,
            PlatformStartupConfiguredState::Disabled
        );
        assert!(
            fixture
                .change(&item, PlatformStartupDesiredState::Enabled)
                .unwrap()
                .verified
        );
    }

    #[test]
    fn session_entries_are_visible_but_system_managed() {
        let fixture = Fixture::new("session");
        fixture.system_file(
            "polkit-kde-authentication-agent-1.desktop",
            "[Desktop Entry]\nName=Polkit\nExec=/bin/sh\n",
        );
        let item = fixture.scan().items.remove(0);
        assert_eq!(
            item.control_capability,
            PlatformStartupControlCapability::SystemManaged
        );
        assert_eq!(item.trust, PlatformStartupTrustState::System);
    }

    #[test]
    fn desktop_restrictions_match_the_current_desktop() {
        let only = parse_desktop_entry("[Desktop Entry]\nOnlyShowIn=GNOME;\n");
        let not = parse_desktop_entry("[Desktop Entry]\nNotShowIn=KDE;\n");
        let gnome = vec!["ubuntu".to_string(), "GNOME".to_string()];
        let kde = vec!["KDE".to_string()];
        assert!(only.shows_in(&gnome) && !only.shows_in(&kde));
        assert!(not.shows_in(&gnome) && !not.shows_in(&kde));
    }

    #[test]
    fn missing_programs_are_reported() {
        let fixture = Fixture::new("missing");
        fixture.system_file(
            "gone.desktop",
            "[Desktop Entry]\nName=Gone\nExec=/nonexistent/gone\n",
        );
        let item = fixture.scan().items.remove(0);
        assert!(item
            .diagnostics
            .contains(&PlatformStartupDiagnosticCode::MissingTarget));
    }

    #[test]
    fn item_ids_cannot_escape_the_autostart_directory() {
        assert!(!is_plain_desktop_file_name("../x.desktop"));
        assert!(!is_plain_desktop_file_name(".hidden.desktop"));
        assert!(is_plain_desktop_file_name(
            "org.kde.discover.notifier.desktop"
        ));
    }

    #[test]
    fn quoted_exec_words_keep_spaces() {
        assert_eq!(
            exec_words(r#""/opt/My App/run" --flag %f"#),
            vec!["/opt/My App/run", "--flag"]
        );
    }
}
