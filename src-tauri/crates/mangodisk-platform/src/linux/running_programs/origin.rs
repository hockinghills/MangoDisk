//! Works out how a program got onto the machine: distro package, side installer, container,
//! sandboxed app, git clone or loose file. Checks run from the most specific evidence (the
//! process's control group) to the least (a file in the home folder).

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};

use super::{
    file_facts::{
        canonical, find_upwards, git_clone, go_build, is_system_path, landed_at_ms,
        link_modified_ms, modified_ms, parse_container_created, program_name, GitClone,
        GitDateSource,
    },
    package_index::clean_description,
    packages::PackageOwners,
    proc_reader::{read_text, RawProcess},
    python_packages::{environment_root, user_sites, PythonDistribution, PythonPackages},
    run_tool,
    target::ResolvedTarget,
};
use crate::{
    PlatformCancellation, PlatformContainerEngine, PlatformContainerFacts,
    PlatformInterpreterFamily, PlatformOriginDateSource, PlatformOriginFact, PlatformProgramOrigin,
    PlatformProgramOriginKind as Kind,
};

const CONTAINER_MARKERS: &[&str] = &[
    "libpod-conmon-",
    "docker-",
    "docker/",
    "libpod-",
    "cri-containerd-",
    "crio-",
];
const SCRIPT_TEXT_LIMIT: usize = 160;

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The container id following one of the engine markers in a cgroup path.
pub(super) fn container_id(cgroup: &str) -> Option<(String, PlatformContainerEngine)> {
    for marker in CONTAINER_MARKERS {
        let mut search = cgroup;
        while let Some(index) = search.find(marker) {
            let rest = &search[index + marker.len()..];
            let hex: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
            if hex.len() >= 12 {
                let engine = if marker.contains("libpod") {
                    PlatformContainerEngine::Podman
                } else {
                    PlatformContainerEngine::Docker
                };
                return Some((hex[..12].to_owned(), engine));
            }
            search = rest;
        }
    }
    None
}

/// `lxc.payload.<project_name>/<inner cgroup>` → (raw name, inner unit).
pub(super) fn lxc_payload(cgroup: &str) -> Option<(String, Option<String>)> {
    let rest = &cgroup[cgroup.find("/lxc.payload.")? + "/lxc.payload.".len()..];
    let (raw, inner) = rest.split_once('/').unwrap_or((rest, ""));
    let inner = inner
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|part| !part.is_empty())
        .map(str::to_owned);
    (!raw.is_empty()).then(|| (raw.to_owned(), inner))
}

/// Reverses systemd's `\xNN` unit-name escaping.
pub(super) fn unescape_unit(text: &str) -> String {
    let mut out = Vec::with_capacity(text.len());
    let bytes = text.as_bytes();
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

/// `app-flatpak-<id>-<random>.scope` → `<id>`.
pub(super) fn flatpak_scope_id(cgroup: &str) -> Option<String> {
    let rest = &cgroup[cgroup.find("app-flatpak-")? + "app-flatpak-".len()..];
    let scope = rest.split('/').next()?.strip_suffix(".scope")?;
    let (id, random) = scope.rsplit_once('-')?;
    (!id.is_empty() && random.chars().all(|ch| ch.is_ascii_alphanumeric()))
        .then(|| unescape_unit(id))
}

/// `/snap.<name>.<app>-…` → `<name>`.
pub(super) fn snap_scope_name(cgroup: &str) -> Option<String> {
    let rest = &cgroup[cgroup.find("/snap.")? + "/snap.".len()..];
    let (name, _) = rest.split_once('.')?;
    (!name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-'))
    .then(|| name.to_owned())
}

/// `/nix/store/<32 chars>-<name>/…` → (`<name>`, store path).
pub(super) fn nix_store_entry(path: &str) -> Option<(String, String)> {
    let rest = path.strip_prefix("/nix/store/")?;
    let entry = rest.split('/').next()?;
    let (hash, name) = entry.split_at_checked(32)?;
    let name = name.strip_prefix('-')?;
    (hash
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        && !name.is_empty())
    .then(|| (name.to_owned(), format!("/nix/store/{entry}")))
}

/// `<prefix>/Cellar/<formula>/<version>/…` → (cellar, formula, version).
pub(super) fn homebrew_cellar(path: &str) -> Option<(String, String, String)> {
    let index = path.rfind("/Cellar/")?;
    let mut parts = path[index + "/Cellar/".len()..].splitn(3, '/');
    let formula = parts.next().filter(|part| !part.is_empty())?;
    let version = parts.next().filter(|part| !part.is_empty())?;
    parts.next()?;
    Some((
        format!("{}/Cellar", &path[..index]),
        formula.to_owned(),
        version.to_owned(),
    ))
}

#[derive(Debug, Clone)]
struct ContainerRow {
    engine: PlatformContainerEngine,
    name: String,
    image: String,
    project: String,
    service: String,
    created: String,
}

pub(super) struct OriginClassifier {
    home: Option<PathBuf>,
    pub(super) owners: PackageOwners,
    python: PythonPackages,
    user_sites: Vec<PathBuf>,
    cargo: HashMap<PathBuf, HashMap<String, (String, String, String)>>,
    containers: Option<HashMap<String, ContainerRow>>,
    lxc_cli: Option<PlatformContainerEngine>,
}

impl OriginClassifier {
    pub(super) fn new(home: Option<PathBuf>, owners: PackageOwners) -> Self {
        let user_sites = user_sites(home.as_deref());
        let lxc_cli = if Path::new("/usr/bin/incus").exists() {
            Some(PlatformContainerEngine::Incus)
        } else {
            Some(PlatformContainerEngine::Lxc)
        };
        Self {
            home,
            owners,
            python: PythonPackages::default(),
            user_sites,
            cargo: HashMap::new(),
            containers: None,
            lxc_cli,
        }
    }

    fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }

    pub(super) fn classify(
        &mut self,
        process: &RawProcess,
        resolved: &ResolvedTarget,
        cancellation: &PlatformCancellation,
    ) -> PlatformProgramOrigin {
        if let Some(origin) = self.sandbox_or_container(process, cancellation) {
            return origin;
        }
        if let Some(origin) = appimage(process) {
            return origin;
        }
        let target = &resolved.target;
        if let Some(project) = &target.project_dir {
            if project.to_string_lossy().contains("/node_modules/") {
                // An npm -g package serving from its own dist/ folder is the same program as the package.
                let mut probe = project.to_string_lossy().into_owned();
                probe.push('/');
                if let Some(origin) = self.node(Path::new(&probe), cancellation) {
                    return origin;
                }
            }
            return self.project(project, target.runner.as_deref(), process);
        }
        if target.module.is_some() && target.interpreter == Some(PlatformInterpreterFamily::Python)
        {
            if let Some(origin) = self.python_program(resolved) {
                return origin;
            }
        }
        let Some(path) = target.path.clone() else {
            let mut origin = PlatformProgramOrigin::new(Kind::Unknown, process.name.clone());
            origin.facts.push(PlatformOriginFact::NoPermission);
            return origin;
        };
        let text = path.to_string_lossy().into_owned();
        if let Some(name) = text
            .strip_prefix("/snap/")
            .and_then(|rest| rest.split('/').next())
        {
            return snap(name);
        }
        if text.starts_with("/app/")
            || text.starts_with("/var/lib/flatpak/")
            || text.contains("/.local/share/flatpak/")
        {
            if let Some(id) = text
                .split("/flatpak/app/")
                .nth(1)
                .and_then(|rest| rest.split('/').next())
            {
                return self.flatpak(id);
            }
        }
        if let Some((name, location)) = nix_store_entry(&text) {
            let mut origin = PlatformProgramOrigin::new(Kind::Nix, name);
            origin.location = Some(location);
            return origin;
        }
        if let Some((cellar, formula, version)) = homebrew_cellar(&text) {
            return homebrew(&cellar, &formula, &version);
        }
        if text.contains("/node_modules/") {
            if let Some(origin) = self.node(&path, cancellation) {
                return origin;
            }
        }
        if let Some(toolchain) = text
            .split("/.rustup/toolchains/")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
        {
            let mut origin = PlatformProgramOrigin::new(Kind::Rustup, file_name(&path));
            origin.version = Some(toolchain.to_owned());
            origin.location = Some(text.clone());
            return origin;
        }
        if text.contains("/.cargo/bin/") {
            return self.cargo_bin(&path);
        }
        if is_go_bin(&path) {
            if let Some(build) = go_build(&path) {
                let mut origin = file_origin(Kind::Go, file_name(&path), &path);
                origin.version = build.version;
                origin.source_url = build.module;
                origin.installed_at_ms = modified_ms(&path);
                return origin;
            }
        }
        if is_system_path(&path) {
            if let Some(package) = self.owners.owner(&path, cancellation) {
                return self.system_package(package, cancellation);
            }
        }
        if let Some(origin) = self.python_program(resolved) {
            return origin;
        }
        if let Some(git) = git_clone(&path, self.home()) {
            return from_git(git);
        }
        if text.starts_with("/usr/local/") {
            let (name, version) = program_name(&path, self.home());
            let mut origin = file_origin(Kind::ManualLocal, name, &path);
            origin.version = version;
            origin.facts.push(PlatformOriginFact::CopiedByInstallScript);
            return origin;
        }
        if text.starts_with("/opt/") {
            let top: PathBuf = path.iter().take(3).collect();
            let installed = landed_at_ms(&top);
            let current = landed_at_ms(&path);
            let mut origin = PlatformProgramOrigin::new(Kind::ManualOpt, file_name(&top));
            origin.location = Some(top.to_string_lossy().into_owned());
            origin.installed_at_ms = installed.or(current);
            origin.date_source = origin
                .installed_at_ms
                .map(|_| PlatformOriginDateSource::FolderDate);
            if let (Some(installed), Some(current)) = (installed, current) {
                if current.saturating_sub(installed) > 2 * 86_400_000 {
                    origin
                        .facts
                        .push(PlatformOriginFact::UpdatedInPlace(current));
                }
            }
            return origin;
        }
        if self.home().is_some_and(|home| path.starts_with(home)) {
            let (name, version) = program_name(&path, self.home());
            let mut origin = file_origin(Kind::HomeFile, name, &path);
            origin.version = version;
            return origin;
        }
        let mut origin = PlatformProgramOrigin::new(Kind::Unknown, file_name(&path));
        origin.location = Some(text);
        if is_system_path(&path) {
            origin.installed_at_ms = modified_ms(&path);
            origin.date_source = origin
                .installed_at_ms
                .map(|_| PlatformOriginDateSource::FileDate);
            origin.facts.push(PlatformOriginFact::UnownedSystemFile);
        }
        origin
    }

    fn sandbox_or_container(
        &mut self,
        process: &RawProcess,
        cancellation: &PlatformCancellation,
    ) -> Option<PlatformProgramOrigin> {
        let cgroup = process.cgroup.as_deref()?;
        let container = container_id(cgroup);
        if container.is_some() || cgroup.contains("/kubepods") {
            return Some(self.container(container, process, cancellation));
        }
        if let Some((raw, inner)) = lxc_payload(cgroup) {
            let (project, name) = match raw.rsplit_once('_') {
                Some((project, name)) => (Some(project.to_owned()), name.to_owned()),
                None => (None, raw.clone()),
            };
            let mut origin = PlatformProgramOrigin::new(Kind::Container, name.clone());
            origin.location = Some(format!("lxc:{raw}"));
            origin.container = Some(PlatformContainerFacts {
                engine: self.lxc_cli,
                id: raw,
                name: Some(name),
                project,
                ..Default::default()
            });
            if let Some(inner) = inner {
                origin
                    .facts
                    .push(PlatformOriginFact::ContainerRunsCommand(inner));
            }
            return Some(origin);
        }
        if let Some(id) = process
            .flatpak_id
            .clone()
            .or_else(|| flatpak_scope_id(cgroup))
        {
            return Some(self.flatpak(&id));
        }
        snap_scope_name(cgroup).map(|name| snap(&name))
    }

    fn container(
        &mut self,
        found: Option<(String, PlatformContainerEngine)>,
        process: &RawProcess,
        cancellation: &PlatformCancellation,
    ) -> PlatformProgramOrigin {
        let Some((id, engine)) = found else {
            let mut origin = PlatformProgramOrigin::new(Kind::Container, process.name.clone());
            origin.location = Some("kubernetes".into());
            origin.container = Some(PlatformContainerFacts {
                engine: Some(PlatformContainerEngine::Kubernetes),
                id: "kubernetes".into(),
                ..Default::default()
            });
            origin.facts.push(PlatformOriginFact::ContainerRunsCommand(
                process.name.clone(),
            ));
            return origin;
        };
        let rows = self
            .containers
            .get_or_insert_with(|| list_containers(cancellation));
        let Some(row) = rows.get(&id).cloned() else {
            let mut origin = PlatformProgramOrigin::new(Kind::Container, id.clone());
            origin.location = Some(id.clone());
            origin.container = Some(PlatformContainerFacts {
                engine: Some(engine),
                id,
                ..Default::default()
            });
            origin.facts.push(PlatformOriginFact::ContainerRunsCommand(
                process.name.clone(),
            ));
            origin
                .facts
                .push(PlatformOriginFact::ContainerNamesUnavailable);
            return origin;
        };
        let mut origin = PlatformProgramOrigin::new(Kind::Container, row.name.clone());
        origin.location = Some(id.clone());
        origin.installed_at_ms = parse_container_created(&row.created);
        origin.date_source = origin
            .installed_at_ms
            .map(|_| PlatformOriginDateSource::ContainerCreated);
        let non_empty = |value: &str| Some(value.to_owned()).filter(|value| !value.is_empty());
        origin.container = Some(PlatformContainerFacts {
            engine: Some(row.engine),
            id,
            name: Some(row.name),
            image: non_empty(&row.image),
            compose_project: non_empty(&row.project),
            compose_service: non_empty(&row.service),
            project: None,
        });
        origin
    }

    fn flatpak(&self, app_id: &str) -> PlatformProgramOrigin {
        let mut origin = PlatformProgramOrigin::new(Kind::Flatpak, app_id);
        origin.location = Some(app_id.to_owned());
        origin.description = flatpak_summary(self.home(), app_id);
        let user_root = self
            .home()
            .map(|home| home.join(".local/share/flatpak/app"));
        let roots = user_root
            .into_iter()
            .map(|root| (root, PlatformOriginFact::FlatpakUserInstall))
            .chain([(
                PathBuf::from("/var/lib/flatpak/app"),
                PlatformOriginFact::FlatpakSystemInstall,
            )]);
        for (root, scope) in roots {
            let folder = root.join(app_id);
            if folder.is_dir() {
                origin.installed_at_ms =
                    link_modified_ms(&folder.join("current")).or_else(|| modified_ms(&folder));
                origin.date_source = origin
                    .installed_at_ms
                    .map(|_| PlatformOriginDateSource::LastInstallOrUpdate);
                origin.facts.push(scope);
                break;
            }
        }
        origin
    }

    fn system_package(
        &mut self,
        package: String,
        cancellation: &PlatformCancellation,
    ) -> PlatformProgramOrigin {
        let facts = self.owners.facts(&package, cancellation);
        let mut origin = PlatformProgramOrigin::new(Kind::SystemPackage, package.clone());
        origin.location = Some(package);
        origin.package_manager = self.owners.manager();
        origin.installed_at_ms = facts.installed_at_ms;
        origin.date_source = facts.installed_at_ms.map(|_| {
            if facts.from_history {
                PlatformOriginDateSource::PackageHistory
            } else {
                PlatformOriginDateSource::PackageDatabase
            }
        });
        origin.package_request = facts.request;
        origin.install_command = facts.install_command;
        origin.install_burst = facts.install_burst;
        origin.description = facts.description;
        origin.required_by = facts.required_by;
        if facts.essential {
            origin.facts.push(PlatformOriginFact::EssentialPackage);
        }
        origin
    }

    fn project(
        &self,
        folder: &Path,
        runner: Option<&str>,
        process: &RawProcess,
    ) -> PlatformProgramOrigin {
        let mut facts = Vec::new();
        if let Some(runner) = runner {
            facts.push(PlatformOriginFact::LaunchedThroughRunner(runner.to_owned()));
        }
        if let Some(script) = process.environment.get("npm_lifecycle_script") {
            facts.push(PlatformOriginFact::RunsScript(
                script.chars().take(SCRIPT_TEXT_LIMIT).collect(),
            ));
        }
        if let Some(git) = git_clone(folder, self.home()) {
            let mut origin = from_git(git);
            facts.append(&mut origin.facts);
            origin.facts = facts;
            return origin;
        }
        let manifest: Option<serde_json::Value> =
            read_text(&folder.join("package.json"), 1024 * 1024)
                .and_then(|text| serde_json::from_str(&text).ok());
        let mut name = file_name(folder);
        let hashed = name.len() >= 20 && name.chars().all(|ch| ch.is_ascii_hexdigit());
        if hashed || name.is_empty() {
            if let Some(manifest_name) = manifest
                .as_ref()
                .and_then(|value| value.get("name"))
                .and_then(|value| value.as_str())
            {
                name = manifest_name.to_owned();
            }
        }
        let mut origin = PlatformProgramOrigin::new(Kind::Project, name);
        origin.version = manifest
            .as_ref()
            .and_then(|value| value.get("version"))
            .and_then(|value| value.as_str())
            .map(str::to_owned);
        origin.description = manifest
            .as_ref()
            .and_then(|value| value.get("description"))
            .and_then(|value| value.as_str())
            .and_then(clean_description)
            .or_else(|| readme_summary(folder));
        origin.location = Some(folder.to_string_lossy().into_owned());
        origin.installed_at_ms = landed_at_ms(folder);
        origin.date_source = origin
            .installed_at_ms
            .map(|_| PlatformOriginDateSource::FolderDate);
        origin.facts = facts;
        origin
    }

    fn node(
        &mut self,
        path: &Path,
        cancellation: &PlatformCancellation,
    ) -> Option<PlatformProgramOrigin> {
        let text = path.to_string_lossy();
        let (prefix, rest) = text.split_once("/node_modules/")?;
        let segments: Vec<&str> = rest.split('/').collect();
        let package = if segments[0].starts_with('@') && segments.len() > 1 {
            format!("{}/{}", segments[0], segments[1])
        } else {
            segments[0].to_owned()
        };
        if matches!(package.as_str(), ".bin" | ".pnpm" | ".store" | "") {
            return None;
        }
        let package_dir = PathBuf::from(format!("{prefix}/node_modules/{package}"));
        let manifest: Option<serde_json::Value> =
            read_text(&package_dir.join("package.json"), 1024 * 1024)
                .and_then(|text| serde_json::from_str(&text).ok());
        let field = |key: &str| manifest.as_ref().and_then(|value| value.get(key));
        let name = field("name")
            .and_then(|value| value.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| package.clone());
        let version = field("version")
            .and_then(|value| value.as_str())
            .map(str::to_owned);
        let source = field("repository")
            .and_then(|repo| {
                repo.as_str()
                    .or_else(|| repo.get("url").and_then(|url| url.as_str()))
            })
            .map(str::to_owned);
        let description = field("description")
            .and_then(|value| value.as_str())
            .and_then(clean_description);
        let make = |kind: Kind, facts: Vec<PlatformOriginFact>| {
            let mut origin = PlatformProgramOrigin::new(kind, name.clone());
            origin.version = version.clone();
            origin.installed_at_ms = modified_ms(&package_dir);
            origin.date_source = origin
                .installed_at_ms
                .map(|_| PlatformOriginDateSource::FolderDate);
            origin.source_url = source.clone();
            origin.location = Some(package_dir.to_string_lossy().into_owned());
            origin.description = description.clone();
            origin.facts = facts;
            origin
        };
        if prefix.contains("/_npx/") || prefix.contains("/dlx/") || prefix.contains("/.cache/") {
            return Some(make(Kind::NpxCache, Vec::new()));
        }
        if let Some(version) = prefix
            .split("/.nvm/versions/node/")
            .nth(1)
            .and_then(|rest| rest.strip_suffix("/lib"))
            .filter(|v| !v.contains('/'))
        {
            return Some(make(
                Kind::NpmGlobal,
                vec![PlatformOriginFact::InstalledUnderNvm(version.to_owned())],
            ));
        }
        if prefix.contains("/.volta/") {
            return Some(make(Kind::Volta, Vec::new()));
        }
        if prefix.contains("/pnpm/global/") || prefix.contains("/.pnpm-global/") {
            return Some(make(Kind::PnpmGlobal, Vec::new()));
        }
        if prefix.contains("/.bun/install/global") {
            return Some(make(Kind::BunGlobal, Vec::new()));
        }
        if prefix.contains("/yarn/global") || prefix.contains("/.yarn/global") {
            return Some(make(Kind::YarnGlobal, Vec::new()));
        }
        // A global npm prefix is <prefix>/lib/node_modules with commands linked from <prefix>/bin.
        let prefix_path = Path::new(prefix);
        let global = prefix.ends_with("/lib")
            && (matches!(prefix, "/usr/lib" | "/usr/local/lib")
                || prefix_path
                    .parent()
                    .is_some_and(|root| root.join("bin").is_dir()));
        if global {
            if is_system_path(path) && self.owners.owner(path, cancellation).is_some() {
                return None; // the distro packaged this module
            }
            return Some(make(Kind::NpmGlobal, Vec::new()));
        }
        // A dependency inside some project's node_modules: identify the project instead.
        let dependency = PlatformOriginFact::RunsDependency(name.clone());
        if let Some(git) = git_clone(prefix_path, self.home()) {
            let mut origin = from_git(git);
            origin.facts.push(dependency);
            return Some(origin);
        }
        let mut origin = PlatformProgramOrigin::new(Kind::NodeProject, file_name(prefix_path));
        origin.location = Some(prefix.to_owned());
        origin.installed_at_ms = modified_ms(prefix_path);
        origin.date_source = origin
            .installed_at_ms
            .map(|_| PlatformOriginDateSource::FolderDate);
        origin.facts.push(dependency);
        Some(origin)
    }

    fn cargo_bin(&mut self, path: &Path) -> PlatformProgramOrigin {
        let text = path.to_string_lossy();
        let cargo_home = PathBuf::from(
            &text[..text
                .find("/.cargo/")
                .map_or(0, |index| index + "/.cargo".len())],
        );
        let mapping = self
            .cargo
            .entry(cargo_home.clone())
            .or_insert_with(|| cargo_installs(&cargo_home));
        let binary = file_name(path);
        match mapping.get(&binary) {
            Some((krate, version, source)) => {
                let mut origin = file_origin(Kind::Cargo, krate.clone(), path);
                origin.version = Some(version.clone());
                origin.installed_at_ms = modified_ms(path);
                origin.source_url = Some(if source.contains("crates.io") {
                    "crates.io".to_owned()
                } else {
                    source
                        .split_once('+')
                        .map_or(source.as_str(), |(_, url)| url)
                        .to_owned()
                });
                origin
            }
            None => {
                let mut origin = file_origin(Kind::Rustup, binary, path);
                origin.installed_at_ms = modified_ms(path);
                origin.facts.push(PlatformOriginFact::RustupProxy);
                origin
            }
        }
    }

    fn python_program(&mut self, resolved: &ResolvedTarget) -> Option<PlatformProgramOrigin> {
        let target = &resolved.target;
        let path = target.path.as_deref();
        let in_site = path.is_some_and(|path| {
            let text = path.to_string_lossy();
            text.contains("/site-packages/") || text.contains("/dist-packages/")
        });
        let in_bin = path
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .is_some_and(|name| name == "bin");
        if target.interpreter != Some(PlatformInterpreterFamily::Python) && !in_site && !in_bin {
            return None;
        }
        if let Some(distribution) = self.python.look_up(
            path,
            target.module.as_deref(),
            &resolved.interpreter_paths,
            &self.user_sites,
        ) {
            return Some(self.python_distribution(distribution, target.module.as_deref()));
        }
        if target.interpreter != Some(PlatformInterpreterFamily::Python) {
            return None;
        }
        let venv = path
            .and_then(|path| find_upwards(path, "pyvenv.cfg", &[]))
            .or_else(|| {
                resolved
                    .interpreter_paths
                    .iter()
                    .find_map(|path| find_upwards(path, "pyvenv.cfg", &[]))
            })?;
        if let (Some(git), Some(path)) = (
            venv.parent()
                .and_then(|parent| git_clone(parent, self.home())),
            path,
        ) {
            if path.starts_with(&git.root) {
                return None; // the project's own script; the git clone is the better answer
            }
        }
        let name = target
            .module
            .clone()
            .unwrap_or_else(|| file_name(path.unwrap_or(&venv)));
        let mut origin = PlatformProgramOrigin::new(Kind::Virtualenv, name);
        origin.location = Some(venv.to_string_lossy().into_owned());
        origin.installed_at_ms = modified_ms(&venv.join("pyvenv.cfg"));
        origin.date_source = origin
            .installed_at_ms
            .map(|_| PlatformOriginDateSource::VirtualenvCreated);
        Some(origin)
    }

    fn python_distribution(
        &self,
        distribution: PythonDistribution,
        module: Option<&str>,
    ) -> PlatformProgramOrigin {
        let root = environment_root(&distribution.site);
        let root_text = root.to_string_lossy().into_owned();
        let mut facts = Vec::new();
        if let Some(installer) = distribution
            .installer
            .as_deref()
            .filter(|installer| !matches!(*installer, "pip" | "uv"))
        {
            facts.push(PlatformOriginFact::InstalledBy(installer.to_owned()));
        }
        let kind = if root_text.contains("/pipx/venvs/") {
            Kind::Pipx
        } else if root_text.contains("/uv/tools/") {
            Kind::UvTool
        } else if root.join("conda-meta").is_dir() {
            Kind::Conda
        } else if root.join("pyvenv.cfg").exists() {
            if let Some(git) = root
                .parent()
                .and_then(|parent| git_clone(parent, self.home()))
            {
                facts.push(PlatformOriginFact::VirtualenvOfGitClone(git.root));
            }
            Kind::Virtualenv
        } else if root_text.ends_with("/.local") {
            Kind::PipUser
        } else if matches!(root_text.as_str(), "/usr" | "/usr/local") {
            Kind::PipSystem
        } else {
            Kind::Pip
        };
        let mut source = distribution.source_url.clone();
        if let Some(editable) = &distribution.editable_dir {
            facts.push(PlatformOriginFact::EditableInstall(editable.clone()));
            if let Some(remote) = git_clone(editable, self.home()).and_then(|git| git.remote) {
                source = Some(remote);
            }
        }
        if let Some(module) = module {
            let top = module.split('.').next().unwrap_or(module);
            if top != distribution.name.replace('-', "_").to_lowercase() {
                facts.push(PlatformOriginFact::RunAsModule(module.to_owned()));
            }
        }
        let mut origin = PlatformProgramOrigin::new(kind, distribution.name);
        origin.version = distribution.version;
        origin.installed_at_ms = distribution.installed_at_ms;
        origin.date_source = origin
            .installed_at_ms
            .map(|_| PlatformOriginDateSource::PackageRecord);
        origin.source_url = source;
        origin.location = Some(root_text);
        origin.description = distribution.summary;
        origin.facts = facts;
        origin
    }
}

fn file_origin(kind: Kind, name: String, path: &Path) -> PlatformProgramOrigin {
    let mut origin = PlatformProgramOrigin::new(kind, name);
    origin.location = Some(path.to_string_lossy().into_owned());
    origin.installed_at_ms = landed_at_ms(path);
    origin.date_source = origin
        .installed_at_ms
        .map(|_| PlatformOriginDateSource::FileDate);
    origin
}

fn is_go_bin(path: &Path) -> bool {
    let in_go_bin = path
        .parent()
        .is_some_and(|parent| parent.ends_with("go/bin"));
    let in_gobin =
        std::env::var_os("GOBIN").is_some_and(|gobin| !gobin.is_empty() && path.starts_with(gobin));
    in_go_bin || in_gobin
}

fn appimage(process: &RawProcess) -> Option<PlatformProgramOrigin> {
    let executable = process
        .executable
        .as_deref()?
        .to_string_lossy()
        .into_owned();
    let mount = executable.split("/.mount_").nth(1)?;
    let image = process.appimage.as_deref();
    let raw_name = image
        .map(file_name)
        .unwrap_or_else(|| mount.split('/').next().unwrap_or(mount).to_owned());
    let name = raw_name
        .strip_suffix(".AppImage")
        .or_else(|| raw_name.strip_suffix(".appimage"))
        .unwrap_or(&raw_name)
        .to_owned();
    let mut origin = PlatformProgramOrigin::new(Kind::AppImage, name);
    origin.location = Some(
        image
            .map(|image| image.to_string_lossy().into_owned())
            .unwrap_or(raw_name),
    );
    origin.installed_at_ms = image.and_then(modified_ms);
    origin.date_source = origin
        .installed_at_ms
        .map(|_| PlatformOriginDateSource::FileDate);
    Some(origin)
}

fn snap(name: &str) -> PlatformProgramOrigin {
    let current = canonical(&Path::new("/snap").join(name).join("current"));
    let revision = file_name(&current);
    let mut origin = PlatformProgramOrigin::new(Kind::Snap, name);
    origin.location = Some(name.to_owned());
    origin.description = snap_summary(name);
    if !revision.is_empty() && revision.chars().all(|ch| ch.is_ascii_digit()) {
        origin.version = Some(format!("rev {revision}"));
        origin.installed_at_ms = modified_ms(Path::new(&format!(
            "/var/lib/snapd/snaps/{name}_{revision}.snap"
        )));
        origin.date_source = origin
            .installed_at_ms
            .map(|_| PlatformOriginDateSource::RevisionDownloaded);
    }
    origin
}

fn homebrew(cellar: &str, formula: &str, version: &str) -> PlatformProgramOrigin {
    let folder = Path::new(cellar).join(formula).join(version);
    let receipt: Option<serde_json::Value> =
        read_text(&folder.join("INSTALL_RECEIPT.json"), 1024 * 1024)
            .and_then(|text| serde_json::from_str(&text).ok());
    let mut origin = PlatformProgramOrigin::new(Kind::Homebrew, formula);
    origin.version = Some(version.to_owned());
    origin.location = Some(format!("{cellar}/{formula}"));
    origin.description = homebrew_description(&folder, formula);
    match receipt
        .as_ref()
        .and_then(|value| value.get("time"))
        .and_then(serde_json::Value::as_f64)
    {
        Some(seconds) => {
            origin.installed_at_ms = Some((seconds * 1000.0) as u64);
            origin.date_source = Some(PlatformOriginDateSource::InstallReceipt);
        }
        None => {
            origin.installed_at_ms = modified_ms(&folder);
            origin.date_source = origin
                .installed_at_ms
                .map(|_| PlatformOriginDateSource::FolderDate);
        }
    }
    if receipt
        .as_ref()
        .and_then(|value| value.get("installed_on_request"))
        .and_then(serde_json::Value::as_bool)
        == Some(false)
    {
        origin.facts.push(PlatformOriginFact::BrewDependency);
    }
    origin
}

fn from_git(git: GitClone) -> PlatformProgramOrigin {
    let mut origin = PlatformProgramOrigin::new(Kind::GitClone, file_name(&git.root));
    origin.description = readme_summary(&git.root);
    origin.installed_at_ms = git.cloned_at_ms;
    origin.date_source = git.cloned_at_ms.map(|_| match git.date_source {
        GitDateSource::FirstLogEntry => PlatformOriginDateSource::GitHistory,
        GitDateSource::FolderDate => PlatformOriginDateSource::FolderDate,
    });
    origin.source_url = git.remote;
    if let Some(last) = git.last_activity_ms {
        origin.facts.push(PlatformOriginFact::LastGitActivity(last));
    }
    let has_venv = std::fs::read_dir(&git.root)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .any(|entry| entry.path().join("pyvenv.cfg").exists())
        })
        .unwrap_or(false);
    if has_venv {
        origin.facts.push(PlatformOriginFact::HasOwnVirtualenv);
    }
    if git.root.join("node_modules").is_dir() {
        origin.facts.push(PlatformOriginFact::HasOwnNodeModules);
    }
    origin.location = Some(git.root.to_string_lossy().into_owned());
    origin
}

/// The first prose paragraph of a README: skips headings, badges, images and HTML.
fn readme_summary(folder: &Path) -> Option<String> {
    let text = [
        "README.md",
        "README.rst",
        "README.txt",
        "README",
        "readme.md",
    ]
    .iter()
    .find_map(|name| read_text(&folder.join(name), 64 * 1024))?;
    let mut paragraph = Vec::new();
    for line in text.lines().map(str::trim) {
        let decoration = line.starts_with(['#', '!', '[', '<', '=', '-', '*', '`', '|', '.', ':'])
            || line.chars().all(|ch| matches!(ch, '=' | '-' | '~' | '^'));
        if line.is_empty() || decoration {
            if !paragraph.is_empty() {
                break;
            }
            continue;
        }
        paragraph.push(line);
    }
    clean_description(&paragraph.join(" "))
}

fn xml_element(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&format!("</{tag}>"))? + start;
    clean_description(&text[start..end])
}

fn flatpak_summary(home: Option<&Path>, app_id: &str) -> Option<String> {
    let roots = home
        .map(|home| home.join(".local/share/flatpak/app"))
        .into_iter()
        .chain([PathBuf::from("/var/lib/flatpak/app")]);
    roots
        .map(|root| root.join(app_id).join("current/active/files/share"))
        .flat_map(|share| {
            [
                share
                    .join("metainfo")
                    .join(format!("{app_id}.metainfo.xml")),
                share.join("appdata").join(format!("{app_id}.appdata.xml")),
            ]
        })
        .find_map(|path| read_text(&path, 512 * 1024))
        .and_then(|xml| xml_element(&xml, "summary"))
}

fn snap_summary(name: &str) -> Option<String> {
    let yaml = read_text(
        &Path::new("/snap").join(name).join("current/meta/snap.yaml"),
        256 * 1024,
    )?;
    yaml.lines()
        .find_map(|line| line.strip_prefix("summary:"))
        .map(|value| value.trim().trim_matches(['"', '\'']))
        .and_then(clean_description)
}

fn homebrew_description(folder: &Path, formula: &str) -> Option<String> {
    let recipe = read_text(
        &folder.join(".brew").join(format!("{formula}.rb")),
        256 * 1024,
    )?;
    recipe
        .lines()
        .find_map(|line| line.trim().strip_prefix("desc "))
        .map(|value| value.trim().trim_matches('"'))
        .and_then(clean_description)
}

/// Binary name → (crate, version, source) from cargo's install ledger.
fn cargo_installs(cargo_home: &Path) -> HashMap<String, (String, String, String)> {
    let mut mapping = HashMap::new();
    let ledger: Option<serde_json::Value> =
        read_text(&cargo_home.join(".crates2.json"), 8 * 1024 * 1024)
            .and_then(|text| serde_json::from_str(&text).ok());
    let Some(installs) = ledger
        .as_ref()
        .and_then(|value| value.get("installs"))
        .and_then(|value| value.as_object())
    else {
        return mapping;
    };
    for (key, value) in installs {
        // "<crate> <version> (<source>)"
        let mut parts = key.splitn(3, ' ');
        let (Some(krate), Some(version), Some(source)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let source = source
            .trim_start_matches('(')
            .trim_end_matches(')')
            .to_owned();
        for binary in value
            .get("bins")
            .and_then(|bins| bins.as_array())
            .into_iter()
            .flatten()
            .filter_map(|bin| bin.as_str())
        {
            mapping.insert(
                binary.to_owned(),
                (krate.to_owned(), version.to_owned(), source.clone()),
            );
        }
    }
    mapping
}

const CONTAINER_FORMAT: &str = "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Label \"com.docker.compose.project\"}}\t{{.Label \"com.docker.compose.service\"}}\t{{.CreatedAt}}";

fn parse_container_rows(
    engine: PlatformContainerEngine,
    text: &str,
) -> Vec<(String, ContainerRow)> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() < 6 || fields[0].len() < 12 {
                return None;
            }
            Some((
                fields[0][..12].to_owned(),
                ContainerRow {
                    engine,
                    name: fields[1].to_owned(),
                    image: fields[2].to_owned(),
                    project: fields[3].replace("<no value>", ""),
                    service: fields[4].replace("<no value>", ""),
                    created: fields[5].to_owned(),
                },
            ))
        })
        .collect()
}

/// Asks docker and podman for running containers. Without permission (not in the docker group)
/// the list is empty and containers are reported by id.
fn list_containers(cancellation: &PlatformCancellation) -> HashMap<String, ContainerRow> {
    let mut rows = HashMap::new();
    for (engine, candidates) in [
        (
            PlatformContainerEngine::Docker,
            ["/usr/bin/docker", "/usr/local/bin/docker"],
        ),
        (
            PlatformContainerEngine::Podman,
            ["/usr/bin/podman", "/usr/local/bin/podman"],
        ),
    ] {
        let Some(executable) = candidates
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
        else {
            continue;
        };
        let command_id = if engine == PlatformContainerEngine::Docker {
            "running_programs.docker_ps"
        } else {
            "running_programs.podman_ps"
        };
        let args = ["ps", "--no-trunc", "--format", CONTAINER_FORMAT];
        if let Some(output) = run_tool(
            command_id,
            &executable,
            &args,
            Duration::from_secs(10),
            cancellation,
        ) {
            rows.extend(parse_container_rows(engine, &output.stdout));
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_ids_come_from_engine_cgroups() {
        let docker = "/system.slice/docker-0123456789abcdef0123456789abcdef.scope";
        assert_eq!(
            container_id(docker),
            Some(("0123456789ab".to_owned(), PlatformContainerEngine::Docker))
        );
        let podman = "/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-abcdefabcdef1234.scope/container";
        assert_eq!(
            container_id(podman).map(|(_, engine)| engine),
            Some(PlatformContainerEngine::Podman)
        );
        assert_eq!(container_id("/system.slice/docker.service"), None);
    }

    #[test]
    fn lxc_payload_names_project_and_inner_unit() {
        assert_eq!(
            lxc_payload("/lxc.payload.dev_web/system.slice/nginx.service"),
            Some(("dev_web".to_owned(), Some("nginx.service".to_owned())))
        );
        assert_eq!(
            lxc_payload("/lxc.payload.box"),
            Some(("box".to_owned(), None))
        );
    }

    #[test]
    fn sandbox_scopes_name_their_app() {
        assert_eq!(
            flatpak_scope_id("/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.example.App-12345.scope").as_deref(),
            Some("org.example.App")
        );
        assert_eq!(
            snap_scope_name("/user.slice/snap.firefox.firefox-1234.scope").as_deref(),
            Some("firefox")
        );
        assert_eq!(unescape_unit(r"my\x2dapp"), "my-app");
    }

    #[test]
    fn store_and_cellar_paths_are_parsed() {
        let nix = format!("/nix/store/{}-ripgrep-14.1.0/bin/rg", "a".repeat(32));
        assert_eq!(
            nix_store_entry(&nix).map(|(name, _)| name).as_deref(),
            Some("ripgrep-14.1.0")
        );
        assert_eq!(
            homebrew_cellar("/home/linuxbrew/.linuxbrew/Cellar/jq/1.7.1/bin/jq"),
            Some((
                "/home/linuxbrew/.linuxbrew/Cellar".to_owned(),
                "jq".to_owned(),
                "1.7.1".to_owned()
            ))
        );
        assert_eq!(
            homebrew_cellar("/home/linuxbrew/.linuxbrew/Cellar/jq"),
            None
        );
    }

    #[test]
    fn container_rows_are_keyed_by_short_id() {
        let text =
            "0123456789abcdef\tweb\tnginx:1\tshop\tfrontend\t2024-01-02 05:04:05 +0200 EET\n";
        let rows = parse_container_rows(PlatformContainerEngine::Docker, text);
        assert_eq!(rows[0].0, "0123456789ab");
        assert_eq!(rows[0].1.project, "shop");
        let unlabeled = parse_container_rows(
            PlatformContainerEngine::Podman,
            "0123456789abcdef\tdb\tpg\t<no value>\t<no value>\t2024-01-02 03:04:05 +0000 UTC\n",
        );
        assert!(unlabeled[0].1.project.is_empty());
    }

    #[test]
    fn readme_summaries_skip_headings_and_badges() {
        let dir = std::env::temp_dir().join(format!("md-readme-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("README.md"),
            "# Tool\n\n[![build](x)](y)\n\nSyncs photos to a NAS\nevery night.\n\nMore text.\n",
        )
        .unwrap();
        assert_eq!(
            readme_summary(&dir).as_deref(),
            Some("Syncs photos to a NAS every night.")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn appstream_summaries_are_read() {
        let xml = "<component><id>x</id><summary>Password manager</summary></component>";
        assert_eq!(
            xml_element(xml, "summary").as_deref(),
            Some("Password manager")
        );
        assert_eq!(xml_element(xml, "description"), None);
    }
}
