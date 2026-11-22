//! Maps platform facts to Core models, redacting free text on the way.

use std::path::Path;

use mangodisk_platform::{
    PlatformContainerEngine, PlatformContainerFacts, PlatformOriginDateSource, PlatformOriginFact,
    PlatformPackageManager, PlatformPackageRequest, PlatformProgramOrigin,
    PlatformProgramOriginKind, PlatformUnitFileOrigin,
};

use super::{
    models::{
        ProgramContainer, ProgramContainerEngine, ProgramDateSource, ProgramOrigin,
        ProgramOriginFact, ProgramOriginKind, ProgramPackageManager, ProgramPackageRequest,
        ProgramUnitFileOrigin,
    },
    redaction::redact_text,
};

pub(super) fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn origin_kind(kind: PlatformProgramOriginKind) -> ProgramOriginKind {
    use PlatformProgramOriginKind as P;
    use ProgramOriginKind as C;
    match kind {
        P::SystemPackage => C::SystemPackage,
        P::PipUser => C::PipUser,
        P::PipSystem => C::PipSystem,
        P::Pip => C::Pip,
        P::Pipx => C::Pipx,
        P::UvTool => C::UvTool,
        P::Virtualenv => C::Virtualenv,
        P::Conda => C::Conda,
        P::NpmGlobal => C::NpmGlobal,
        P::PnpmGlobal => C::PnpmGlobal,
        P::YarnGlobal => C::YarnGlobal,
        P::BunGlobal => C::BunGlobal,
        P::Volta => C::Volta,
        P::NpxCache => C::NpxCache,
        P::Project => C::Project,
        P::NodeProject => C::NodeProject,
        P::Homebrew => C::Homebrew,
        P::Cargo => C::Cargo,
        P::Rustup => C::Rustup,
        P::Go => C::Go,
        P::Flatpak => C::Flatpak,
        P::Snap => C::Snap,
        P::AppImage => C::AppImage,
        P::Container => C::Container,
        P::Nix => C::Nix,
        P::GitClone => C::GitClone,
        P::ManualLocal => C::ManualLocal,
        P::ManualOpt => C::ManualOpt,
        P::HomeFile => C::HomeFile,
        P::Unknown => C::Unknown,
    }
}

fn date_source(source: PlatformOriginDateSource) -> ProgramDateSource {
    use PlatformOriginDateSource as P;
    use ProgramDateSource as C;
    match source {
        P::PackageHistory => C::PackageHistory,
        P::PackageDatabase => C::PackageDatabase,
        P::InstallReceipt => C::InstallReceipt,
        P::PackageRecord => C::PackageRecord,
        P::ContainerCreated => C::ContainerCreated,
        P::RevisionDownloaded => C::RevisionDownloaded,
        P::LastInstallOrUpdate => C::LastInstallOrUpdate,
        P::VirtualenvCreated => C::VirtualenvCreated,
        P::GitHistory => C::GitHistory,
        P::FolderDate => C::FolderDate,
        P::FileDate => C::FileDate,
    }
}

fn package_manager(manager: PlatformPackageManager) -> ProgramPackageManager {
    match manager {
        PlatformPackageManager::Dpkg => ProgramPackageManager::Dpkg,
        PlatformPackageManager::Rpm => ProgramPackageManager::Rpm,
        PlatformPackageManager::Pacman => ProgramPackageManager::Pacman,
    }
}

fn package_request(request: PlatformPackageRequest) -> ProgramPackageRequest {
    match request {
        PlatformPackageRequest::Requested => ProgramPackageRequest::Requested,
        PlatformPackageRequest::BulkInstall => ProgramPackageRequest::BulkInstall,
        PlatformPackageRequest::Dependency => ProgramPackageRequest::Dependency,
        PlatformPackageRequest::CameWithSystem => ProgramPackageRequest::CameWithSystem,
    }
}

fn container_engine(engine: PlatformContainerEngine) -> ProgramContainerEngine {
    match engine {
        PlatformContainerEngine::Docker => ProgramContainerEngine::Docker,
        PlatformContainerEngine::Podman => ProgramContainerEngine::Podman,
        PlatformContainerEngine::Lxc => ProgramContainerEngine::Lxc,
        PlatformContainerEngine::Incus => ProgramContainerEngine::Incus,
        PlatformContainerEngine::Kubernetes => ProgramContainerEngine::Kubernetes,
    }
}

fn container(facts: PlatformContainerFacts) -> ProgramContainer {
    ProgramContainer {
        engine: facts.engine.map(container_engine),
        id: facts.id,
        name: facts.name,
        image: facts.image,
        compose_project: facts.compose_project,
        compose_service: facts.compose_service,
        project: facts.project,
    }
}

fn fact(fact: PlatformOriginFact) -> ProgramOriginFact {
    use PlatformOriginFact as P;
    use ProgramOriginFact as C;
    match fact {
        P::BrewDependency => C::BrewDependency,
        P::InstalledUnderNvm(version) => C::InstalledUnderNvm(version),
        P::InstalledBy(installer) => C::InstalledBy(installer),
        P::EditableInstall(path) => C::EditableInstall(path_text(&path)),
        P::RunAsModule(module) => C::RunAsModule(module),
        P::VirtualenvOfGitClone(path) => C::VirtualenvOfGitClone(path_text(&path)),
        P::LastGitActivity(at) => C::LastGitActivity(at),
        P::HasOwnVirtualenv => C::HasOwnVirtualenv,
        P::HasOwnNodeModules => C::HasOwnNodeModules,
        P::RunsDependency(name) => C::RunsDependency(name),
        P::LaunchedThroughRunner(runner) => C::LaunchedThroughRunner(runner),
        P::RunsScript(script) => C::RunsScript(redact_text(&script)),
        P::UpdatedInPlace(at) => C::UpdatedInPlace(at),
        P::FlatpakUserInstall => C::FlatpakUserInstall,
        P::FlatpakSystemInstall => C::FlatpakSystemInstall,
        P::RustupProxy => C::RustupProxy,
        P::CopiedByInstallScript => C::CopiedByInstallScript,
        P::UnownedSystemFile => C::UnownedSystemFile,
        P::ContainerNamesUnavailable => C::ContainerNamesUnavailable,
        P::NoPermission => C::NoPermission,
        P::ContainerRunsCommand(command) => C::ContainerRunsCommand(redact_text(&command)),
    }
}

pub(super) fn origin(origin: PlatformProgramOrigin) -> ProgramOrigin {
    ProgramOrigin {
        kind: origin_kind(origin.kind),
        name: origin.name,
        version: origin.version,
        installed_at_ms: origin.installed_at_ms,
        date_source: origin.date_source.map(date_source),
        source_url: origin.source_url.as_deref().map(redact_text),
        location: origin.location,
        package_manager: origin.package_manager.map(package_manager),
        package_request: origin.package_request.map(package_request),
        install_command: origin.install_command.as_deref().map(redact_text),
        install_burst: origin.install_burst,
        container: origin.container.map(container),
        facts: origin.facts.into_iter().map(fact).collect(),
    }
}

pub(super) fn unit_file_origin(origin: &PlatformUnitFileOrigin) -> ProgramUnitFileOrigin {
    match origin {
        PlatformUnitFileOrigin::Package(_) => ProgramUnitFileOrigin::Package,
        PlatformUnitFileOrigin::AddedToEtc => ProgramUnitFileOrigin::AddedToEtc,
        PlatformUnitFileOrigin::AddedToHome => ProgramUnitFileOrigin::AddedToHome,
        PlatformUnitFileOrigin::Generated => ProgramUnitFileOrigin::Generated,
        PlatformUnitFileOrigin::Unknown => ProgramUnitFileOrigin::Unknown,
    }
}
