use std::path::PathBuf;

use super::{PlatformCancellation, PlatformError, PlatformErrorCode, PlatformResult};

/// Operating-system facts for the running-programs domain: every visible process, the file that
/// identifies the program it runs, and how that program got onto the machine.
///
/// Core owns grouping, launch interpretation, safety classes and every user-facing judgement.
/// Platforms report what the system says, including where that evidence came from, and leave
/// fields empty rather than guess.
pub trait RunningProgramsPlatform: Send + Sync {
    fn capture_running_programs(
        &self,
        _request: &PlatformRunningProgramsRequest,
        _cancellation: &PlatformCancellation,
    ) -> PlatformResult<PlatformRunningProgramsSnapshot> {
        Err(PlatformError::new(
            PlatformErrorCode::Unsupported,
            "running-program inventory is not implemented on this platform",
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformRunningProgramsRequest {
    /// Time between the two CPU samples used for current CPU use.
    pub cpu_sample_ms: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlatformRunningProgramsSnapshot {
    pub captured_at_ms: u64,
    /// Whether the capture could read other users' processes in full.
    pub elevated: bool,
    /// Home folder of the user the capture runs as; programs found under it were added by that user.
    pub home_directory: Option<PathBuf>,
    pub memory: PlatformMemoryTotals,
    pub processes: Vec<PlatformProcessRecord>,
    /// Service units seen in process cgroups, with the file that defines each one.
    pub units: Vec<PlatformServiceUnitFacts>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformMemoryTotals {
    pub total_kb: u64,
    pub available_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
    /// Swap kept as compressed pages in RAM (zram), and the RAM those pages really use.
    pub compressed_swap_used_kb: Option<u64>,
    pub compressed_swap_ram_kb: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlatformProcessRecord {
    pub pid: u32,
    pub parent_pid: u32,
    pub uid: u32,
    /// Kernel process name, at most 15 bytes on Linux.
    pub name: String,
    /// Raw command line. Core redacts secrets before anything crosses an adapter boundary.
    pub command_line: Vec<String>,
    pub executable_path: Option<PathBuf>,
    /// The program file was replaced or deleted after the process started.
    pub executable_replaced: bool,
    pub working_directory: Option<PathBuf>,
    /// Control-group path, the strongest evidence of what started the process.
    pub cgroup: Option<String>,
    pub started_at_ms: u64,
    pub cpu_seconds: f64,
    /// Percent of one core during the capture's sample window.
    pub cpu_percent_now: f64,
    pub resident_kb: u64,
    /// Proportional set size; `None` when the process belongs to another user.
    pub proportional_kb: Option<u64>,
    pub swap_kb: u64,
    pub target: PlatformProgramTarget,
    pub origin: PlatformProgramOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformInterpreterFamily {
    Python,
    Node,
    Gjs,
    Ruby,
    Perl,
    Php,
    Shell,
    Java,
    Lua,
}

/// The file that identifies the program: the script an interpreter runs, or the binary itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformProgramTarget {
    pub interpreter: Option<PlatformInterpreterFamily>,
    pub path: Option<PathBuf>,
    /// `python -m module` or a Java main class.
    pub module: Option<String>,
    /// Code passed on the command line (`python -c`, `sh -c`).
    pub inline: bool,
    /// Project folder for `npm run` style launches whose script is not on the command line.
    pub project_dir: Option<PathBuf>,
    /// Package-manager runner (npm, pnpm, yarn) the script was started through.
    pub runner: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformProgramOriginKind {
    SystemPackage,
    PipUser,
    PipSystem,
    Pip,
    Pipx,
    UvTool,
    Virtualenv,
    Conda,
    NpmGlobal,
    PnpmGlobal,
    YarnGlobal,
    BunGlobal,
    Volta,
    NpxCache,
    Project,
    NodeProject,
    Homebrew,
    Cargo,
    Rustup,
    Go,
    Flatpak,
    Snap,
    AppImage,
    Container,
    Nix,
    GitClone,
    ManualLocal,
    ManualOpt,
    HomeFile,
    Unknown,
}

/// How the install date was worked out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformOriginDateSource {
    PackageHistory,
    PackageDatabase,
    InstallReceipt,
    PackageRecord,
    ContainerCreated,
    RevisionDownloaded,
    LastInstallOrUpdate,
    VirtualenvCreated,
    GitHistory,
    FolderDate,
    FileDate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformPackageManager {
    Dpkg,
    Rpm,
    Pacman,
}

/// What the package history says about why a distro package is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformPackageRequest {
    /// Someone asked for this package by name.
    Requested,
    /// Part of a transaction that installed many packages at once, or a burst of installs.
    BulkInstall,
    /// Pulled in by another package.
    Dependency,
    /// Present since the system was installed.
    CameWithSystem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformContainerEngine {
    Docker,
    Podman,
    Lxc,
    Incus,
    Kubernetes,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformContainerFacts {
    pub engine: Option<PlatformContainerEngine>,
    pub id: String,
    /// `None` when the container engine could not be asked (no permission).
    pub name: Option<String>,
    pub image: Option<String>,
    pub compose_project: Option<String>,
    pub compose_service: Option<String>,
    /// LXC/Incus project.
    pub project: Option<String>,
}

/// Typed evidence about an origin. Core and the UI turn these into sentences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformOriginFact {
    /// A Homebrew formula installed only because another formula needed it.
    BrewDependency,
    InstalledUnderNvm(String),
    InstalledBy(String),
    EditableInstall(PathBuf),
    RunAsModule(String),
    VirtualenvOfGitClone(PathBuf),
    LastGitActivity(u64),
    HasOwnVirtualenv,
    HasOwnNodeModules,
    RunsDependency(String),
    LaunchedThroughRunner(String),
    RunsScript(String),
    UpdatedInPlace(u64),
    FlatpakUserInstall,
    FlatpakSystemInstall,
    RustupProxy,
    CopiedByInstallScript,
    UnownedSystemFile,
    ContainerNamesUnavailable,
    NoPermission,
    ContainerRunsCommand(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformProgramOrigin {
    pub kind: PlatformProgramOriginKind,
    pub name: String,
    pub version: Option<String>,
    pub installed_at_ms: Option<u64>,
    pub date_source: Option<PlatformOriginDateSource>,
    pub source_url: Option<String>,
    /// Folder, file, package name or container id that identifies this origin.
    pub location: Option<String>,
    pub package_manager: Option<PlatformPackageManager>,
    pub package_request: Option<PlatformPackageRequest>,
    /// The package-manager command line that first installed the package.
    pub install_command: Option<String>,
    /// Installs within minutes of many others, which points at an install script.
    pub install_burst: bool,
    pub container: Option<PlatformContainerFacts>,
    pub facts: Vec<PlatformOriginFact>,
}

impl PlatformProgramOrigin {
    pub fn new(kind: PlatformProgramOriginKind, name: impl Into<String>) -> Self {
        Self {
            kind,
            name: name.into(),
            version: None,
            installed_at_ms: None,
            date_source: None,
            source_url: None,
            location: None,
            package_manager: None,
            package_request: None,
            install_command: None,
            install_burst: false,
            container: None,
            facts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PlatformServiceUnitScope {
    User,
    System,
}

/// Where a service unit file came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformUnitFileOrigin {
    Package(String),
    /// Under `/etc` without a package owner: added by an administrator or an install script.
    AddedToEtc,
    /// In the user's home folder.
    AddedToHome,
    /// Generated at boot or by a tool (transient, generator, runtime).
    Generated,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformServiceUnitFacts {
    pub scope: PlatformServiceUnitScope,
    pub name: String,
    pub fragment_path: Option<PathBuf>,
    pub fragment_origin: PlatformUnitFileOrigin,
    pub fragment_modified_ms: Option<u64>,
    /// `enabled`, `disabled`, `static` and the other systemd unit-file states.
    pub unit_file_state: Option<String>,
}
