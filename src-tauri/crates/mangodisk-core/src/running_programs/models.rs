use serde::Serialize;

/// Increment when a field changes meaning. Snapshots are not persisted; the version lets the
/// adapter reject a frontend built against a different shape.
pub const RUNNING_PROGRAMS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningProgramsSnapshot {
    pub schema_version: u32,
    pub captured_at_ms: u64,
    pub elapsed_ms: u64,
    /// Without elevation, other users' processes hide their program files and memory details.
    pub elevated: bool,
    /// Administrator rights were asked for but this system cannot grant them (no pkexec).
    pub administrator_rights_unavailable: bool,
    pub memory: RunningProgramsMemory,
    pub programs: Vec<RunningProgram>,
    pub summary: RunningProgramsSummary,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningProgramsMemory {
    pub total_kb: u64,
    pub available_kb: u64,
    pub swap_total_kb: u64,
    pub swap_used_kb: u64,
    pub compressed_swap_used_kb: Option<u64>,
    pub compressed_swap_ram_kb: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningProgramsSummary {
    pub process_count: usize,
    pub program_count: usize,
    pub side_installed_count: usize,
    /// Memory of every listed program, proportional where the kernel allowed it.
    pub memory_kb: u64,
    pub swap_kb: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProgramOriginKind {
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
    /// A service unit someone added that runs a distro program.
    AddedService,
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

impl ProgramOriginKind {
    /// Added by hand or by a side installer rather than the distro.
    pub fn is_side_install(self) -> bool {
        !matches!(self, Self::SystemPackage | Self::Unknown)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProgramDateSource {
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
    UnitFileDate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProgramPackageManager {
    Dpkg,
    Rpm,
    Pacman,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProgramPackageRequest {
    Requested,
    BulkInstall,
    Dependency,
    CameWithSystem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProgramContainerEngine {
    Docker,
    Podman,
    Lxc,
    Incus,
    Kubernetes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramContainer {
    pub engine: Option<ProgramContainerEngine>,
    pub id: String,
    pub name: Option<String>,
    pub image: Option<String>,
    pub compose_project: Option<String>,
    pub compose_service: Option<String>,
    pub project: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProgramUnitFileOrigin {
    Package,
    AddedToEtc,
    AddedToHome,
    Generated,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProgramUnitScope {
    User,
    System,
}

/// Typed evidence about an origin; the frontend turns each into a localized sentence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub enum ProgramOriginFact {
    BrewDependency,
    InstalledUnderNvm(String),
    InstalledBy(String),
    EditableInstall(String),
    RunAsModule(String),
    VirtualenvOfGitClone(String),
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
    /// For an added service: the distro program it runs and that program's package.
    ServiceRunsProgram {
        program: String,
        package: Option<String>,
    },
    ServiceFile {
        path: String,
        origin: ProgramUnitFileOrigin,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramOrigin {
    pub kind: ProgramOriginKind,
    pub name: String,
    pub version: Option<String>,
    pub installed_at_ms: Option<u64>,
    pub date_source: Option<ProgramDateSource>,
    pub source_url: Option<String>,
    pub location: Option<String>,
    pub package_manager: Option<ProgramPackageManager>,
    pub package_request: Option<ProgramPackageRequest>,
    pub install_command: Option<String>,
    pub install_burst: bool,
    pub container: Option<ProgramContainer>,
    pub facts: Vec<ProgramOriginFact>,
}

impl ProgramOrigin {
    /// Identity used to group processes into one program.
    pub(crate) fn group_key(&self) -> String {
        format!(
            "{:?}:{}:{}",
            self.kind,
            self.location.as_deref().unwrap_or(""),
            self.name
        )
    }
}

/// How a program safely relates to the running system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProgramSafetyClass {
    /// Part of the desktop or operating system; stopping it breaks the session.
    Core,
    /// A desktop component that can be switched off in the desktop's own settings.
    Optional,
    /// Installed with the system; stop only knowing what depends on it.
    System,
    /// Something you or a side installer added.
    Yours,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProgramLaunchKind {
    Autostart,
    AppLaunched,
    OnDemand,
    Session,
    UserService,
    Transient,
    Terminal,
    LoginSession,
    SystemService,
    Cron,
    Container,
    Init,
    Widget,
    Ssh,
    Child,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramLaunch {
    pub kind: ProgramLaunchKind,
    pub unit: Option<String>,
    pub scope: Option<ProgramUnitScope>,
    /// Desktop entry or D-Bus name the session started it from.
    pub desktop_name: Option<String>,
    pub background_slice: bool,
    pub terminal: Option<String>,
    pub multiplexer: Option<String>,
    /// Another program's process that started this one.
    pub spawned_by: Option<String>,
    pub spawned_by_editor: bool,
}

/// What a process does inside a multi-process app (Chromium, Chrome, Electron apps), from its
/// `--type=` argument. These apps do not put the page or window a process serves on its command
/// line, so the role is as specific as the system can tell from outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProgramProcessRole {
    /// The main process that owns the windows.
    Main,
    /// Runs web content: tabs, frames and app pages.
    Renderer,
    /// Runs an extension's background page.
    Extension,
    Gpu,
    /// A service such as networking, storage or audio; the detail names it.
    Utility,
    /// Pre-forks renderers for faster tab start.
    Zygote,
    CrashHandler,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub uid: u32,
    pub name: String,
    pub command_line: Vec<String>,
    pub executable_path: Option<String>,
    pub working_directory: Option<String>,
    pub started_at_ms: u64,
    pub cpu_percent_now: f64,
    pub memory_kb: u64,
    pub memory_is_proportional: bool,
    pub swap_kb: u64,
    /// The program this process would be on its own, when it is counted as a helper of another.
    pub folded_from: Option<String>,
    /// Runs code passed on its command line (`python -c`, `sh -c`).
    pub inline_code: bool,
    pub role: Option<ProgramProcessRole>,
    /// The service a utility process runs, such as `NetworkService`.
    pub role_detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningProgram {
    pub id: String,
    pub name: String,
    /// The distro package, when the name shown is the process name rather than the package.
    pub package_name: Option<String>,
    pub origin: ProgramOrigin,
    pub safety: ProgramSafetyClass,
    pub launches: Vec<ProgramLaunch>,
    pub processes: Vec<ProgramProcess>,
    pub memory_kb: u64,
    pub memory_is_proportional: bool,
    pub swap_kb: u64,
    pub cpu_percent_now: f64,
    /// Average percent of one core since the oldest process started.
    pub cpu_percent_average: f64,
    pub cpu_seconds: f64,
    pub started_at_ms: u64,
    /// Running for at least six hours with almost no CPU use since it started.
    pub quiet_since_start: bool,
    /// The program file was replaced or deleted after it started (an update awaits a restart).
    pub executable_replaced: bool,
}
