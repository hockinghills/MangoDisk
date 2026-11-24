/** Mirrors `mangodisk_core::running_programs::models`. Keep both sides in one change. */
export const RUNNING_PROGRAMS_SCHEMA_VERSION = 1;

export type ProgramOriginKind =
  | 'systemPackage'
  | 'pipUser'
  | 'pipSystem'
  | 'pip'
  | 'pipx'
  | 'uvTool'
  | 'virtualenv'
  | 'conda'
  | 'npmGlobal'
  | 'pnpmGlobal'
  | 'yarnGlobal'
  | 'bunGlobal'
  | 'volta'
  | 'npxCache'
  | 'project'
  | 'nodeProject'
  | 'addedService'
  | 'homebrew'
  | 'cargo'
  | 'rustup'
  | 'go'
  | 'flatpak'
  | 'snap'
  | 'appImage'
  | 'container'
  | 'nix'
  | 'gitClone'
  | 'manualLocal'
  | 'manualOpt'
  | 'homeFile'
  | 'unknown';

export type ProgramDateSource =
  | 'packageHistory'
  | 'packageDatabase'
  | 'installReceipt'
  | 'packageRecord'
  | 'containerCreated'
  | 'revisionDownloaded'
  | 'lastInstallOrUpdate'
  | 'virtualenvCreated'
  | 'gitHistory'
  | 'folderDate'
  | 'fileDate'
  | 'unitFileDate';

export type ProgramPackageManager = 'dpkg' | 'rpm' | 'pacman';
export type ProgramPackageRequest = 'requested' | 'bulkInstall' | 'dependency' | 'cameWithSystem';
export type ProgramContainerEngine = 'docker' | 'podman' | 'lxc' | 'incus' | 'kubernetes';
export type ProgramUnitFileOrigin = 'package' | 'addedToEtc' | 'addedToHome' | 'generated' | 'unknown';
export type ProgramUnitScope = 'user' | 'system';
export type ProgramSafetyClass = 'core' | 'optional' | 'system' | 'yours';

export type ProgramLaunchKind =
  | 'autostart'
  | 'appLaunched'
  | 'onDemand'
  | 'session'
  | 'userService'
  | 'transient'
  | 'terminal'
  | 'loginSession'
  | 'systemService'
  | 'cron'
  | 'container'
  | 'init'
  | 'widget'
  | 'ssh'
  | 'child'
  | 'unknown';

export interface ProgramContainer {
  engine: ProgramContainerEngine | null;
  id: string;
  name: string | null;
  image: string | null;
  composeProject: string | null;
  composeService: string | null;
  project: string | null;
}

export type ProgramOriginFact =
  | { kind: 'brewDependency' }
  | { kind: 'installedUnderNvm'; value: string }
  | { kind: 'installedBy'; value: string }
  | { kind: 'editableInstall'; value: string }
  | { kind: 'runAsModule'; value: string }
  | { kind: 'virtualenvOfGitClone'; value: string }
  | { kind: 'lastGitActivity'; value: number }
  | { kind: 'hasOwnVirtualenv' }
  | { kind: 'hasOwnNodeModules' }
  | { kind: 'runsDependency'; value: string }
  | { kind: 'launchedThroughRunner'; value: string }
  | { kind: 'runsScript'; value: string }
  | { kind: 'updatedInPlace'; value: number }
  | { kind: 'flatpakUserInstall' }
  | { kind: 'flatpakSystemInstall' }
  | { kind: 'rustupProxy' }
  | { kind: 'copiedByInstallScript' }
  | { kind: 'unownedSystemFile' }
  | { kind: 'containerNamesUnavailable' }
  | { kind: 'noPermission' }
  | { kind: 'containerRunsCommand'; value: string }
  | { kind: 'serviceRunsProgram'; value: { program: string; package: string | null } }
  | { kind: 'serviceFile'; value: { path: string; origin: ProgramUnitFileOrigin } };

export interface ProgramOrigin {
  kind: ProgramOriginKind;
  name: string;
  version: string | null;
  installedAtMs: number | null;
  dateSource: ProgramDateSource | null;
  sourceUrl: string | null;
  location: string | null;
  packageManager: ProgramPackageManager | null;
  packageRequest: ProgramPackageRequest | null;
  installCommand: string | null;
  installBurst: boolean;
  container: ProgramContainer | null;
  facts: ProgramOriginFact[];
}

export interface ProgramLaunch {
  kind: ProgramLaunchKind;
  unit: string | null;
  scope: ProgramUnitScope | null;
  desktopName: string | null;
  backgroundSlice: boolean;
  terminal: string | null;
  multiplexer: string | null;
  spawnedBy: string | null;
  spawnedByEditor: boolean;
}

export type ProgramProcessRole =
  'main' | 'renderer' | 'extension' | 'gpu' | 'utility' | 'zygote' | 'crashHandler' | 'other';

export interface ProgramProcess {
  pid: number;
  parentPid: number;
  uid: number;
  name: string;
  commandLine: string[];
  executablePath: string | null;
  workingDirectory: string | null;
  startedAtMs: number;
  cpuPercentNow: number;
  memoryKb: number;
  memoryIsProportional: boolean;
  swapKb: number;
  foldedFrom: string | null;
  inlineCode: boolean;
  role: ProgramProcessRole | null;
  roleDetail: string | null;
}

export interface RunningProgram {
  id: string;
  name: string;
  packageName: string | null;
  origin: ProgramOrigin;
  safety: ProgramSafetyClass;
  launches: ProgramLaunch[];
  processes: ProgramProcess[];
  memoryKb: number;
  memoryIsProportional: boolean;
  swapKb: number;
  cpuPercentNow: number;
  cpuPercentAverage: number;
  cpuSeconds: number;
  startedAtMs: number;
  quietSinceStart: boolean;
  executableReplaced: boolean;
}

export interface RunningProgramsMemory {
  totalKb: number;
  availableKb: number;
  swapTotalKb: number;
  swapUsedKb: number;
  compressedSwapUsedKb: number | null;
  compressedSwapRamKb: number | null;
}

export interface RunningProgramsSummary {
  processCount: number;
  programCount: number;
  sideInstalledCount: number;
  memoryKb: number;
  swapKb: number;
}

export interface RunningProgramsSnapshot {
  schemaVersion: number;
  capturedAtMs: number;
  elapsedMs: number;
  elevated: boolean;
  memory: RunningProgramsMemory;
  programs: RunningProgram[];
  summary: RunningProgramsSummary;
}

export const PROGRAM_ORIGIN_KINDS: readonly ProgramOriginKind[] = [
  'systemPackage',
  'pipUser',
  'pipSystem',
  'pip',
  'pipx',
  'uvTool',
  'virtualenv',
  'conda',
  'npmGlobal',
  'pnpmGlobal',
  'yarnGlobal',
  'bunGlobal',
  'volta',
  'npxCache',
  'project',
  'nodeProject',
  'addedService',
  'homebrew',
  'cargo',
  'rustup',
  'go',
  'flatpak',
  'snap',
  'appImage',
  'container',
  'nix',
  'gitClone',
  'manualLocal',
  'manualOpt',
  'homeFile',
  'unknown',
];

export const PROGRAM_SAFETY_CLASSES: readonly ProgramSafetyClass[] = ['yours', 'optional', 'system', 'core'];

export type RunningProgramsFilter = 'all' | 'sideInstalled' | 'yours' | 'quiet';
export type RunningProgramsSort = 'memory' | 'cpuNow' | 'cpuAverage' | 'installed' | 'name';
