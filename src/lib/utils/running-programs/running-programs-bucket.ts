import type { ProgramOriginKind, RunningProgram } from '@/lib/models/running-programs/running-programs';

/** How a program got onto the machine, coarse enough to weigh as a group. */
export type ProgramOriginGroup =
  | 'distro'
  | 'python'
  | 'node'
  | 'sandboxed'
  | 'containers'
  | 'toolchains'
  | 'projects'
  | 'manual'
  | 'services'
  | 'unknown';

const ORIGIN_GROUPS: Record<ProgramOriginKind, ProgramOriginGroup> = {
  systemPackage: 'distro',
  pipUser: 'python',
  pipSystem: 'python',
  pip: 'python',
  pipx: 'python',
  uvTool: 'python',
  virtualenv: 'python',
  conda: 'python',
  npmGlobal: 'node',
  pnpmGlobal: 'node',
  yarnGlobal: 'node',
  bunGlobal: 'node',
  volta: 'node',
  npxCache: 'node',
  nodeProject: 'node',
  flatpak: 'sandboxed',
  snap: 'sandboxed',
  appImage: 'sandboxed',
  container: 'containers',
  homebrew: 'toolchains',
  cargo: 'toolchains',
  rustup: 'toolchains',
  go: 'toolchains',
  nix: 'toolchains',
  project: 'projects',
  gitClone: 'projects',
  manualLocal: 'manual',
  manualOpt: 'manual',
  homeFile: 'manual',
  addedService: 'services',
  unknown: 'unknown',
};

/** Memory and swap together: what the program holds, wherever the kernel keeps it. */
export function programFootprintKb(program: RunningProgram): number {
  return program.memoryKb + program.swapKb;
}

/** Programs below this footprint look too small to matter one at a time. */
export const SMALL_PROGRAM_KB = 100 * 1024;

export function originGroup(kind: ProgramOriginKind): ProgramOriginGroup {
  return ORIGIN_GROUPS[kind];
}

export interface BucketGroup {
  group: ProgramOriginGroup;
  count: number;
  footprintKb: number;
  cpuPercentAverage: number;
}

export interface ProgramBucket {
  count: number;
  footprintKb: number;
  cpuPercentNow: number;
  cpuPercentAverage: number;
  smallCount: number;
  smallFootprintKb: number;
  /** Heaviest group first. */
  groups: BucketGroup[];
}

/** Weighs everything that is not a core desktop or system component. */
export function weighBucket(programs: readonly RunningProgram[]): ProgramBucket {
  const bucket: ProgramBucket = {
    count: 0,
    footprintKb: 0,
    cpuPercentNow: 0,
    cpuPercentAverage: 0,
    smallCount: 0,
    smallFootprintKb: 0,
    groups: [],
  };
  const groups = new Map<ProgramOriginGroup, BucketGroup>();
  for (const program of programs) {
    if (program.safety === 'core') continue;
    const footprint = programFootprintKb(program);
    bucket.count += 1;
    bucket.footprintKb += footprint;
    bucket.cpuPercentNow += program.cpuPercentNow;
    bucket.cpuPercentAverage += program.cpuPercentAverage;
    if (footprint < SMALL_PROGRAM_KB) {
      bucket.smallCount += 1;
      bucket.smallFootprintKb += footprint;
    }
    const group = originGroup(program.origin.kind);
    const entry = groups.get(group) ?? { group, count: 0, footprintKb: 0, cpuPercentAverage: 0 };
    entry.count += 1;
    entry.footprintKb += footprint;
    entry.cpuPercentAverage += program.cpuPercentAverage;
    groups.set(group, entry);
  }
  bucket.groups = [...groups.values()].sort((left, right) => right.footprintKb - left.footprintKb);
  return bucket;
}
