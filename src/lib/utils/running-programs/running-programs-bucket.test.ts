import { describe, expect, it } from 'vitest';

import type {
  ProgramOriginKind,
  ProgramSafetyClass,
  RunningProgram,
} from '@/lib/models/running-programs/running-programs';

import { SMALL_PROGRAM_KB, weighBucket } from './running-programs-bucket';

function program(
  name: string,
  kind: ProgramOriginKind,
  safety: ProgramSafetyClass,
  memoryKb: number,
  swapKb = 0
): RunningProgram {
  return {
    id: name,
    name,
    packageName: null,
    origin: {
      kind,
      name,
      version: null,
      installedAtMs: null,
      dateSource: null,
      sourceUrl: null,
      location: null,
      packageManager: null,
      packageRequest: null,
      installCommand: null,
      installBurst: false,
      container: null,
      facts: [],
      description: null,
      requiredByCount: null,
    },
    safety,
    launches: [],
    processes: [],
    memoryKb,
    memoryIsProportional: true,
    swapKb,
    cpuPercentNow: 1,
    cpuPercentAverage: 0.5,
    cpuSeconds: 0,
    startedAtMs: 0,
    quietSinceStart: false,
    executableReplaced: false,
  };
}

describe('weighBucket', () => {
  it('leaves out core components and groups the rest by how they were installed', () => {
    const bucket = weighBucket([
      program('plasmashell', 'systemPackage', 'core', 900_000),
      program('media-sync', 'pipx', 'yours', 50_000, 30_000),
      program('old-bot', 'virtualenv', 'yours', 20_000),
      program('cupsd', 'systemPackage', 'system', 200_000),
      program('vault', 'flatpak', 'yours', 10_000),
    ]);
    expect(bucket.count).toBe(4);
    expect(bucket.footprintKb).toBe(310_000);
    expect(bucket.cpuPercentAverage).toBeCloseTo(2);
    expect(bucket.groups.map(group => [group.group, group.count, group.footprintKb])).toEqual([
      ['distro', 1, 200_000],
      ['python', 2, 100_000],
      ['sandboxed', 1, 10_000],
    ]);
  });

  it('adds up the programs that look too small to matter one at a time', () => {
    const bucket = weighBucket([
      program('a', 'npmGlobal', 'yours', SMALL_PROGRAM_KB - 1),
      program('b', 'npmGlobal', 'yours', SMALL_PROGRAM_KB - 1),
      program('big', 'npmGlobal', 'yours', SMALL_PROGRAM_KB * 5),
    ]);
    expect(bucket.smallCount).toBe(2);
    expect(bucket.smallFootprintKb).toBe((SMALL_PROGRAM_KB - 1) * 2);
  });
});
