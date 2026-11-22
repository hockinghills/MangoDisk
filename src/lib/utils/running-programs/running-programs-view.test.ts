import { describe, expect, it } from 'vitest';

import type { RunningProgram } from '@/lib/models/running-programs/running-programs';

import { cpuPercentText, filterPrograms, isSideInstall, sortPrograms } from './running-programs-view';

function program(overrides: Partial<RunningProgram> & { name: string }): RunningProgram {
  return {
    id: overrides.name,
    packageName: null,
    origin: {
      kind: 'systemPackage',
      name: overrides.name,
      version: null,
      installedAtMs: null,
      dateSource: null,
      sourceUrl: null,
      location: null,
      packageManager: 'dpkg',
      packageRequest: null,
      installCommand: null,
      installBurst: false,
      container: null,
      facts: [],
    },
    safety: 'system',
    launches: [],
    processes: [],
    memoryKb: 0,
    memoryIsProportional: true,
    swapKb: 0,
    cpuPercentNow: 0,
    cpuPercentAverage: 0,
    cpuSeconds: 0,
    startedAtMs: 0,
    quietSinceStart: false,
    executableReplaced: false,
    ...overrides,
  };
}

describe('running-programs view', () => {
  const pipx = program({
    name: 'media-sync',
    safety: 'yours',
    memoryKb: 100,
    swapKb: 900,
    origin: { ...program({ name: 'x' }).origin, kind: 'pipx', name: 'media-sync', installedAtMs: 2_000 },
  });
  const sshd = program({ name: 'sshd', packageName: 'openssh-server', memoryKb: 500, cpuPercentNow: 3 });
  const quiet = program({ name: 'clamd', quietSinceStart: true, memoryKb: 50 });

  it('treats only distro packages and unknown files as not side-installed', () => {
    expect(isSideInstall('systemPackage')).toBe(false);
    expect(isSideInstall('unknown')).toBe(false);
    expect(isSideInstall('addedService')).toBe(true);
  });

  it('filters by origin, class and quietness, and searches packages and commands', () => {
    const all = [pipx, sshd, quiet];
    expect(filterPrograms(all, 'sideInstalled', '')).toEqual([pipx]);
    expect(filterPrograms(all, 'yours', '')).toEqual([pipx]);
    expect(filterPrograms(all, 'quiet', '')).toEqual([quiet]);
    expect(filterPrograms(all, 'all', 'OPENSSH')).toEqual([sshd]);
  });

  it('sorts by footprint including swap, and puts unknown install dates last', () => {
    expect(sortPrograms([sshd, pipx, quiet], 'memory').map(item => item.name)).toEqual(['media-sync', 'sshd', 'clamd']);
    expect(sortPrograms([sshd, pipx], 'installed')[0]?.name).toBe('media-sync');
    expect(sortPrograms([pipx, sshd], 'cpuNow')[0]?.name).toBe('sshd');
  });

  it('formats CPU percentages compactly', () => {
    expect(cpuPercentText(0)).toBe('0%');
    expect(cpuPercentText(0.04)).toBe('0.0%');
    expect(cpuPercentText(4.25)).toBe('4.3%');
    expect(cpuPercentText(51.6)).toBe('52%');
  });
});
