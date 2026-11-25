import { describe, expect, it } from 'vitest';

import type { RunningProgram } from '@/lib/models/running-programs/running-programs';
import type { ProgramTriage } from '@/lib/models/running-programs/triage';

import {
  cpuPercentText,
  filterPrograms,
  isSideInstall,
  leftoverProbability,
  sortPrograms,
} from './running-programs-view';

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
      description: null,
      requiredByCount: null,
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

describe('triage-aware view', () => {
  const big = program({ name: 'big', memoryKb: 1000 });
  const small = program({ name: 'small', memoryKb: 100 });
  const unjudged = program({ name: 'unjudged', memoryKb: 5000 });
  function judged(id: string, choice: string, probabilities: Record<string, number>): ProgramTriage {
    return {
      programId: id,
      answers: {
        role: {
          type: 'choice',
          choice,
          probabilities,
          confidence: Math.max(...Object.values(probabilities)),
          ordersAgree: true,
        },
      },
      role: null,
      roleProbabilities: {},
      confidence: 0,
      missLevel: null,
      missProbabilities: [],
      ordersAgree: true,
    };
  }
  const triage = new Map<string, ProgramTriage>([
    ['big', judged('big', 'tool', { tool: 0.9, leftover: 0.1 })],
    ['small', judged('small', 'leftover', { leftover: 0.95, tool: 0.05 })],
  ]);

  it('filters to programs the model calls leftovers', () => {
    expect(filterPrograms([big, small, unjudged], 'leftovers', '', null, triage)).toEqual([small]);
  });

  it('sorts by footprint weighted by leftover probability, unjudged last', () => {
    expect(sortPrograms([unjudged, big, small], 'leftoverWeight', triage).map(item => item.name)).toEqual([
      'big',
      'small',
      'unjudged',
    ]);
  });

  it('reads a leftover option from a custom role question and ignores sets without one', () => {
    const custom = judged('x', 'game', { game: 0.7, work: 0.3 });
    expect(leftoverProbability(custom)).toBeNull();
    expect(leftoverProbability(judged('y', 'leftover', { leftover: 0.6, keep: 0.4 }))).toBe(0.6);
  });
});
