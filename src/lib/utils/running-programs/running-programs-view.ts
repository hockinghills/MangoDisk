import type {
  ProgramOriginKind,
  RunningProgram,
  RunningProgramsFilter,
  RunningProgramsSort,
} from '@/lib/models/running-programs/running-programs';
import type { ProgramTriage } from '@/lib/models/running-programs/triage';

import { originGroup, type ProgramOriginGroup, programFootprintKb } from './running-programs-bucket';

/** Added by hand or by a side installer rather than the distro. Mirrors Core. */
export function isSideInstall(kind: ProgramOriginKind): boolean {
  return kind !== 'systemPackage' && kind !== 'unknown';
}

/** Judged by a decision model, keyed by program id. */
export type TriageLookup = ReadonlyMap<string, ProgramTriage>;

/** The footprint a model thinks is leftover: what removing the leftovers would give back. */
export function leftoverWeightKb(program: RunningProgram, triage: TriageLookup): number | null {
  const result = triage.get(program.id);
  return result ? programFootprintKb(program) * (result.roleProbabilities.leftover ?? 0) : null;
}

function matchesQuery(program: RunningProgram, query: string): boolean {
  const needle = query.trim().toLocaleLowerCase();
  if (!needle) return true;
  const haystack = [
    program.name,
    program.packageName ?? '',
    program.origin.name,
    program.origin.location ?? '',
    program.origin.sourceUrl ?? '',
    ...program.launches.map(launch => launch.unit ?? launch.desktopName ?? ''),
    ...program.processes.flatMap(process => [process.name, process.commandLine.join(' ')]),
  ];
  return haystack.some(value => value.toLocaleLowerCase().includes(needle));
}

function matchesFilter(program: RunningProgram, filter: RunningProgramsFilter, triage: TriageLookup): boolean {
  switch (filter) {
    case 'leftovers':
      return triage.get(program.id)?.role === 'leftover';
    case 'sideInstalled':
      return isSideInstall(program.origin.kind);
    case 'yours':
      return program.safety === 'yours';
    case 'quiet':
      return program.quietSinceStart;
    case 'all':
      return true;
  }
}

export function filterPrograms(
  programs: readonly RunningProgram[],
  filter: RunningProgramsFilter,
  query: string,
  group: ProgramOriginGroup | null = null,
  triage: TriageLookup = new Map()
): RunningProgram[] {
  return programs.filter(
    program =>
      matchesFilter(program, filter, triage) &&
      matchesQuery(program, query) &&
      (group === null || originGroup(program.origin.kind) === group)
  );
}

export function sortPrograms(
  programs: readonly RunningProgram[],
  sort: RunningProgramsSort,
  triage: TriageLookup = new Map()
): RunningProgram[] {
  const byName = (left: RunningProgram, right: RunningProgram) => left.name.localeCompare(right.name);
  const descending = (value: (program: RunningProgram) => number) => (left: RunningProgram, right: RunningProgram) =>
    value(right) - value(left) || byName(left, right);
  const compare = {
    memory: descending(programFootprintKb),
    // Programs the model has not judged go last.
    leftoverWeight: descending(program => leftoverWeightKb(program, triage) ?? -1),
    cpuNow: descending(program => program.cpuPercentNow),
    cpuAverage: descending(program => program.cpuPercentAverage),
    // Newest installs first; programs without a known date go last.
    installed: descending(program => program.origin.installedAtMs ?? Number.NEGATIVE_INFINITY),
    name: byName,
  }[sort];
  return [...programs].sort(compare);
}

/** Percent of one core, shown with one decimal below ten and none above. */
export function cpuPercentText(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return '0%';
  return value < 10 ? `${value.toFixed(1)}%` : `${Math.round(value)}%`;
}
