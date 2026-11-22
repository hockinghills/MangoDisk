import type {
  ProgramOriginKind,
  RunningProgram,
  RunningProgramsFilter,
  RunningProgramsSort,
} from '@/lib/models/running-programs/running-programs';

/** Added by hand or by a side installer rather than the distro. Mirrors Core. */
export function isSideInstall(kind: ProgramOriginKind): boolean {
  return kind !== 'systemPackage' && kind !== 'unknown';
}

/** Memory and swap together: what the program holds, wherever the kernel keeps it. */
export function programFootprintKb(program: RunningProgram): number {
  return program.memoryKb + program.swapKb;
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

function matchesFilter(program: RunningProgram, filter: RunningProgramsFilter): boolean {
  switch (filter) {
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
  query: string
): RunningProgram[] {
  return programs.filter(program => matchesFilter(program, filter) && matchesQuery(program, query));
}

export function sortPrograms(programs: readonly RunningProgram[], sort: RunningProgramsSort): RunningProgram[] {
  const byName = (left: RunningProgram, right: RunningProgram) => left.name.localeCompare(right.name);
  const descending = (value: (program: RunningProgram) => number) => (left: RunningProgram, right: RunningProgram) =>
    value(right) - value(left) || byName(left, right);
  const compare = {
    memory: descending(programFootprintKb),
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
