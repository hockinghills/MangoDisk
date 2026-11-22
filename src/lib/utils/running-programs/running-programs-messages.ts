import type { ProgramLaunch, ProgramOrigin, ProgramOriginFact } from '@/lib/models/running-programs/running-programs';

/** A locale key under `runningPrograms.` and its interpolation values. */
export interface ProgramMessage {
  key: string;
  params: Record<string, string | number>;
}

function message(key: string, params: Record<string, string | number> = {}): ProgramMessage {
  return { key, params };
}

/** What started a process, from the launch evidence Core reports. */
export function launchMessage(launch: ProgramLaunch): ProgramMessage {
  const unit = launch.unit ?? '';
  const name = launch.desktopName ?? unit;
  let base: ProgramMessage;
  switch (launch.kind) {
    case 'autostart':
      base = message('launch.autostart', { name });
      break;
    case 'appLaunched':
      base = launch.desktopName ? message('launch.appLaunchedFrom', { name }) : message('launch.appLaunched');
      break;
    case 'onDemand':
      base = message('launch.onDemand', { name });
      break;
    case 'session':
      base = unit ? message('launch.sessionUnit', { unit }) : message('launch.session');
      break;
    case 'userService':
      base = message(launch.backgroundSlice ? 'launch.backgroundUserService' : 'launch.userService', { unit });
      break;
    case 'systemService':
      base = message('launch.systemService', { unit });
      break;
    case 'terminal':
      if (launch.terminal && launch.multiplexer) {
        base = message('launch.terminalWithMultiplexer', {
          terminal: launch.terminal,
          multiplexer: launch.multiplexer,
        });
      } else if (launch.terminal) {
        base = message('launch.terminal', { terminal: launch.terminal });
      } else if (launch.multiplexer) {
        base = message('launch.multiplexer', { multiplexer: launch.multiplexer });
      } else {
        base = message('launch.terminalUnknown');
      }
      break;
    case 'child':
      base = message(launch.spawnedByEditor ? 'launch.childOfEditor' : 'launch.child', {
        parent: launch.spawnedBy ?? '',
      });
      break;
    default:
      base = message(`launch.${launch.kind}`);
  }
  return base;
}

/** How the install date was worked out, or null when there is no date. */
export function installedDateSourceKey(origin: ProgramOrigin): string | null {
  return origin.installedAtMs === null || origin.dateSource === null ? null : `dateSources.${origin.dateSource}`;
}

/** A typed origin fact as a sentence. Dates are passed through as epoch milliseconds. */
export function factMessage(fact: ProgramOriginFact): ProgramMessage {
  switch (fact.kind) {
    case 'serviceRunsProgram':
      return fact.value.package
        ? message('facts.serviceRunsPackagedProgram', { program: fact.value.program, package: fact.value.package })
        : message('facts.serviceRunsProgram', { program: fact.value.program });
    case 'serviceFile':
      return message(`facts.serviceFile.${fact.value.origin}`, { path: fact.value.path });
    case 'lastGitActivity':
    case 'updatedInPlace':
      return message(`facts.${fact.kind}`, { date: fact.value });
    case 'installedUnderNvm':
    case 'installedBy':
    case 'editableInstall':
    case 'runAsModule':
    case 'virtualenvOfGitClone':
    case 'runsDependency':
    case 'launchedThroughRunner':
    case 'runsScript':
    case 'containerRunsCommand':
      return message(`facts.${fact.kind}`, { value: fact.value });
    default:
      return message(`facts.${fact.kind}`);
  }
}
