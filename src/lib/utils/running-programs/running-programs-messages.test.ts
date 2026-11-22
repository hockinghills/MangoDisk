import { describe, expect, it } from 'vitest';

import type { ProgramLaunch } from '@/lib/models/running-programs/running-programs';

import { factMessage, launchMessage } from './running-programs-messages';

function launch(overrides: Partial<ProgramLaunch>): ProgramLaunch {
  return {
    kind: 'unknown',
    unit: null,
    scope: null,
    desktopName: null,
    backgroundSlice: false,
    terminal: null,
    multiplexer: null,
    spawnedBy: null,
    spawnedByEditor: false,
    ...overrides,
  };
}

describe('running-programs messages', () => {
  it('describes launches from their typed evidence', () => {
    expect(launchMessage(launch({ kind: 'autostart', desktopName: 'org.kde.kdeconnect.daemon' }))).toEqual({
      key: 'launch.autostart',
      params: { name: 'org.kde.kdeconnect.daemon' },
    });
    expect(launchMessage(launch({ kind: 'userService', unit: 'syncthing.service', backgroundSlice: true })).key).toBe(
      'launch.backgroundUserService'
    );
    expect(launchMessage(launch({ kind: 'terminal', terminal: 'konsole', multiplexer: 'tmux' })).key).toBe(
      'launch.terminalWithMultiplexer'
    );
    expect(launchMessage(launch({ kind: 'child', spawnedBy: 'code', spawnedByEditor: true }))).toEqual({
      key: 'launch.childOfEditor',
      params: { parent: 'code' },
    });
    expect(launchMessage(launch({ kind: 'cron' })).key).toBe('launch.cron');
  });

  it('describes origin facts', () => {
    expect(
      factMessage({ kind: 'serviceRunsProgram', value: { program: 'python3', package: 'python3.12-minimal' } })
    ).toEqual({
      key: 'facts.serviceRunsPackagedProgram',
      params: { program: 'python3', package: 'python3.12-minimal' },
    });
    expect(
      factMessage({ kind: 'serviceFile', value: { path: '/etc/systemd/system/x.service', origin: 'addedToEtc' } }).key
    ).toBe('facts.serviceFile.addedToEtc');
    expect(factMessage({ kind: 'runsDependency', value: 'next' }).params).toEqual({ value: 'next' });
    expect(factMessage({ kind: 'noPermission' }).key).toBe('facts.noPermission');
  });
});
