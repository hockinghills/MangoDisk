// @vitest-environment happy-dom
import { mount } from '@vue/test-utils';
import { createPinia } from 'pinia';
import { describe, expect, it } from 'vitest';

import { i18n } from '@/i18n';
import type { RunningProgram } from '@/lib/models/running-programs/running-programs';

import MdRunningProgramRow from './md-running-program-row.vue';

const program: RunningProgram = {
  id: 'AddedService:unit:System:chat-bot.service:chat-bot',
  name: 'chat-bot',
  packageName: null,
  origin: {
    kind: 'addedService',
    name: 'chat-bot',
    version: null,
    installedAtMs: 1_700_000_000_000,
    dateSource: 'unitFileDate',
    sourceUrl: null,
    location: 'unit:System:chat-bot.service',
    packageManager: null,
    packageRequest: null,
    installCommand: null,
    installBurst: false,
    container: null,
    description: 'Answers questions in a chat room',
    requiredByCount: null,
    facts: [
      { kind: 'serviceRunsProgram', value: { program: 'python3', package: 'python3.12-minimal' } },
      { kind: 'serviceFile', value: { path: '/etc/systemd/system/chat-bot.service', origin: 'addedToEtc' } },
    ],
  },
  safety: 'yours',
  launches: [
    {
      kind: 'systemService',
      unit: 'chat-bot.service',
      scope: 'system',
      desktopName: null,
      backgroundSlice: false,
      terminal: null,
      multiplexer: null,
      spawnedBy: null,
      spawnedByEditor: false,
    },
  ],
  processes: [
    {
      pid: 4242,
      parentPid: 1,
      uid: 0,
      name: 'python3',
      commandLine: ['/usr/bin/python3', '/opt/chat-bot/bot.py', '--token', '***'],
      executablePath: '/usr/bin/python3.12',
      workingDirectory: '/opt/chat-bot',
      startedAtMs: 1_700_000_000_000,
      cpuPercentNow: 0.5,
      memoryKb: 40_960,
      memoryIsProportional: true,
      swapKb: 0,
      foldedFrom: null,
      inlineCode: false,
      role: null,
      roleDetail: null,
    },
  ],
  memoryKb: 40_960,
  memoryIsProportional: true,
  swapKb: 0,
  cpuPercentNow: 0.5,
  cpuPercentAverage: 0.1,
  cpuSeconds: 120,
  startedAtMs: 1_700_000_000_000,
  quietSinceStart: true,
  executableReplaced: true,
};

function row(expanded: boolean) {
  return mount(MdRunningProgramRow, {
    props: { program, expanded, triage: null },
    global: { plugins: [createPinia(), i18n], stubs: { MdIcon: true } },
  });
}

describe('running program row', () => {
  it('summarizes origin, launch and class when collapsed', () => {
    const wrapper = row(false);
    const text = wrapper.text();
    expect(text).toContain('chat-bot');
    expect(text).toContain(i18n.global.t('runningPrograms.originKinds.addedService'));
    expect(text).toContain(i18n.global.t('runningPrograms.launch.systemService', { unit: 'chat-bot.service' }));
    expect(text).toContain(i18n.global.t('runningPrograms.safety.yours'));
    expect(wrapper.find('.program-detail').exists()).toBe(false);
  });

  it('shows typed facts, notes and the redacted process list when expanded', async () => {
    const wrapper = row(true);
    const detail = wrapper.get('.program-detail').text();
    expect(detail).toContain(
      i18n.global.t('runningPrograms.facts.serviceRunsPackagedProgram', {
        program: 'python3',
        package: 'python3.12-minimal',
      })
    );
    expect(detail).toContain('/etc/systemd/system/chat-bot.service');
    expect(detail).toContain(i18n.global.t('runningPrograms.detail.executableReplaced'));
    expect(detail).toContain(i18n.global.t('runningPrograms.detail.quietSinceStart'));
    expect(wrapper.get('.command-line').text()).toContain('--token ***');
    await wrapper.get('.program-main').trigger('click');
    expect(wrapper.emitted('toggleExpanded')).toHaveLength(1);
  });
});
