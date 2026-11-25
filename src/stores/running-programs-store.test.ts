import { createPinia, setActivePinia } from 'pinia';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { RunningProgramsSnapshot } from '@/lib/models/running-programs/running-programs';
import { RunningProgramsService } from '@/lib/services/running-programs/running-programs-service';
import { TriageService } from '@/lib/services/running-programs/triage-service';

import { useRunningProgramsStore } from './running-programs-store';

function snapshot(overrides: Partial<RunningProgramsSnapshot> = {}): RunningProgramsSnapshot {
  return {
    schemaVersion: 1,
    capturedAtMs: 0,
    elapsedMs: 0,
    elevated: false,
    administratorRightsUnavailable: false,
    memory: {
      totalKb: 0,
      availableKb: 0,
      swapTotalKb: 0,
      swapUsedKb: 0,
      compressedSwapUsedKb: null,
      compressedSwapRamKb: null,
    },
    programs: [],
    summary: { processCount: 0, programCount: 0, sideInstalledCount: 0, memoryKb: 0, swapKb: 0 },
    ...overrides,
  };
}

describe('running programs store', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.restoreAllMocks();
  });

  it('repeats an administrator-rights scan on rescan', async () => {
    const scan = vi.spyOn(RunningProgramsService, 'scan').mockResolvedValue(snapshot({ elevated: true }));
    const store = useRunningProgramsStore();
    await store.scan(true);
    await store.scan();
    expect(scan.mock.calls).toEqual([[true], [true]]);
    await store.scan(false);
    await store.scan();
    expect(scan.mock.calls.slice(2)).toEqual([[false], [false]]);
  });

  it('reports a failed authorization without replacing the previous result', async () => {
    const store = useRunningProgramsStore();
    vi.spyOn(RunningProgramsService, 'scan').mockResolvedValueOnce(snapshot());
    await store.scan(false);
    const previous = store.snapshot;
    vi.spyOn(RunningProgramsService, 'scan').mockRejectedValueOnce({
      code: 'permissionDenied',
      details: {},
      retryable: false,
    });
    await store.scan(true);
    expect(store.elevationProblem).toBe('denied');
    expect(store.snapshot).toBe(previous);
  });

  it('stops asking for rights when the system cannot grant them', async () => {
    const scan = vi
      .spyOn(RunningProgramsService, 'scan')
      .mockResolvedValue(snapshot({ administratorRightsUnavailable: true }));
    const store = useRunningProgramsStore();
    await store.scan(true);
    expect(store.elevationProblem).toBe('unavailable');
    await store.scan();
    expect(scan.mock.calls).toEqual([[true], [false]]);
  });

  it('asks to connect a model before triage, then reports typed failures', async () => {
    const store = useRunningProgramsStore();
    vi.spyOn(RunningProgramsService, 'scan').mockResolvedValue(snapshot());
    await store.scan(false);
    const triage = vi.spyOn(TriageService, 'triage');
    store.decisionSettings = null;
    await store.triage();
    expect(store.connectDialogOpen).toBe(true);
    expect(triage).not.toHaveBeenCalled();

    store.decisionSettingsSaved({ endpoint: 'https://openrouter.ai/api', model: 'vendor/decider', hasApiKey: true });
    store.closeConnectDialog();
    triage.mockRejectedValueOnce('insufficientCredits');
    await store.triage();
    expect(store.triageError).toBe('insufficientCredits');
    expect(store.connectDialogOpen).toBe(false);

    triage.mockResolvedValueOnce({
      model: 'vendor/decider-1',
      questions: { schemaVersion: 1, questions: [] },
      questionSource: 'builtIn',
      results: [],
      failures: [],
      inputTokens: 0,
      costUsd: 0,
      elapsedMs: 1,
    });
    await store.triage();
    expect(store.triageError).toBeNull();
    expect(store.sort).toBe('leftoverWeight');

    // A new scan replaces the facts the answers judged, so the triage and its sort go with it.
    await store.scan(false);
    expect(store.triageReport).toBeNull();
    expect(store.sort).toBe('memory');
  });

  it('exports through the native picker and reports typed failures', async () => {
    const store = useRunningProgramsStore();
    vi.spyOn(RunningProgramsService, 'scan').mockResolvedValue(snapshot());
    await store.scan(false);
    const exportTriage = vi.spyOn(TriageService, 'export').mockResolvedValueOnce(null);
    await store.exportTriage('markdown', 'Save');
    expect(exportTriage).toHaveBeenCalledWith('markdown', 'Save');
    expect(store.exportedPath).toBeNull();

    exportTriage.mockResolvedValueOnce('/tmp/triage.md');
    await store.exportTriage('markdown', 'Save');
    expect(store.exportedPath).toBe('/tmp/triage.md');

    exportTriage.mockRejectedValueOnce('invalidExportPath');
    await store.exportTriage('json', 'Save');
    expect(store.exportError).toBe('invalidExportPath');
  });
});
