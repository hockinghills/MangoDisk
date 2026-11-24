import { createPinia, setActivePinia } from 'pinia';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { RunningProgramsSnapshot } from '@/lib/models/running-programs/running-programs';
import { RunningProgramsService } from '@/lib/services/running-programs/running-programs-service';

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
});
