import { defineStore } from 'pinia';

import type {
  RunningProgramsFilter,
  RunningProgramsSnapshot,
  RunningProgramsSort,
} from '@/lib/models/running-programs/running-programs';
import { RUNNING_PROGRAMS_SCHEMA_VERSION } from '@/lib/models/running-programs/running-programs';
import { LOG_DOMAINS } from '@/lib/models/diagnostics/telemetry';
import { LoggerService } from '@/lib/services/diagnostics/logger-service';
import { RunningProgramsService } from '@/lib/services/running-programs/running-programs-service';
import { parseCommandError } from '@/lib/utils/diagnostics/error';
import { filterPrograms, sortPrograms } from '@/lib/utils/running-programs/running-programs-view';

import { useAppStore } from './app-store';

interface RunningProgramsState {
  snapshot: RunningProgramsSnapshot | null;
  scanning: boolean;
  cancelling: boolean;
  filter: RunningProgramsFilter;
  sort: RunningProgramsSort;
  query: string;
  expandedId: string | null;
}

export const useRunningProgramsStore = defineStore('running-programs', {
  state: (): RunningProgramsState => ({
    snapshot: null,
    scanning: false,
    cancelling: false,
    filter: 'all',
    sort: 'memory',
    query: '',
    expandedId: null,
  }),
  getters: {
    visiblePrograms(state) {
      if (!state.snapshot) return [];
      return sortPrograms(filterPrograms(state.snapshot.programs, state.filter, state.query), state.sort);
    },
  },
  actions: {
    async scan() {
      if (this.scanning) return;
      const appStore = useAppStore();
      this.scanning = true;
      this.cancelling = false;
      appStore.clearError();
      try {
        const snapshot = await RunningProgramsService.scan();
        if (snapshot.schemaVersion !== RUNNING_PROGRAMS_SCHEMA_VERSION) {
          LoggerService.warn(LOG_DOMAINS.runningPrograms, 'schema_mismatch', {
            expected: RUNNING_PROGRAMS_SCHEMA_VERSION,
            received: snapshot.schemaVersion,
          });
        }
        this.snapshot = snapshot;
        if (this.expandedId && !snapshot.programs.some(program => program.id === this.expandedId)) {
          this.expandedId = null;
        }
      } catch (error) {
        if (parseCommandError(error)?.code !== 'operationCancelled') appStore.reportError(error);
      } finally {
        this.scanning = false;
        this.cancelling = false;
      }
    },
    async cancelScan() {
      if (!this.scanning || this.cancelling) return;
      this.cancelling = true;
      try {
        await RunningProgramsService.cancelScan();
      } catch (error) {
        useAppStore().reportError(error);
        this.cancelling = false;
      }
    },
    setFilter(filter: RunningProgramsFilter) {
      this.filter = filter;
    },
    setSort(sort: RunningProgramsSort) {
      this.sort = sort;
    },
    setQuery(query: string) {
      this.query = query;
    },
    toggleExpanded(id: string) {
      this.expandedId = this.expandedId === id ? null : id;
    },
  },
});
