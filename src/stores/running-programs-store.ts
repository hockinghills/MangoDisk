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

/** Why the last administrator-rights scan did not run, rendered as a page notice. */
export type RunningProgramsElevationProblem = 'denied' | 'unavailable';

interface RunningProgramsState {
  snapshot: RunningProgramsSnapshot | null;
  /** Rescans repeat the last choice so an elevated view stays elevated. */
  useAdministratorRights: boolean;
  elevationProblem: RunningProgramsElevationProblem | null;
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
    useAdministratorRights: false,
    elevationProblem: null,
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
    async scan(useAdministratorRights?: boolean) {
      if (this.scanning) return;
      const appStore = useAppStore();
      const elevate = useAdministratorRights ?? this.useAdministratorRights;
      this.scanning = true;
      this.cancelling = false;
      this.elevationProblem = null;
      appStore.clearError();
      try {
        const snapshot = await RunningProgramsService.scan(elevate);
        // Without a way to ask for rights, later rescans should not keep trying.
        this.useAdministratorRights = elevate && !snapshot.administratorRightsUnavailable;
        if (snapshot.administratorRightsUnavailable) this.elevationProblem = 'unavailable';
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
        const code = parseCommandError(error)?.code;
        if (elevate && code === 'permissionDenied') this.elevationProblem = 'denied';
        else if (code !== 'operationCancelled') appStore.reportError(error);
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
