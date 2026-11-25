import { defineStore } from 'pinia';

import type {
  RunningProgramsFilter,
  RunningProgramsSnapshot,
  RunningProgramsSort,
} from '@/lib/models/running-programs/running-programs';
import { RUNNING_PROGRAMS_SCHEMA_VERSION } from '@/lib/models/running-programs/running-programs';
import { LOG_DOMAINS } from '@/lib/models/diagnostics/telemetry';
import { LoggerService } from '@/lib/services/diagnostics/logger-service';
import type {
  DecisionErrorCode,
  DecisionSettings,
  ProgramTriage,
  TriageExportFormat,
  TriageQuestionsInfo,
  TriageReport,
} from '@/lib/models/running-programs/triage';
import { FileManagerService } from '@/lib/services/filesystem/file-manager-service';
import { RunningProgramsService } from '@/lib/services/running-programs/running-programs-service';
import { TriageService } from '@/lib/services/running-programs/triage-service';
import { parseCommandError } from '@/lib/utils/diagnostics/error';
import type { ProgramOriginGroup } from '@/lib/utils/running-programs/running-programs-bucket';
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
  originGroup: ProgramOriginGroup | null;
  expandedId: string | null;
  /** `undefined` until loaded; `null` when no decision model is connected. */
  decisionSettings: DecisionSettings | null | undefined;
  triageReport: TriageReport | null;
  triaging: boolean;
  triageError: DecisionErrorCode | null;
  connectDialogOpen: boolean;
  /** Where the triage questions live and whether that file is usable. */
  questionsInfo: TriageQuestionsInfo | null;
  exporting: boolean;
  exportedPath: string | null;
  exportError: DecisionErrorCode | null;
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
    originGroup: null,
    expandedId: null,
    decisionSettings: undefined,
    triageReport: null,
    triaging: false,
    triageError: null,
    connectDialogOpen: false,
    questionsInfo: null,
    exporting: false,
    exportedPath: null,
    exportError: null,
  }),
  getters: {
    triageById(state): Map<string, ProgramTriage> {
      return new Map((state.triageReport?.results ?? []).map(result => [result.programId, result]));
    },
    visiblePrograms(state): ReturnType<typeof sortPrograms> {
      if (!state.snapshot) return [];
      const triage = this.triageById;
      return sortPrograms(
        filterPrograms(state.snapshot.programs, state.filter, state.query, state.originGroup, triage),
        state.sort,
        triage
      );
    },
    decisionModelConnected(state): boolean {
      return Boolean(state.decisionSettings?.hasApiKey && state.decisionSettings.model);
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
        // Core drops a triage once its scan is replaced: the answers judged the earlier facts.
        if (this.triageReport) {
          this.triageReport = null;
          if (this.sort === 'leftoverWeight') this.sort = 'memory';
          if (this.filter === 'leftovers') this.filter = 'all';
        }
        this.exportedPath = null;
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
    setOriginGroup(group: ProgramOriginGroup | null) {
      this.originGroup = group;
    },
    async loadDecisionSettings() {
      try {
        this.decisionSettings = await TriageService.settings();
      } catch (error) {
        this.decisionSettings = null;
        LoggerService.warn(LOG_DOMAINS.runningPrograms, 'decision_settings_unavailable', {
          code: TriageService.errorCode(error),
        });
      }
    },
    openConnectDialog() {
      this.connectDialogOpen = true;
    },
    closeConnectDialog() {
      this.connectDialogOpen = false;
    },
    decisionSettingsSaved(settings: DecisionSettings | null) {
      this.decisionSettings = settings;
      this.triageError = null;
    },
    async triage() {
      if (this.triaging || !this.snapshot) return;
      if (!this.decisionModelConnected) {
        this.openConnectDialog();
        return;
      }
      this.triaging = true;
      this.triageError = null;
      try {
        const report = await TriageService.triage(null);
        this.triageReport = report;
        this.exportedPath = null;
        if (this.sort === 'memory') this.sort = 'leftoverWeight';
      } catch (error) {
        const code = TriageService.errorCode(error) ?? 'invalidResponse';
        if (code !== 'cancelled') this.triageError = code;
        if (code === 'notConfigured' || code === 'unauthorized') this.openConnectDialog();
      } finally {
        this.triaging = false;
        void this.loadQuestions();
      }
    },
    async cancelTriage() {
      if (!this.triaging) return;
      await TriageService.cancel();
    },
    async loadQuestions() {
      try {
        this.questionsInfo = await TriageService.questions();
      } catch (error) {
        this.questionsInfo = null;
        LoggerService.warn(LOG_DOMAINS.runningPrograms, 'triage_questions_unavailable', {
          code: TriageService.errorCode(error),
        });
      }
    },
    /** Creates the question file from the built-in set if needed and shows it in the file manager. */
    async editQuestions() {
      try {
        const path = await TriageService.createQuestions();
        await FileManagerService.reveal(path);
      } catch (error) {
        useAppStore().reportError(error);
      }
      await this.loadQuestions();
    },
    async exportTriage(format: TriageExportFormat, dialogTitle: string) {
      if (this.exporting || !this.snapshot) return;
      this.exporting = true;
      this.exportError = null;
      try {
        const path = await TriageService.export(format, dialogTitle);
        if (path) this.exportedPath = path;
      } catch (error) {
        this.exportError = TriageService.errorCode(error) ?? 'exportFailed';
      } finally {
        this.exporting = false;
      }
    },
    revealExport() {
      if (this.exportedPath) void FileManagerService.reveal(this.exportedPath).catch(() => undefined);
    },
    toggleExpanded(id: string) {
      this.expandedId = this.expandedId === id ? null : id;
    },
  },
});
