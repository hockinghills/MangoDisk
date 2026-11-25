<script setup lang="ts">
import { computed, onMounted } from 'vue';
import { useI18n } from 'vue-i18n';

import MdCategoryFilter from '@/components/custom/md-category-filter.vue';
import MdEmptyState from '@/components/custom/md-empty-state.vue';
import MdOperationProgress from '@/components/custom/md-operation-progress.vue';
import MdOperationWorkspace from '@/components/custom/md-operation-workspace.vue';
import MdPageShell from '@/components/custom/md-page-shell.vue';
import MdResultFilterToolbar from '@/components/custom/md-result-filter-toolbar.vue';
import MdResultSearch from '@/components/custom/md-result-search.vue';
import MdResultSummary from '@/components/custom/md-result-summary.vue';
import MdResultTable from '@/components/custom/md-result-table.vue';
import MdResultWorkspace from '@/components/custom/md-result-workspace.vue';
import MdIcon from '@/components/icons/md-icon.vue';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { ICON_NAMES } from '@/lib/models/presentation/ui';
import type { RunningProgramsFilter, RunningProgramsSort } from '@/lib/models/running-programs/running-programs';
import { FormatService } from '@/lib/services/presentation/format-service';
import { ByteSizeService } from '@/lib/services/settings/byte-size-service';
import { filterPrograms } from '@/lib/utils/running-programs/running-programs-view';
import { useRunningProgramsStore } from '@/stores/running-programs-store';

import MdDecisionModelDialog from './components/md-decision-model-dialog.vue';
import MdRunningProgramRow from './components/md-running-program-row.vue';
import MdRunningProgramsBucket from './components/md-running-programs-bucket.vue';

const { t, locale } = useI18n({ useScope: 'global' });
const store = useRunningProgramsStore();

const BASE_FILTERS: readonly RunningProgramsFilter[] = ['all', 'sideInstalled', 'yours', 'quiet'];
const BASE_SORTS: readonly RunningProgramsSort[] = ['memory', 'cpuNow', 'cpuAverage', 'installed', 'name'];
const FILTERS = computed<readonly RunningProgramsFilter[]>(() =>
  store.triageReport ? [...BASE_FILTERS, 'leftovers'] : BASE_FILTERS
);
const SORTS = computed<readonly RunningProgramsSort[]>(() =>
  store.triageReport ? ['leftoverWeight', ...BASE_SORTS] : BASE_SORTS
);

onMounted(() => {
  if (store.decisionSettings === undefined) void store.loadDecisionSettings();
});

const triageSummary = computed(() => {
  const report = store.triageReport;
  if (!report) return '';
  const parts = [t('runningPrograms.triage.judged', { count: report.results.length, model: report.model })];
  if (report.costUsd !== null) {
    parts.push(
      t('runningPrograms.triage.cost', {
        cost: report.costUsd < 0.01 ? report.costUsd.toFixed(4) : report.costUsd.toFixed(2),
      })
    );
  }
  if (report.failures.length) parts.push(t('runningPrograms.triage.failedCount', { count: report.failures.length }));
  return parts.join(' · ');
});

const snapshot = computed(() => store.snapshot);
const filterOptions = computed(() => {
  const programs = snapshot.value?.programs ?? [];
  return FILTERS.value.map(filter => ({
    value: filter,
    label: t(`runningPrograms.filters.${filter}`),
    count: filterPrograms(programs, filter, '', null, store.triageById).length,
  }));
});

function kb(value: number): string {
  return ByteSizeService.memory(value * 1024);
}

const memoryLine = computed(() => {
  const memory = snapshot.value?.memory;
  if (!memory) return '';
  const used = Math.max(memory.totalKb - memory.availableKb, 0);
  const parts = [t('runningPrograms.summary.ramUsed', { used: kb(used), total: kb(memory.totalKb) })];
  if (memory.swapTotalKb) {
    parts.push(t('runningPrograms.summary.swapUsed', { used: kb(memory.swapUsedKb), total: kb(memory.swapTotalKb) }));
  }
  if (memory.compressedSwapUsedKb && memory.compressedSwapRamKb !== null) {
    parts.push(
      t('runningPrograms.summary.compressedSwap', {
        stored: kb(memory.compressedSwapUsedKb),
        ram: kb(memory.compressedSwapRamKb),
      })
    );
  }
  return parts.join(' · ');
});

function updateFilter(value: string) {
  if ((FILTERS.value as readonly string[]).includes(value)) store.setFilter(value as RunningProgramsFilter);
}

function updateSort(value: unknown) {
  if (typeof value === 'string' && (SORTS.value as readonly string[]).includes(value)) {
    store.setSort(value as RunningProgramsSort);
  }
}
</script>

<template>
  <MdPageShell content-mode="workspace" :title="t('runningPrograms.title')">
    <template v-if="snapshot && !store.scanning" #actions>
      <Button variant="outline" type="button" :disabled="store.triaging" @click="store.triage()">
        <MdIcon :name="ICON_NAMES.sparkles" :size="16" />
        {{ store.triageReport ? t('runningPrograms.triage.rerun') : t('runningPrograms.triage.run') }}
      </Button>
      <Button v-if="!snapshot.elevated" variant="outline" type="button" @click="store.scan(true)">
        <MdIcon :name="ICON_NAMES.shield" :size="16" />
        {{ t('runningPrograms.rescanElevated') }}
      </Button>
      <Button variant="outline" type="button" @click="store.scan()">
        <MdIcon :name="ICON_NAMES.refresh" :size="16" />
        {{ t('runningPrograms.rescan') }}
      </Button>
    </template>

    <MdOperationWorkspace v-if="store.scanning">
      <MdOperationProgress
        :icon-name="ICON_NAMES.process"
        :title="store.cancelling ? t('runningPrograms.cancelling') : t('runningPrograms.scanning')"
        :progress="null"
        :path-label="t('runningPrograms.scanning')"
        :preparing-text="t('runningPrograms.scanningDescription')"
        :hint="t('runningPrograms.scanningDescription')"
        :show-traversal-details="false"
        :show-step-progress="false"
        :cancelable="true"
        :cancel-disabled="store.cancelling"
        @cancel="store.cancelScan()"
      />
    </MdOperationWorkspace>

    <MdResultWorkspace v-else>
      <template v-if="snapshot" #summary>
        <MdResultSummary
          :title="
            t('runningPrograms.summary.programs', {
              programs: FormatService.integer(snapshot.summary.programCount),
              processes: FormatService.integer(snapshot.summary.processCount),
            })
          "
          :metric-label="t('runningPrograms.summary.sideInstalled')"
          :metric-value="FormatService.integer(snapshot.summary.sideInstalledCount)"
        >
          <template #status>
            <span class="summary-memory">{{ memoryLine }}</span>
          </template>
          <template #actions>
            <span class="summary-captured">
              {{
                t('runningPrograms.summary.captured', { date: FormatService.dateTime(snapshot.capturedAtMs, locale) })
              }}
            </span>
          </template>
        </MdResultSummary>
        <p class="summary-note">
          {{ snapshot.elevated ? t('runningPrograms.summary.elevated') : t('runningPrograms.summary.notElevated') }}
        </p>
        <div v-if="store.triaging || store.triageReport || store.triageError" class="triage-status" role="status">
          <template v-if="store.triaging">
            <span>{{ t('runningPrograms.triage.running', { model: store.decisionSettings?.model ?? '' }) }}</span>
            <Button size="sm" variant="ghost" type="button" @click="store.cancelTriage()">
              {{ t('runningPrograms.triage.cancel') }}
            </Button>
          </template>
          <span v-else-if="store.triageError" class="triage-error">
            {{ t(`runningPrograms.triage.errors.${store.triageError}`) }}
          </span>
          <template v-else>
            <span>{{ triageSummary }}</span>
            <Button size="sm" variant="ghost" type="button" @click="store.openConnectDialog()">
              {{ t('runningPrograms.triage.changeModel') }}
            </Button>
          </template>
        </div>
        <p v-if="store.triageReport && !store.triaging" class="summary-note">
          {{ t('runningPrograms.triage.advisory') }}
        </p>
        <MdRunningProgramsBucket
          :programs="snapshot.programs"
          :selected-group="store.originGroup"
          @select-group="store.setOriginGroup"
        />
      </template>

      <template v-if="snapshot" #header>
        <MdResultFilterToolbar>
          <MdCategoryFilter
            :model-value="store.filter"
            :options="filterOptions"
            :accessibility-label="t('runningPrograms.filterLabel')"
            @update:model-value="updateFilter"
          />
          <template #aside>
            <Select :key="locale" :model-value="store.sort" @update:model-value="updateSort">
              <SelectTrigger class="h-9" :aria-label="t('runningPrograms.sortLabel')">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem v-for="sort in SORTS" :key="sort" :value="sort">
                  {{ t(`runningPrograms.sorts.${sort}`) }}
                </SelectItem>
              </SelectContent>
            </Select>
            <MdResultSearch
              :model-value="store.query"
              :placeholder="t('runningPrograms.searchPlaceholder')"
              @update:model-value="store.setQuery"
            />
          </template>
        </MdResultFilterToolbar>
      </template>

      <p v-if="store.elevationProblem" class="elevation-problem" role="status">
        {{ t(`runningPrograms.elevation.${store.elevationProblem}`) }}
      </p>

      <MdEmptyState
        v-if="!snapshot"
        :icon-name="ICON_NAMES.process"
        :title="t('runningPrograms.emptyTitle')"
        :description="t('runningPrograms.emptyDescription')"
      >
        <div class="empty-actions">
          <Button size="lg" type="button" @click="store.scan(false)">
            <MdIcon :name="ICON_NAMES.scan" :size="17" />
            {{ t('runningPrograms.scan') }}
          </Button>
          <Button size="lg" variant="outline" type="button" @click="store.scan(true)">
            <MdIcon :name="ICON_NAMES.shield" :size="17" />
            {{ t('runningPrograms.scanElevated') }}
          </Button>
        </div>
        <p class="summary-note">{{ t('runningPrograms.elevation.explanation') }}</p>
      </MdEmptyState>

      <MdEmptyState
        v-else-if="!store.visiblePrograms.length"
        compact
        :icon-name="ICON_NAMES.search"
        :title="t('runningPrograms.noMatchesTitle')"
        :description="t('runningPrograms.noMatchesDescription')"
      />

      <MdResultTable v-else>
        <div class="program-columns" aria-hidden="true">
          <span />
          <span>{{ t('runningPrograms.columns.program') }}</span>
          <span>{{ t('runningPrograms.columns.startedBy') }}</span>
          <span class="numeric">{{ t('runningPrograms.columns.memory') }}</span>
          <span class="numeric">{{ t('runningPrograms.columns.swap') }}</span>
          <span class="numeric">{{ t('runningPrograms.columns.cpuNow') }}</span>
          <span class="numeric">{{ t('runningPrograms.columns.cpuAverage') }}</span>
          <span class="numeric">{{ t('runningPrograms.columns.class') }}</span>
        </div>
        <MdRunningProgramRow
          v-for="program in store.visiblePrograms"
          :key="program.id"
          :program="program"
          :expanded="store.expandedId === program.id"
          :triage="store.triageById.get(program.id) ?? null"
          @toggle-expanded="store.toggleExpanded(program.id)"
        />
      </MdResultTable>
    </MdResultWorkspace>
    <MdDecisionModelDialog
      :open="store.connectDialogOpen"
      :settings="store.decisionSettings"
      @update:open="open => (open ? store.openConnectDialog() : store.closeConnectDialog())"
      @saved="store.decisionSettingsSaved"
    />
  </MdPageShell>
</template>

<style scoped>
@reference "@assets/main.css";

.summary-memory,
.summary-captured,
.summary-note {
  @apply text-sm text-muted-foreground;
}

.summary-note {
  padding: 0 16px 8px;
}

.empty-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 10px;
}

.triage-status {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 16px 4px;
  @apply text-sm;
}

.triage-error {
  @apply text-destructive-text;
}

.elevation-problem {
  margin: 8px 16px 0;
  @apply text-sm text-destructive-text;
}

/* Matches the row grid in md-running-program-row.vue. */
.program-columns {
  display: grid;
  grid-template-columns: 16px minmax(10rem, 1.4fr) minmax(8rem, 1.6fr) repeat(4, 5.5rem) 12rem;
  gap: 10px;
  padding: 4px var(--result-table-content-inline-padding, 14px);
  @apply text-xs font-medium text-muted-foreground;
}

.program-columns .numeric {
  text-align: end;
}
</style>
