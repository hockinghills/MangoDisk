<script setup lang="ts">
import { computed } from 'vue';
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

import MdRunningProgramRow from './components/md-running-program-row.vue';

const { t, locale } = useI18n({ useScope: 'global' });
const store = useRunningProgramsStore();

const FILTERS: readonly RunningProgramsFilter[] = ['all', 'sideInstalled', 'yours', 'quiet'];
const SORTS: readonly RunningProgramsSort[] = ['memory', 'cpuNow', 'cpuAverage', 'installed', 'name'];

const snapshot = computed(() => store.snapshot);
const filterOptions = computed(() => {
  const programs = snapshot.value?.programs ?? [];
  return FILTERS.map(filter => ({
    value: filter,
    label: t(`runningPrograms.filters.${filter}`),
    count: filterPrograms(programs, filter, '').length,
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
  if ((FILTERS as readonly string[]).includes(value)) store.setFilter(value as RunningProgramsFilter);
}

function updateSort(value: unknown) {
  if (typeof value === 'string' && (SORTS as readonly string[]).includes(value)) {
    store.setSort(value as RunningProgramsSort);
  }
}
</script>

<template>
  <MdPageShell content-mode="workspace" :title="t('runningPrograms.title')">
    <template v-if="snapshot && !store.scanning" #actions>
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
        <p v-if="!snapshot.elevated" class="summary-note">{{ t('runningPrograms.summary.notElevated') }}</p>
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

      <MdEmptyState
        v-if="!snapshot"
        :icon-name="ICON_NAMES.process"
        :title="t('runningPrograms.emptyTitle')"
        :description="t('runningPrograms.emptyDescription')"
      >
        <Button size="lg" type="button" @click="store.scan()">
          <MdIcon :name="ICON_NAMES.scan" :size="17" />
          {{ t('runningPrograms.scan') }}
        </Button>
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
          @toggle-expanded="store.toggleExpanded(program.id)"
        />
      </MdResultTable>
    </MdResultWorkspace>
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

/* Matches the row grid in md-running-program-row.vue. */
.program-columns {
  display: grid;
  grid-template-columns: 16px minmax(10rem, 1.4fr) minmax(8rem, 1.6fr) repeat(4, 5.5rem) 6.5rem;
  gap: 10px;
  padding: 4px var(--result-table-content-inline-padding, 14px);
  @apply text-xs font-medium text-muted-foreground;
}

.program-columns .numeric {
  text-align: end;
}
</style>
