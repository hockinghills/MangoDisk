<script setup lang="ts">
import { computed } from 'vue';
import { useI18n } from 'vue-i18n';

import type { RunningProgram } from '@/lib/models/running-programs/running-programs';
import { ByteSizeService } from '@/lib/services/settings/byte-size-service';
import {
  type ProgramOriginGroup,
  SMALL_PROGRAM_KB,
  weighBucket,
} from '@/lib/utils/running-programs/running-programs-bucket';
import { cpuPercentText } from '@/lib/utils/running-programs/running-programs-view';

const props = defineProps<{
  programs: readonly RunningProgram[];
  selectedGroup: ProgramOriginGroup | null;
}>();

const emit = defineEmits<{
  selectGroup: [group: ProgramOriginGroup | null];
}>();

const { t } = useI18n({ useScope: 'global' });

const bucket = computed(() => weighBucket(props.programs));

function kb(value: number): string {
  return ByteSizeService.memory(value * 1024);
}

function toggle(group: ProgramOriginGroup) {
  emit('selectGroup', props.selectedGroup === group ? null : group);
}
</script>

<template>
  <section v-if="bucket.count" class="bucket" :aria-label="t('runningPrograms.bucket.title')">
    <p class="bucket-headline">
      <strong>{{ t('runningPrograms.bucket.title') }}</strong>
      {{
        t('runningPrograms.bucket.headline', {
          count: bucket.count,
          footprint: kb(bucket.footprintKb),
          cpu: cpuPercentText(bucket.cpuPercentAverage),
        })
      }}
    </p>
    <p v-if="bucket.smallCount > 1" class="bucket-small">
      {{
        t('runningPrograms.bucket.small', {
          count: bucket.smallCount,
          threshold: kb(SMALL_PROGRAM_KB),
          footprint: kb(bucket.smallFootprintKb),
        })
      }}
    </p>
    <div class="bucket-groups" role="group" :aria-label="t('runningPrograms.bucket.groupsLabel')">
      <button
        v-for="group in bucket.groups"
        :key="group.group"
        type="button"
        class="bucket-group"
        :data-selected="selectedGroup === group.group"
        :aria-pressed="selectedGroup === group.group"
        @click="toggle(group.group)"
      >
        <span>{{ t(`runningPrograms.originGroups.${group.group}`) }}</span>
        <span class="bucket-group-weight">{{ kb(group.footprintKb) }} · {{ group.count }}</span>
      </button>
    </div>
  </section>
</template>

<style scoped>
@reference "@assets/main.css";

.bucket {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 4px 16px 10px;
}

.bucket-headline {
  @apply text-sm;
}

.bucket-headline strong {
  margin-inline-end: 6px;
}

.bucket-small {
  @apply text-sm text-muted-foreground;
}

.bucket-groups {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.bucket-group {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 2px 10px;
  @apply text-xs;
}

.bucket-group:hover {
  background: var(--accent);
}

.bucket-group[data-selected='true'] {
  border-color: var(--primary);
  @apply text-primary-text;
}

.bucket-group-weight {
  font-variant-numeric: tabular-nums;
  @apply text-muted-foreground;
}
</style>
