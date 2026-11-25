<script setup lang="ts">
import { computed } from 'vue';
import { useI18n } from 'vue-i18n';

import MdResultTableRow from '@/components/custom/md-result-table-row.vue';
import MdStatusBadge from '@/components/custom/md-status-badge.vue';
import MdTooltip from '@/components/custom/md-tooltip.vue';
import MdIcon from '@/components/icons/md-icon.vue';
import { ICON_NAMES } from '@/lib/models/presentation/ui';
import type { ProgramSafetyClass, RunningProgram } from '@/lib/models/running-programs/running-programs';
import type { ProgramTriage, TriageAnswer, TriageRole } from '@/lib/models/running-programs/triage';
import { TRIAGE_ROLES } from '@/lib/models/running-programs/triage';
import { FormatService } from '@/lib/services/presentation/format-service';
import { ByteSizeService } from '@/lib/services/settings/byte-size-service';
import {
  factMessage,
  installedDateSourceKey,
  launchMessage,
  type ProgramMessage,
} from '@/lib/utils/running-programs/running-programs-messages';
import { cpuPercentText } from '@/lib/utils/running-programs/running-programs-view';

const props = defineProps<{
  program: RunningProgram;
  expanded: boolean;
  triage: ProgramTriage | null;
}>();

const emit = defineEmits<{
  toggleExpanded: [];
}>();

const { t, locale } = useI18n({ useScope: 'global' });

const SAFETY_TONES: Record<ProgramSafetyClass, 'neutral' | 'primary' | 'warning'> = {
  core: 'warning',
  optional: 'neutral',
  system: 'neutral',
  yours: 'primary',
};

function kb(value: number): string {
  return ByteSizeService.memory(value * 1024);
}

function text(entry: ProgramMessage): string {
  const params = Object.fromEntries(
    Object.entries(entry.params).map(([key, value]) => [
      key,
      key === 'date' && typeof value === 'number' ? FormatService.date(value, locale.value) : value,
    ])
  );
  return t(`runningPrograms.${entry.key}`, params);
}

const origin = computed(() => props.program.origin);
const originLabel = computed(() => t(`runningPrograms.originKinds.${origin.value.kind}`));
const launchSummary = computed(() => {
  const first = props.program.launches[0];
  return first ? text(launchMessage(first)) : t('runningPrograms.launch.unknown');
});
const installedText = computed(() => {
  const sourceKey = installedDateSourceKey(origin.value);
  if (!sourceKey || origin.value.installedAtMs === null) return null;
  return t('runningPrograms.detail.installedOn', {
    date: FormatService.date(origin.value.installedAtMs, locale.value),
    source: t(`runningPrograms.${sourceKey}`),
  });
});
const containerText = computed(() => {
  const container = origin.value.container;
  if (!container) return null;
  const parts = [
    container.engine ? t(`runningPrograms.containerEngines.${container.engine}`) : null,
    container.image ? t('runningPrograms.detail.containerImage', { image: container.image }) : null,
    container.composeProject
      ? t('runningPrograms.detail.composeService', {
          project: container.composeProject,
          service: container.composeService ?? '',
        })
      : null,
    container.project ? t('runningPrograms.detail.containerProject', { project: container.project }) : null,
    t('runningPrograms.detail.containerId', { id: container.id }),
  ];
  return parts.filter(Boolean).join(' · ');
});
const facts = computed(() => origin.value.facts.map(fact => text(factMessage(fact))));
const launches = computed(() => props.program.launches.map(launch => text(launchMessage(launch))));
const memoryLabel = computed(() =>
  props.program.memoryIsProportional ? t('runningPrograms.columns.memory') : t('runningPrograms.columns.memoryResident')
);
const TRIAGE_TONES: Record<TriageRole, 'neutral' | 'primary' | 'warning'> = {
  desktop: 'neutral',
  needed: 'neutral',
  tool: 'primary',
  leftover: 'warning',
  unclear: 'neutral',
};

function percent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

const triageRoles = computed(() =>
  props.triage?.role
    ? TRIAGE_ROLES.map(role => ({ role, probability: props.triage?.roleProbabilities[role] ?? 0 })).sort(
        (left, right) => right.probability - left.probability
      )
    : []
);
const missLevelKey = computed(() =>
  props.triage && props.triage.missLevel !== null
    ? `runningPrograms.triage.missLevels.${Math.min(4, Math.max(0, Math.round(props.triage.missLevel)))}`
    : null
);

function answerText(answer: TriageAnswer): string {
  switch (answer.type) {
    case 'choice':
      return `${answer.choice} ${percent(answer.confidence)}`;
    case 'score':
      return t('runningPrograms.triage.answerLevel', { level: answer.expected.toFixed(1) });
    case 'noul':
      return t('runningPrograms.triage.answerTrue', { percent: percent(answer.probability) });
  }
}

/** Answers the page has no labels for, from custom questions, shown with their own ids. */
const otherAnswers = computed(() => {
  const triage = props.triage;
  if (!triage) return [];
  return Object.entries(triage.answers)
    .filter(([id]) => !(id === 'role' && triage.role !== null) && !(id === 'miss' && triage.missLevel !== null))
    .map(([id, answer]) => ({ id, text: answerText(answer) }));
});

/** The chip: the built-in role, or else the first choice answer of a custom set. */
const chip = computed(() => {
  const triage = props.triage;
  if (!triage) return null;
  if (triage.role) {
    return {
      tone: TRIAGE_TONES[triage.role],
      text: `${t(`runningPrograms.triage.roles.${triage.role}`)} ${percent(triage.confidence)}`,
    };
  }
  const choice = Object.values(triage.answers).find(answer => answer.type === 'choice');
  return choice ? { tone: 'neutral' as const, text: answerText(choice) } : null;
});

const startedText = computed(() => FormatService.dateTime(props.program.startedAtMs, locale.value));
</script>

<template>
  <article class="program-row">
    <MdResultTableRow class="program-line" :data-expanded="expanded">
      <button
        class="program-main"
        type="button"
        :aria-expanded="expanded"
        :aria-label="t('runningPrograms.viewDetails', { name: program.name })"
        @click="emit('toggleExpanded')"
      >
        <MdIcon
          class="program-chevron"
          :name="expanded ? ICON_NAMES.chevronDown : ICON_NAMES.chevronRight"
          :size="16"
        />
        <span class="program-identity">
          <MdTooltip :text="program.name">
            <strong class="md-result-primary">{{ program.name }}</strong>
          </MdTooltip>
          <small class="program-origin">
            {{
              program.packageName ? t('runningPrograms.packageOrigin', { package: program.packageName }) : originLabel
            }}
            <template v-if="origin.version"> · {{ origin.version }}</template>
            <template v-if="program.processes.length > 1">
              · {{ t('runningPrograms.processCount', { count: program.processes.length }) }}
            </template>
          </small>
        </span>
        <span class="program-launch">{{ launchSummary }}</span>
        <span class="program-metric" :aria-label="memoryLabel">{{ kb(program.memoryKb) }}</span>
        <span class="program-metric program-metric--muted">{{ program.swapKb ? kb(program.swapKb) : '—' }}</span>
        <span class="program-metric">{{ cpuPercentText(program.cpuPercentNow) }}</span>
        <span class="program-metric program-metric--muted">{{ cpuPercentText(program.cpuPercentAverage) }}</span>
        <span class="program-badges">
          <MdTooltip v-if="chip" :text="t('runningPrograms.triage.chipHint')">
            <MdStatusBadge size="compact" :tone="chip.tone">{{ chip.text }}</MdStatusBadge>
          </MdTooltip>
          <MdTooltip :text="t(`runningPrograms.safetyDescriptions.${program.safety}`)">
            <MdStatusBadge size="compact" :tone="SAFETY_TONES[program.safety]">
              {{ t(`runningPrograms.safety.${program.safety}`) }}
            </MdStatusBadge>
          </MdTooltip>
        </span>
      </button>
    </MdResultTableRow>

    <div v-if="expanded" class="program-detail">
      <dl class="detail-list">
        <template v-if="triage">
          <dt>{{ t('runningPrograms.triage.detailTitle') }}</dt>
          <dd>
            <ul class="detail-bullets">
              <li v-for="entry in triageRoles" :key="entry.role">
                {{ t(`runningPrograms.triage.roles.${entry.role}`) }}: {{ percent(entry.probability) }}
              </li>
              <li v-if="missLevelKey">{{ t('runningPrograms.triage.missPrefix') }} {{ t(missLevelKey) }}</li>
              <li v-for="entry in otherAnswers" :key="entry.id">{{ entry.id }}: {{ entry.text }}</li>
              <li v-if="!triage.ordersAgree">{{ t('runningPrograms.triage.ordersDisagree') }}</li>
            </ul>
          </dd>
        </template>

        <template v-if="origin.description">
          <dt>{{ t('runningPrograms.detail.description') }}</dt>
          <dd>{{ origin.description }}</dd>
        </template>

        <template v-if="origin.requiredByCount !== null">
          <dt>{{ t('runningPrograms.detail.requiredBy') }}</dt>
          <dd>{{ t('runningPrograms.detail.requiredByCount', { count: origin.requiredByCount }) }}</dd>
        </template>

        <dt>{{ t('runningPrograms.detail.origin') }}</dt>
        <dd>
          {{ originLabel }}
          <template v-if="origin.kind !== 'systemPackage' && origin.name !== program.name">
            · {{ origin.name }}</template
          >
        </dd>

        <template v-if="installedText">
          <dt>{{ t('runningPrograms.detail.installed') }}</dt>
          <dd>{{ installedText }}</dd>
        </template>

        <template v-if="origin.packageRequest">
          <dt>{{ t('runningPrograms.detail.packageRequest') }}</dt>
          <dd>
            {{ t(`runningPrograms.packageRequests.${origin.packageRequest}`) }}
            <template v-if="origin.installBurst"> · {{ t('runningPrograms.detail.installBurst') }}</template>
          </dd>
        </template>

        <template v-if="origin.installCommand">
          <dt>{{ t('runningPrograms.detail.installCommand') }}</dt>
          <dd>
            <code>{{ origin.installCommand }}</code>
          </dd>
        </template>

        <template v-if="origin.location">
          <dt>{{ t('runningPrograms.detail.location') }}</dt>
          <dd>
            <code>{{ origin.location }}</code>
          </dd>
        </template>

        <template v-if="origin.sourceUrl">
          <dt>{{ t('runningPrograms.detail.source') }}</dt>
          <dd>
            <code>{{ origin.sourceUrl }}</code>
          </dd>
        </template>

        <template v-if="containerText">
          <dt>{{ t('runningPrograms.detail.container') }}</dt>
          <dd>{{ containerText }}</dd>
        </template>

        <dt>{{ t('runningPrograms.detail.startedBy') }}</dt>
        <dd>
          <ul class="detail-bullets">
            <li v-for="(launch, index) in launches" :key="index">{{ launch }}</li>
          </ul>
        </dd>

        <dt>{{ t('runningPrograms.detail.running') }}</dt>
        <dd>
          {{ t('runningPrograms.detail.runningSince', { date: startedText }) }} ·
          {{ t('runningPrograms.detail.cpuTime', { seconds: FormatService.integer(Math.round(program.cpuSeconds)) }) }}
          <template v-if="program.quietSinceStart"> · {{ t('runningPrograms.detail.quietSinceStart') }}</template>
        </dd>

        <template v-if="facts.length || program.executableReplaced">
          <dt>{{ t('runningPrograms.detail.notes') }}</dt>
          <dd>
            <ul class="detail-bullets">
              <li v-for="(fact, index) in facts" :key="index">{{ fact }}</li>
              <li v-if="program.executableReplaced">{{ t('runningPrograms.detail.executableReplaced') }}</li>
            </ul>
          </dd>
        </template>

        <template v-if="!program.memoryIsProportional">
          <dt>{{ t('runningPrograms.detail.memoryNote') }}</dt>
          <dd>{{ t('runningPrograms.detail.memoryResidentNote') }}</dd>
        </template>
      </dl>

      <p v-if="program.processes.some(process => process.role === 'renderer')" class="process-hint">
        {{ t('runningPrograms.detail.rendererHint') }}
      </p>
      <table class="process-table">
        <thead>
          <tr>
            <th>{{ t('runningPrograms.processes.pid') }}</th>
            <th>{{ t('runningPrograms.processes.name') }}</th>
            <th class="numeric">{{ t('runningPrograms.columns.memory') }}</th>
            <th class="numeric">{{ t('runningPrograms.columns.swap') }}</th>
            <th class="numeric">{{ t('runningPrograms.columns.cpuNow') }}</th>
            <th>{{ t('runningPrograms.processes.commandLine') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="process in program.processes" :key="process.pid">
            <td>{{ process.pid }}</td>
            <td>
              {{ process.name }}
              <small v-if="process.role" class="process-note">
                {{
                  process.roleDetail
                    ? t('runningPrograms.processRoles.utilityNamed', { service: process.roleDetail })
                    : t(`runningPrograms.processRoles.${process.role}`)
                }}
              </small>
              <small v-if="process.foldedFrom" class="process-note">
                {{ t('runningPrograms.processes.foldedFrom', { name: process.foldedFrom }) }}
              </small>
              <small v-if="process.inlineCode" class="process-note">
                {{
                  process.workingDirectory
                    ? t('runningPrograms.processes.inlineCodeIn', { folder: process.workingDirectory })
                    : t('runningPrograms.processes.inlineCode')
                }}
              </small>
            </td>
            <td class="numeric">{{ kb(process.memoryKb) }}</td>
            <td class="numeric">{{ process.swapKb ? kb(process.swapKb) : '—' }}</td>
            <td class="numeric">{{ cpuPercentText(process.cpuPercentNow) }}</td>
            <td class="command-line">
              <code>{{ process.commandLine.join(' ') }}</code>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </article>
</template>

<style scoped>
@reference "@assets/main.css";

.program-main {
  display: grid;
  width: 100%;
  min-width: 0;
  min-height: 52px;
  grid-template-columns: 16px minmax(10rem, 1.4fr) minmax(8rem, 1.6fr) repeat(4, 5.5rem) 12rem;
  align-items: center;
  gap: 10px;
  padding-block: 4px;
  text-align: start;
  cursor: pointer;
}

.program-identity {
  display: flex;
  min-width: 0;
  flex-direction: column;
}

.program-identity strong,
.program-origin,
.program-launch {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.program-origin,
.program-launch,
.program-metric--muted,
.process-note {
  @apply text-sm text-muted-foreground;
}

.program-metric {
  text-align: end;
  font-variant-numeric: tabular-nums;
}

.program-badges {
  display: flex;
  justify-content: flex-end;
  gap: 6px;
}

.program-chevron {
  @apply text-muted-foreground;
}

.program-detail {
  display: flex;
  flex-direction: column;
  gap: 14px;
  margin-inline-start: 40px;
  padding: 6px 14px 16px;
}

.detail-list {
  display: grid;
  grid-template-columns: minmax(8rem, max-content) minmax(0, 1fr);
  gap: 6px 16px;
  @apply text-sm;
}

.detail-list dt {
  @apply text-muted-foreground;
}

.detail-list dd {
  min-width: 0;
  overflow-wrap: anywhere;
}

.detail-bullets {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.process-table {
  width: 100%;
  border-collapse: collapse;
  @apply text-sm;
}

.process-table th {
  padding: 4px 8px;
  text-align: start;
  font-weight: 500;
  @apply text-muted-foreground;
}

.process-table td {
  padding: 4px 8px;
  vertical-align: top;
  border-top: 1px solid var(--border);
}

.process-table .numeric {
  text-align: end;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.process-note {
  display: block;
}

.process-hint {
  @apply text-sm text-muted-foreground;
}

.command-line code {
  overflow-wrap: anywhere;
  @apply text-xs;
}
</style>
