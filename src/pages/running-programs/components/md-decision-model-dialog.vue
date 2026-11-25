<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';

import MdDialogContent from '@/components/custom/md-dialog-content.vue';
import MdDialogFooter from '@/components/custom/md-dialog-footer.vue';
import MdDialogHeader from '@/components/custom/md-dialog-header.vue';
import { Button } from '@/components/ui/button';
import { Dialog, DialogDescription, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import type { DecisionErrorCode, DecisionModel, DecisionSettings } from '@/lib/models/running-programs/triage';
import { TriageService } from '@/lib/services/running-programs/triage-service';

const props = defineProps<{
  open: boolean;
  settings: DecisionSettings | null | undefined;
}>();

const emit = defineEmits<{
  'update:open': [open: boolean];
  saved: [settings: DecisionSettings | null];
}>();

const { t } = useI18n({ useScope: 'global' });

const apiKey = ref('');
const model = ref('');
const models = ref<DecisionModel[]>([]);
const loadingModels = ref(false);
const saving = ref(false);
const error = ref<DecisionErrorCode | null>(null);

const canSave = computed(
  () =>
    !saving.value && model.value.length > 0 && (apiKey.value.trim().length > 0 || Boolean(props.settings?.hasApiKey))
);

function priceText(entry: DecisionModel): string {
  if (entry.inputPricePerMillion === null) return '';
  return t('runningPrograms.triage.pricePerMillion', {
    price:
      entry.inputPricePerMillion < 0.01 ? entry.inputPricePerMillion.toFixed(4) : entry.inputPricePerMillion.toFixed(3),
  });
}

/** A generally available paid model; free listings can have tighter limits and other data terms. */
const PREFERRED_MODEL = 'microsoft/microsoft-decision-1.1';

function defaultModel(entries: DecisionModel[]): string {
  if (entries.some(entry => entry.id === PREFERRED_MODEL)) return PREFERRED_MODEL;
  const paid = entries.filter(entry => (entry.inputPricePerMillion ?? 0) > 0);
  paid.sort((left, right) => (left.inputPricePerMillion ?? 0) - (right.inputPricePerMillion ?? 0));
  return paid[0]?.id ?? entries[0]?.id ?? '';
}

async function loadModels() {
  loadingModels.value = true;
  error.value = null;
  try {
    models.value = await TriageService.models(props.settings?.endpoint ?? null);
    if (!model.value && models.value.length) model.value = defaultModel(models.value);
  } catch (reason) {
    error.value = TriageService.errorCode(reason) ?? 'connectionFailed';
  } finally {
    loadingModels.value = false;
  }
}

watch(
  () => props.open,
  open => {
    if (!open) return;
    apiKey.value = '';
    model.value = props.settings?.model ?? '';
    void loadModels();
  },
  { immediate: true }
);

function updateModel(value: unknown) {
  if (typeof value === 'string') model.value = value;
}

async function save() {
  if (!canSave.value) return;
  saving.value = true;
  error.value = null;
  try {
    const settings = await TriageService.saveSettings({
      endpoint: props.settings?.endpoint ?? null,
      model: model.value,
      apiKey: apiKey.value.trim() ? apiKey.value.trim() : null,
    });
    emit('saved', settings);
    emit('update:open', false);
  } catch (reason) {
    error.value = TriageService.errorCode(reason) ?? 'configurationUnavailable';
  } finally {
    saving.value = false;
  }
}

async function remove() {
  saving.value = true;
  try {
    await TriageService.deleteSettings();
    emit('saved', null);
    emit('update:open', false);
  } catch (reason) {
    error.value = TriageService.errorCode(reason) ?? 'configurationUnavailable';
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <Dialog :open="open" @update:open="value => emit('update:open', value)">
    <MdDialogContent size="standard">
      <MdDialogHeader>
        <DialogTitle>{{ t('runningPrograms.triage.connectTitle') }}</DialogTitle>
        <DialogDescription>{{ t('runningPrograms.triage.connectDescription') }}</DialogDescription>
      </MdDialogHeader>

      <div class="connect-form">
        <label class="connect-field">
          <span>{{ t('runningPrograms.triage.apiKey') }}</span>
          <Input
            v-model="apiKey"
            type="password"
            autocomplete="off"
            :placeholder="
              settings?.hasApiKey
                ? t('runningPrograms.triage.apiKeySaved')
                : t('runningPrograms.triage.apiKeyPlaceholder')
            "
          />
        </label>

        <div class="connect-field">
          <span>{{ t('runningPrograms.triage.model') }}</span>
          <Select :model-value="model" :disabled="loadingModels || !models.length" @update:model-value="updateModel">
            <SelectTrigger :aria-label="t('runningPrograms.triage.model')">
              <SelectValue
                :placeholder="
                  loadingModels ? t('runningPrograms.triage.loadingModels') : t('runningPrograms.triage.chooseModel')
                "
              />
            </SelectTrigger>
            <SelectContent>
              <SelectItem v-for="entry in models" :key="entry.id" :value="entry.id">
                {{ entry.name }}<template v-if="priceText(entry)"> · {{ priceText(entry) }}</template>
              </SelectItem>
            </SelectContent>
          </Select>
        </div>

        <p class="connect-note">{{ t('runningPrograms.triage.privacyNote') }}</p>
        <p v-if="error" class="connect-error" role="alert">{{ t(`runningPrograms.triage.errors.${error}`) }}</p>
      </div>

      <MdDialogFooter align="between">
        <Button v-if="settings" variant="ghost" type="button" :disabled="saving" @click="remove">
          {{ t('runningPrograms.triage.disconnect') }}
        </Button>
        <span v-else />
        <div class="connect-actions">
          <Button variant="outline" type="button" @click="emit('update:open', false)">
            {{ t('runningPrograms.triage.cancel') }}
          </Button>
          <Button type="button" :disabled="!canSave" @click="save">{{ t('runningPrograms.triage.save') }}</Button>
        </div>
      </MdDialogFooter>
    </MdDialogContent>
  </Dialog>
</template>

<style scoped>
@reference "@assets/main.css";

.connect-form {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.connect-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
  @apply text-sm font-medium;
}

.connect-note {
  @apply text-sm text-muted-foreground;
}

.connect-error {
  @apply text-sm text-destructive-text;
}

.connect-actions {
  display: flex;
  gap: 8px;
}
</style>
