import { invoke } from '@tauri-apps/api/core';

import type {
  DecisionConfigurationUpdate,
  DecisionErrorCode,
  DecisionModel,
  DecisionSettings,
  TriageReport,
} from '@/lib/models/running-programs/triage';
import { DECISION_ERROR_CODES } from '@/lib/models/running-programs/triage';

export class TriageService {
  static settings(): Promise<DecisionSettings | null> {
    return invoke<DecisionSettings | null>('decisions_get_settings');
  }

  static saveSettings(update: DecisionConfigurationUpdate): Promise<DecisionSettings> {
    return invoke<DecisionSettings>('decisions_save_settings', { update });
  }

  static deleteSettings(): Promise<void> {
    return invoke<void>('decisions_delete_settings');
  }

  static models(endpoint: string | null): Promise<DecisionModel[]> {
    return invoke<DecisionModel[]>('decisions_list_models', { endpoint });
  }

  /** Judges the programs from Core's last scan; `programIds` limits it to some of them. */
  static triage(programIds: string[] | null): Promise<TriageReport> {
    return invoke<TriageReport>('running_programs_triage', { programIds });
  }

  static cancel(): Promise<void> {
    return invoke<void>('running_programs_cancel_triage');
  }

  /** Decision commands reject with a bare code string. */
  static errorCode(error: unknown): DecisionErrorCode | null {
    return typeof error === 'string' && (DECISION_ERROR_CODES as readonly string[]).includes(error)
      ? (error as DecisionErrorCode)
      : null;
  }
}
