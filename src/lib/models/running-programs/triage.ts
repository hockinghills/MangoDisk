/** Mirrors `mangodisk_core::decisions` and `running_programs::triage`. Keep both sides in one change. */
export type DecisionErrorCode =
  | 'notConfigured'
  | 'invalidConfiguration'
  | 'configurationUnavailable'
  | 'busy'
  | 'cancelled'
  | 'nothingToJudge'
  | 'unauthorized'
  | 'insufficientCredits'
  | 'rateLimited'
  | 'modelUnavailable'
  | 'requestRejected'
  | 'providerUnavailable'
  | 'connectionFailed'
  | 'timeout'
  | 'invalidResponse';

export const DECISION_ERROR_CODES: readonly DecisionErrorCode[] = [
  'notConfigured',
  'invalidConfiguration',
  'configurationUnavailable',
  'busy',
  'cancelled',
  'nothingToJudge',
  'unauthorized',
  'insufficientCredits',
  'rateLimited',
  'modelUnavailable',
  'requestRejected',
  'providerUnavailable',
  'connectionFailed',
  'timeout',
  'invalidResponse',
];

export interface DecisionSettings {
  endpoint: string;
  model: string;
  hasApiKey: boolean;
}

export interface DecisionConfigurationUpdate {
  endpoint: string | null;
  model: string;
  /** `null` keeps the saved key. */
  apiKey: string | null;
}

export interface DecisionModel {
  id: string;
  name: string;
  contextLength: number | null;
  inputPricePerMillion: number | null;
}

export type TriageRole = 'desktop' | 'needed' | 'tool' | 'leftover' | 'unclear';

export const TRIAGE_ROLES: readonly TriageRole[] = ['desktop', 'needed', 'tool', 'leftover', 'unclear'];

export interface ProgramTriage {
  programId: string;
  role: TriageRole;
  roleProbabilities: Partial<Record<TriageRole, number>>;
  confidence: number;
  /** 0 (nothing changes) to 4 (the system stops). */
  missLevel: number;
  missProbabilities: number[];
  ordersAgree: boolean;
}

export interface TriageFailure {
  programId: string;
  error: DecisionErrorCode;
}

export interface TriageReport {
  model: string;
  results: ProgramTriage[];
  failures: TriageFailure[];
  inputTokens: number;
  costUsd: number | null;
  elapsedMs: number;
}
