/** Mirrors `mangodisk_core::decisions` and `running_programs::triage`. Keep both sides in one change. */
export type DecisionErrorCode =
  | 'notConfigured'
  | 'invalidConfiguration'
  | 'configurationUnavailable'
  | 'busy'
  | 'cancelled'
  | 'nothingToJudge'
  | 'invalidQuestions'
  | 'invalidExportPath'
  | 'exportFailed'
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
  'invalidQuestions',
  'invalidExportPath',
  'exportFailed',
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

/** One question's answer after averaging both option orders. */
export type TriageAnswer =
  | {
      type: 'choice';
      choice: string;
      probabilities: Record<string, number>;
      confidence: number;
      ordersAgree: boolean;
    }
  | { type: 'score'; expected: number; probabilities: number[] }
  | { type: 'noul'; probability: number };

export interface ProgramTriage {
  programId: string;
  /** Every answer, keyed by the question ids of the set that was asked. */
  answers: Record<string, TriageAnswer>;
  /** Set only when the `role` question uses the built-in options. */
  role: TriageRole | null;
  roleProbabilities: Partial<Record<TriageRole, number>>;
  confidence: number;
  /** From the `miss` score question: 0 (nothing changes) upward. */
  missLevel: number | null;
  missProbabilities: number[];
  ordersAgree: boolean;
}

export type TriageQuestionSource = 'builtIn' | 'file' | 'supplied';

export interface TriageQuestion {
  id: string;
  instructions: string;
  type: 'choice' | 'score' | 'noul';
  options?: { id: string; criterion: string }[];
  levels?: string[];
}

export interface TriageQuestionSet {
  schemaVersion: number;
  questions: TriageQuestion[];
}

export interface TriageQuestionsInfo {
  path: string;
  /** `null` when the file exists but is not valid. */
  source: TriageQuestionSource | null;
  questionCount: number;
  /** The first rule the file breaks, in English, quoting only the user's own file. */
  problem: string | null;
}

export type TriageExportFormat = 'json' | 'markdown';

export interface TriageFailure {
  programId: string;
  error: DecisionErrorCode;
}

export interface TriageReport {
  model: string;
  questions: TriageQuestionSet;
  questionSource: TriageQuestionSource;
  results: ProgramTriage[];
  failures: TriageFailure[];
  inputTokens: number;
  costUsd: number | null;
  elapsedMs: number;
}
