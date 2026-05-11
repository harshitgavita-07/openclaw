export type ThreatAttackCategory =
  | "prompt-injection"
  | "context-poisoning"
  | "tool-output-attack"
  | "recursive-override"
  | "memory-poisoning";

export type ThreatInjectionSurface =
  | "prompt"
  | "developerInstructions"
  | "messages"
  | "toolArgs"
  | "toolResult"
  | "eventStream"
  | "assistantOutput"
  | "memory";

export type ThreatTelemetryStage =
  | "scenario"
  | "prompt_build"
  | "before_tool_call"
  | "dynamic_tool_result"
  | "event_stream"
  | "assistant_output"
  | "completion";

export type ThreatRiskSignal =
  | "promptHierarchyViolation"
  | "developerInstructionOverride"
  | "unsafeToolExecution"
  | "contextLeakage"
  | "recursiveEscalation"
  | "maliciousOutputPropagation"
  | "instructionConfusion"
  | "memoryPoisoningSuccess";

export type ThreatPayload = {
  id: string;
  category: ThreatAttackCategory;
  label: string;
  content: string;
  surfaces: ThreatInjectionSurface[];
  markers: string[];
  description?: string;
};

export type ThreatScenario = {
  id: string;
  category: ThreatAttackCategory;
  name: string;
  description: string;
  payloads: ThreatPayload[];
  inject: {
    prompt?: string;
    developerInstructions?: string;
    messages?: unknown[];
    toolName?: string;
    toolArgs?: Record<string, unknown>;
    toolResultText?: string;
    assistantOutput?: string;
    eventStream?: Array<{ method: string; params?: Record<string, unknown> }>;
    memoryText?: string;
  };
  expectedSignals: ThreatRiskSignal[];
};

export type ThreatTelemetryEvent = {
  stage: ThreatTelemetryStage;
  source: string;
  timestamp?: number;
  scenarioId?: string;
  payloadIds?: string[];
  runId?: string;
  sessionId?: string;
  toolName?: string;
  toolCallId?: string;
  method?: string;
  prompt?: string;
  developerInstructions?: string;
  messages?: unknown[];
  toolArgs?: unknown;
  toolResultText?: string;
  assistantOutput?: string;
  completionStatus?: string;
  metadata?: Record<string, unknown>;
};

export type ThreatObservation = ThreatTelemetryEvent & {
  timestamp: number;
  signals: ThreatRiskSignal[];
};

export type ThreatRiskScores = Record<ThreatRiskSignal, number>;

export type ThreatScenarioResult = {
  scenarioId: string;
  category: ThreatAttackCategory;
  name: string;
  observations: ThreatObservation[];
  scores: ThreatRiskScores;
  detectedSignals: ThreatRiskSignal[];
  passed: boolean;
};

export type ThreatRiskReport = {
  generatedAt: string;
  scenarioCount: number;
  observationCount: number;
  scores: ThreatRiskScores;
  detectedSignals: ThreatRiskSignal[];
  successfulOverrides: number;
  ignoredInstructions: number;
  toolExecutionAnomalies: number;
  hallucinatedAuthority: number;
  unsafeToolBehavior: number;
  recursiveLoops: number;
  contextLeakage: number;
  memoryPoisoning: number;
  scenarios: ThreatScenarioResult[];
};

export type ThreatRunResult = {
  scenarios: ThreatScenario[];
  observations: ThreatObservation[];
  report: ThreatRiskReport;
  artifacts: ThreatRunArtifacts;
};

export type ThreatRunArtifacts = {
  traceJson: string;
  reportJson: string;
  metricsJson: string;
};

export type ThreatScenarioExecutor = (params: {
  scenario: ThreatScenario;
  observe: (event: ThreatTelemetryEvent) => void;
}) => Promise<void> | void;
