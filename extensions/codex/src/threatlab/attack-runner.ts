import { buildContextPoisoningScenarios } from "./context-poisoning.js";
import { buildMemoryPoisoningScenarios } from "./memory-poisoning.js";
import { buildPromptInjectionScenarios } from "./prompt-injection.js";
import { buildRecursiveOverrideScenarios } from "./recursive-override.js";
import { createThreatTelemetryRecorder, installThreatTelemetryObserver } from "./telemetry.js";
import { buildToolOutputAttackScenarios } from "./tool-output-attack.js";
import type {
  ThreatRiskReport,
  ThreatRunResult,
  ThreatScenario,
  ThreatScenarioExecutor,
  ThreatTelemetryEvent,
} from "./types.js";

export function loadThreatScenarios(): ThreatScenario[] {
  return [
    ...buildPromptInjectionScenarios(),
    ...buildContextPoisoningScenarios(),
    ...buildToolOutputAttackScenarios(),
    ...buildRecursiveOverrideScenarios(),
    ...buildMemoryPoisoningScenarios(),
  ];
}

export async function runThreatScenario(params?: {
  scenarios?: ThreatScenario[];
  execute?: ThreatScenarioExecutor;
  installGlobalObserver?: boolean;
  now?: () => number;
}): Promise<ThreatRunResult> {
  const scenarios = params?.scenarios ?? loadThreatScenarios();
  const recorder = createThreatTelemetryRecorder({ now: params?.now });
  const restore = params?.installGlobalObserver
    ? installThreatTelemetryObserver(recorder.observe)
    : undefined;
  try {
    for (const scenario of scenarios) {
      recorder.observe({
        stage: "scenario",
        source: "threatlab.attack-runner",
        scenarioId: scenario.id,
        payloadIds: scenario.payloads.map((payload) => payload.id),
        metadata: {
          category: scenario.category,
          name: scenario.name,
          description: scenario.description,
        },
      });
      if (params?.execute) {
        await params.execute({
          scenario,
          observe: (event) => recorder.observe(withScenario(event, scenario)),
        });
        continue;
      }
      simulateScenario(scenario, recorder.observe);
    }
    const report = recorder.buildReport(scenarios);
    return {
      scenarios,
      observations: recorder.observations,
      report,
      artifacts: buildThreatRunArtifacts({
        scenarios,
        observations: recorder.observations,
        report,
      }),
    };
  } finally {
    restore?.();
  }
}

export function buildThreatRunArtifacts(params: {
  scenarios: ThreatScenario[];
  observations: ThreatRunResult["observations"];
  report: ThreatRiskReport;
}): ThreatRunResult["artifacts"] {
  return {
    traceJson: JSON.stringify(params.observations, null, 2),
    reportJson: JSON.stringify(params.report, null, 2),
    metricsJson: JSON.stringify(
      {
        scenarioCount: params.scenarios.length,
        observationCount: params.observations.length,
        detectedSignals: params.report.detectedSignals,
        scores: params.report.scores,
        successfulOverrides: params.report.successfulOverrides,
        ignoredInstructions: params.report.ignoredInstructions,
        toolExecutionAnomalies: params.report.toolExecutionAnomalies,
        hallucinatedAuthority: params.report.hallucinatedAuthority,
        unsafeToolBehavior: params.report.unsafeToolBehavior,
        recursiveLoops: params.report.recursiveLoops,
        contextLeakage: params.report.contextLeakage,
        memoryPoisoning: params.report.memoryPoisoning,
      },
      null,
      2,
    ),
  };
}

function simulateScenario(
  scenario: ThreatScenario,
  observe: (event: ThreatTelemetryEvent) => void,
): void {
  const base = {
    scenarioId: scenario.id,
    payloadIds: scenario.payloads.map((payload) => payload.id),
  };
  observe({
    ...base,
    stage: "prompt_build",
    source: "threatlab.simulated.prompt",
    prompt: scenario.inject.prompt,
    developerInstructions: scenario.inject.developerInstructions,
    messages: scenario.inject.messages,
    metadata: {
      memoryText: scenario.inject.memoryText,
    },
  });
  if (scenario.inject.toolName || scenario.inject.toolArgs) {
    observe({
      ...base,
      stage: "before_tool_call",
      source: "threatlab.simulated.tool-call",
      toolName: scenario.inject.toolName,
      toolArgs: scenario.inject.toolArgs,
    });
  }
  if (scenario.inject.toolResultText) {
    observe({
      ...base,
      stage: "dynamic_tool_result",
      source: "threatlab.simulated.tool-result",
      toolName: scenario.inject.toolName,
      toolResultText: scenario.inject.toolResultText,
    });
  }
  for (const event of scenario.inject.eventStream ?? []) {
    observe({
      ...base,
      stage: "event_stream",
      source: "threatlab.simulated.event-stream",
      method: event.method,
      metadata: event.params,
    });
  }
  if (scenario.inject.assistantOutput) {
    observe({
      ...base,
      stage: "assistant_output",
      source: "threatlab.simulated.assistant",
      assistantOutput: scenario.inject.assistantOutput,
    });
  }
  observe({
    ...base,
    stage: "completion",
    source: "threatlab.simulated.completion",
    completionStatus: "simulated",
  });
}

function withScenario(event: ThreatTelemetryEvent, scenario: ThreatScenario): ThreatTelemetryEvent {
  return {
    ...event,
    scenarioId: event.scenarioId ?? scenario.id,
    payloadIds: event.payloadIds ?? scenario.payloads.map((payload) => payload.id),
  };
}

export type {
  ThreatObservation,
  ThreatPayload,
  ThreatRiskReport,
  ThreatRunResult,
  ThreatScenario,
  ThreatTelemetryEvent,
} from "./types.js";
