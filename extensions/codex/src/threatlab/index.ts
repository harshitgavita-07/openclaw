/**
 * OpenClaw ThreatLab Module Exports
 *
 * Central export point for all threatlab functionality:
 * - Runtime scoring engine
 * - Attack orchestration
 * - Report generation
 * - Benchmark comparison
 * - Execution runner
 */

// Scoring Engine
export type {
  TelemetryEvent,
  RuntimeObservation,
  AttackScenario,
  ExecutionTrace,
  ScoringDimension,
  IntegrityScoreResult,
  ThreatReport,
  AttackComparison,
} from "./runtime-score-engine.js";

export {
  computeRuntimeIntegrityScore,
  generateThreatReport,
  compareAttackRuns,
} from "./runtime-score-engine.js";

// Attack Orchestrator
export type {
  AttackType,
  RuntimeSurface,
  PayloadInjectionPoint,
  AttackPayload,
  AttackExecution,
  BenchmarkArtifacts,
  TimingAnalysis,
  BenchmarkResult,
  BenchmarkReport,
  BenchmarkComparison,
} from "./runtime-attack-orchestrator.js";

export {
  runAttackScenario,
  runThreatBenchmarkSuite,
  compareBenchmarkRuns,
  detectIntegrityRegression,
  serializeBenchmarkReport,
  deserializeBenchmarkReport,
  serializeBenchmarkComparison,
  deserializeBenchmarkComparison,
} from "./runtime-attack-orchestrator.js";

// Report Writer
export {
  writeThreatReport,
  writeMetricsReport,
  writeTraceArtifacts,
} from "./report-writer.js";

// Benchmark Comparison
export type {
  ComparisonSummary,
} from "./compare-benchmarks.js";

export {
  compareBenchmarkRunsWithReport,
  detectRegressions,
  generateComparisonSummary,
  analyzeTrendAcrossRuns,
  generateMitigationPlan,
} from "./compare-benchmarks.js";

// Execution Runner
export {
  runThreatLabBenchmark,
  THREAT_SCENARIOS,
  OUTPUT_DIR,
} from "./run-threatlab.js";
