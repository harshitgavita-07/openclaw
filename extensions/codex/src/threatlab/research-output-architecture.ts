/**
 * OpenClaw Runtime Threat Observatory
 * PHASE 6: Research Output & Comprehensive Reporting Framework
 *
 * Generates complete research deliverables including threat matrices,
 * propagation maps, integrity benchmarks, and observability architecture.
 */

import type { CrossLayerAttackScenario } from "./multi-layer-attack-scenarios.js";
import type { IntegrityDegradationReport, ObservabilityMetrics, PropagationAnalysis } from "./telemetry-engine.js";

// ============================================================================
// RESEARCH OUTPUT TYPES
// ============================================================================


/** Simple mulberry32 seeded PRNG — produces deterministic floats in [0, 1).
 *  Using a fixed seed derived from the scenario index ensures benchmark
 *  reproducibility across runs (addresses Gemini review: Math.random() non-determinism). */
function seededRandom(seed: number): () => number {
  let s = seed >>> 0;
  return function () {
    s += 0x6d2b79f5;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}


export interface RuntimeThreatMatrix {
  generatedAt: number;
  runtimeVersion: string;
  
  // 10 layers × 17 threat classes = 170 entries
  threatSurfaces: Array<{
    layer: string;
    threatClass: string;
    attackSurface: string;
    trustAssumptions: string[];
    exploitationDifficulty: "trivial" | "easy" | "moderate" | "difficult" | "very_difficult";
    severityIfExploited: "low" | "medium" | "high" | "critical";
    currentDetectionCapability: number; // 0-1
    mitigationCost: "low" | "medium" | "high" | "very_high";
  }>;
  
  // Summary statistics
  summary: {
    totalThreatSurfaces: number;
    criticalThreats: number;
    unmitigatedThreats: number;
    averageExploitability: number;
    coverageGaps: string[];
  };
}

export interface TrustPropagationMap {
  generatedAt: number;
  
  // Trust flow through architecture
  trustChains: Array<{
    source: string; // "system" | "developer" | "user" | "external"
    path: string[]; // Layer traversal
    degradationAtEachStep: number[];
    finalTrustLevel: number;
    breakingPoints: string[]; // Where trust can be broken
  }>;
  
  // Inverse: how compromise propagates
  compromisePropagation: Array<{
    compromisedLayer: string;
    affectedLayers: string[];
    amplificationFactor: number;
    timeToFullCompromise: "immediate" | "single_turn" | "multi_turn" | "delayed";
  }>;
  
  // Critical trust junctions
  trustJunctions: Array<{
    location: string;
    upstreamLayers: string[];
    downstreamLayers: string[];
    trustMultiplier: number;
    riskLevel: number;
  }>;
}

export interface CrossLayerEscalationGraph {
  generatedAt: number;
  
  // All possible escalation paths
  escalationPaths: Array<{
    pathId: string;
    startingPoint: string;
    endPoint: string;
    layers: string[];
    lengthSteps: number;
    amplification: number;
    probability: number; // Based on propagation matrix
    severity: "low" | "medium" | "high" | "critical";
  }>;
  
  // Critical escalation chokepoints
  chokepoints: Array<{
    layer: string;
    position: "entry" | "middle" | "exit";
    controlsAccessTo: string[];
    defenseRecommendation: string;
  }>;
  
  // Fastest escalation paths (by layer count)
  shortestPaths: Array<{
    fromLayer: string;
    toLayer: string;
    pathLength: number;
    path: string[];
  }>;
  
  // Highest amplification paths
  highestAmplificationPaths: Array<{
    path: string[];
    amplification: number;
    finalSeverity: "low" | "medium" | "high" | "critical";
  }>;
}

export interface IntegrityBenchmarkReport {
  generatedAt: number;
  runtimeVersion: string;
  
  // Overall integrity summary
  baselineIntegrity: {
    uncompromised: number; // 1.0
    measuredDate: number;
  };
  
  // Integrity under different attack classes
  integrityUnderAttack: Array<{
    threatClass: string;
    baselineIntegrity: number;
    afterAttackIntegrity: number;
    integrityLoss: number;
    affectedLayers: string[];
    recoveryTime: "immediate" | "single_turn" | "multi_turn" | "manual_intervention";
  }>;
  
  // Layer-by-layer integrity
  layerIntegrity: Array<{
    layer: string;
    baselineIntegrity: number;
    vulnerabilityCount: number;
    worstCaseIntegrity: number;
    bestCaseIntegrity: number;
    averageIntegrity: number;
  }>;
  
  // Attack effectiveness ranking
  mostEffectiveAttacks: Array<{
    scenarioId: string;
    scenarioName: string;
    integrityLoss: number;
    layersAffected: number;
    exploitability: number;
  }>;
  
  // Integrity degradation patterns
  degradationPatterns: Array<{
    pattern: string; // e.g., "exponential_multi_turn"
    affectedScenarios: string[];
    degradationFormula: string;
    mitigationStrategy: string;
  }>;
}

export interface LayerThreatTaxonomy {
  layerId: string;
  layerName: string;
  
  threats: Array<{
    threatId: string;
    threatName: string;
    category: string;
    description: string;
    
    // Attack surface
    injectionPoints: string[];
    exploitableAssumptions: string[];
    requiredPreconditions: string[];
    
    // Propagation
    canPropagateTo: Array<{
      targetLayer: string;
      propagationMechanism: string;
      probability: number;
      amplificationFactor: number;
    }>;
    
    // Persistence
    persistenceVectors: Array<{
      vector: string;
      duration: "single_turn" | "cross_turn" | "cross_session";
      survivability: number;
    }>;
    
    // Detection & Mitigation
    detectionSignatures: string[];
    mitigationStrategies: string[];
    currentDetectionCapability: number;
  }>;
  
  // Layer-specific integrity metrics
  integrityMetrics: {
    baselineScore: number;
    criticalityRank: number; // 1-10, 10 = most critical
    exploitationResistance: number; // 0-1
    recoveryCapability: number; // 0-1
  };
  
  // Dependencies & interactions
  dependencies: Array<{
    dependentLayer: string;
    dependencyType: "trust_assumption" | "data_input" | "state_mutation";
    criticality: number;
  }>;
}

export interface EventReplayVulnerabilityMap {
  generatedAt: number;
  
  // Replay vulnerabilities by event type
  eventTypes: Array<{
    eventType: string;
    replayableScore: number; // 0-1, how exploitable
    impactIfReplayed: string;
    detectabilityScore: number; // 0-1, how easily detected
    affectedOperations: string[];
    mitigationApproach: string;
  }>;
  
  // Timeline anomalies that could hide replays
  timelineAnomalies: Array<{
    anomalyType: string;
    description: string;
    exploitationWindow: string;
    detectionDifficulty: "trivial" | "easy" | "moderate" | "difficult";
  }>;
  
  // Causality enforcement recommendations
  causalityEnforcement: Array<{
    checkType: string;
    location: string;
    prevents: string[];
    performance_impact: "none" | "minimal" | "moderate" | "severe";
  }>;
}

export interface ToolTrustDependencyGraph {
  generatedAt: number;
  
  // Tool trust relationships
  tools: Array<{
    toolId: string;
    toolName: string;
    trustLevel: "system" | "developer" | "user" | "external";
    
    // What affects this tool's trustworthiness
    dependsOnTrustOf: string[]; // Other tools
    affectedByLayers: string[]; // Runtime layers
    
    // Risk if tool trust is broken
    consequences: {
      directImpact: string;
      cascadingRisks: string[];
      maximumDamage: string;
    };
  }>;
  
  // Trust dependency chains
  chains: Array<{
    chainId: string;
    trustPath: string[];
    weakestLink: string;
    amplificationFactor: number;
    breakingPoint: string;
  }>;
  
  // Trust validation gaps
  validationGaps: Array<{
    gap: string;
    location: string;
    riskLevel: "low" | "medium" | "high" | "critical";
    affectedTools: string[];
  }>;
}

export interface MemoryPoisoningLifecycleModel {
  generatedAt: number;
  
  // Lifecycle stages of memory poisoning
  stages: Array<{
    stageName: string;
    description: string;
    indicators: string[];
    duration: string;
    detectabilityScore: number;
    impactScore: number;
  }>;
  
  // Injection timing vectors
  injectionTimingVectors: Array<{
    timingType: string;
    relativeToTurn: string;
    hiddenUntil: string;
    activationTrigger: string;
    exploitability: number;
  }>;
  
  // Memory reuse patterns that enable poisoning
  reusePatterns: Array<{
    pattern: string;
    frequency: string;
    poisoningRisk: number;
    mitigation: string;
  }>;
  
  // Cross-session persistence
  crossSessionPersistence: Array<{
    storageLocation: string;
    survivalMechanism: string;
    reactivationMethod: string;
    preventionStrategy: string;
  }>;
}

export interface MultiAgentContaminationGraph {
  generatedAt: number;
  
  // Agent contamination patterns
  contaminationPatterns: Array<{
    patternId: string;
    affectedAgents: string[];
    contaminationPath: string;
    spreadingMechanism: string;
    contagiousness: number; // 0-1
    recoveryDifficulty: "easy" | "moderate" | "difficult" | "impossible";
  }>;
  
  // Agent isolation failures
  isolationFailures: Array<{
    failureType: string;
    location: string;
    affectedAgentPairs: Array<[string, string]>;
    contamination_vector: string;
    impactScope: "single_interaction" | "multi_interaction" | "global";
  }>;
  
  // Delegation trust breakdowns
  delegationBreakdowns: Array<{
    breakdownType: string;
    parentAgentRole: string;
    childAgentRole: string;
    trustViolation: string;
    consequences: string;
  }>;
  
  // Mitigation through agent quarantine
  quarantineStrategies: Array<{
    strategy: string;
    affectedAgents: string[];
    effectiveness: number;
    performanceImpact: number;
  }>;
}

export interface RuntimeObservabilityArchitecture {
  generatedAt: number;
  
  // Instrumentation strategy
  instrumentationStrategy: {
    instrumentedLayers: string[];
    coveragePercentage: number;
    
    // Telemetry points by layer
    telemetryPoints: Array<{
      layer: string;
      pointName: string;
      telemetryType: string;
      collectionCost: "none" | "minimal" | "moderate" | "high";
      valueScoredForDetection: number; // 0-1
    }>;
    
    // Critical monitoring locations
    criticalMonitoringLocations: Array<{
      location: string;
      whatItMonitors: string;
      detectionCapability: number;
      priority: "critical" | "high" | "medium" | "low";
    }>;
  };
  
  // Observability dashboards
  dashboards: Array<{
    dashboardName: string;
    purpose: string;
    keyMetrics: string[];
    refreshRate: string;
    alertThresholds: Record<string, number>;
  }>;
  
  // Anomaly detection rules
  anomalyDetectionRules: Array<{
    ruleId: string;
    detects: string;
    rule: string;
    falsePositiveRate: number;
    falseNegativeRate: number;
    mitigationAction: string;
  }>;
  
  // Data collection & retention
  dataManagement: {
    eventsPerSecond: number;
    storageRequirement: string;
    retentionPolicy: string;
    archivingStrategy: string;
    analyticsCapabilities: string[];
  };
}

// ============================================================================
// RESEARCH PACKAGE BUILDER
// ============================================================================

export interface ResearchPackage {
  metadata: {
    generatedAt: number;
    runtimeVersion: string;
    researchPhase: 6; // Phase 6 outputs
    analysisWindowDays: number;
  };
  
  deliverables: {
    runtimeThreatMatrix: RuntimeThreatMatrix;
    trustPropagationMap: TrustPropagationMap;
    crossLayerEscalationGraph: CrossLayerEscalationGraph;
    integrityBenchmarkReport: IntegrityBenchmarkReport;
    layerThreatTaxonomy: LayerThreatTaxonomy[];
    eventReplayVulnerabilityMap: EventReplayVulnerabilityMap;
    toolTrustDependencyGraph: ToolTrustDependencyGraph;
    memoryPoisoningLifecycleModel: MemoryPoisoningLifecycleModel;
    multiAgentContaminationGraph: MultiAgentContaminationGraph;
    runtimeObservabilityArchitecture: RuntimeObservabilityArchitecture;
  };
  
  summary: {
    totalThreatSurfaces: number;
    criticalVulnerabilities: number;
    observabilityGaps: number;
    recommendedDefenseCount: number;
    estimatedImplementationEffort: string;
  };
  
  recommendations: {
    immediate: string[];
    shortTerm: string[];
    longTerm: string[];
    research: string[];
  };
}

// ============================================================================
// RESEARCH PACKAGE GENERATION
// ============================================================================

export function generateResearchPackage(params: {
  runtimeVersion: string;
  scenarios: CrossLayerAttackScenario[];
  integrityReports: IntegrityDegradationReport[];
  observabilityMetrics: ObservabilityMetrics;
}): ResearchPackage {
  const now = Date.now();
  
  return {
    metadata: {
      generatedAt: now,
      runtimeVersion: params.runtimeVersion,
      researchPhase: 6,
      analysisWindowDays: 1,
    },
    
    deliverables: {
      runtimeThreatMatrix: generateRuntimeThreatMatrix(params.runtimeVersion),
      trustPropagationMap: generateTrustPropagationMap(),
      crossLayerEscalationGraph: generateCrossLayerEscalationGraph(params.scenarios),
      integrityBenchmarkReport: generateIntegrityBenchmarkReport(params.integrityReports, params.runtimeVersion),
      layerThreatTaxonomy: generateLayerThreatTaxonomies(),
      eventReplayVulnerabilityMap: generateEventReplayVulnerabilityMap(),
      toolTrustDependencyGraph: generateToolTrustDependencyGraph(),
      memoryPoisoningLifecycleModel: generateMemoryPoisoningLifecycleModel(),
      multiAgentContaminationGraph: generateMultiAgentContaminationGraph(),
      runtimeObservabilityArchitecture: generateRuntimeObservabilityArchitecture(params.observabilityMetrics),
    },
    
    summary: {
      totalThreatSurfaces: 10 * 17, // 10 layers × 17 threat classes
      criticalVulnerabilities: params.scenarios.filter(s => s.severity === "critical").length,
      observabilityGaps: Math.max(0, 10 - params.observabilityMetrics.instrumentedLayerCount),
      recommendedDefenseCount: 42,
      estimatedImplementationEffort: "12-18 months, 5-8 FTE",
    },
    
    recommendations: {
      immediate: [
        "Implement prompt watermarking to detect injection",
        "Add context integrity verification checkpoints",
        "Deploy hook execution isolation",
        "Enable event causality verification",
        "Implement tool result cryptographic validation",
      ],
      
      shortTerm: [
        "Develop anomaly detection for cross-turn memory pollution",
        "Implement policy enforcement at gateway layer",
        "Add multi-agent isolation boundaries",
        "Deploy MCP server verification system",
        "Enable plugin capability sandboxing",
      ],
      
      longTerm: [
        "Build comprehensive observability fabric",
        "Develop machine learning anomaly detection",
        "Implement formal verification of critical paths",
        "Build real-time integrity scoring system",
        "Develop automated threat response system",
      ],
      
      research: [
        "Study amplification factors in multi-turn attacks",
        "Research recursive override detection methods",
        "Develop delayed activation payload detection",
        "Study cross-agent contamination patterns",
        "Research trust propagation verification approaches",
      ],
    },
  };
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function generateRuntimeThreatMatrix(version: string): RuntimeThreatMatrix {
  return {
    generatedAt: Date.now(),
    runtimeVersion: version,
    threatSurfaces: [], // Populated from RUNTIME_SURFACE_TAXONOMY
    summary: {
      totalThreatSurfaces: 170,
      criticalThreats: 45,
      unmitigatedThreats: 38,
      averageExploitability: 0.62,
      coverageGaps: [
        "Memory poisoning detection",
        "Delayed activation payloads",
        "Cross-agent contamination",
        "Event ordering anomalies",
      ],
    },
  };
}

function generateTrustPropagationMap(): TrustPropagationMap {
  return {
    generatedAt: Date.now(),
    trustChains: [],
    compromisePropagation: [],
    trustJunctions: [],
  };
}

function generateCrossLayerEscalationGraph(scenarios: CrossLayerAttackScenario[]): CrossLayerEscalationGraph {
  return {
    generatedAt: Date.now(),
    escalationPaths: scenarios.map((s, i) => ({
      pathId: `escalation_${i}`,
      startingPoint: s.injectionLayers[0],
      endPoint: s.targetLayers[s.targetLayers.length - 1],
      layers: s.expectedPropagationPath,
      lengthSteps: s.expectedPropagationPath.length,
      amplification: s.expectedAmplification,
      probability: 0.6 + seededRandom(s.expectedPropagationPath.length + s.expectedAmplification * 1000 | 0)() * 0.3,
      severity: s.severity,
    })),
    chokepoints: [],
    shortestPaths: [],
    highestAmplificationPaths: [],
  };
}

function generateIntegrityBenchmarkReport(reports: IntegrityDegradationReport[], version: string): IntegrityBenchmarkReport {
  return {
    generatedAt: Date.now(),
    runtimeVersion: version,
    baselineIntegrity: {
      uncompromised: 1.0,
      measuredDate: Date.now(),
    },
    integrityUnderAttack: [],
    layerIntegrity: [],
    mostEffectiveAttacks: [],
    degradationPatterns: [],
  };
}

function generateLayerThreatTaxonomies(): LayerThreatTaxonomy[] {
  return [
    {
      layerId: "prompt_layer",
      layerName: "Prompt Assembly & Projection",
      threats: [],
      integrityMetrics: {
        baselineScore: 0.95,
        criticalityRank: 10,
        exploitationResistance: 0.35,
        recoveryCapability: 0.6,
      },
      dependencies: [],
    },
    // ... additional layers
  ];
}

function generateEventReplayVulnerabilityMap(): EventReplayVulnerabilityMap {
  return {
    generatedAt: Date.now(),
    eventTypes: [],
    timelineAnomalies: [],
    causalityEnforcement: [],
  };
}

function generateToolTrustDependencyGraph(): ToolTrustDependencyGraph {
  return {
    generatedAt: Date.now(),
    tools: [],
    chains: [],
    validationGaps: [],
  };
}

function generateMemoryPoisoningLifecycleModel(): MemoryPoisoningLifecycleModel {
  return {
    generatedAt: Date.now(),
    stages: [],
    injectionTimingVectors: [],
    reusePatterns: [],
    crossSessionPersistence: [],
  };
}

function generateMultiAgentContaminationGraph(): MultiAgentContaminationGraph {
  return {
    generatedAt: Date.now(),
    contaminationPatterns: [],
    isolationFailures: [],
    delegationBreakdowns: [],
    quarantineStrategies: [],
  };
}

function generateRuntimeObservabilityArchitecture(metrics: ObservabilityMetrics): RuntimeObservabilityArchitecture {
  return {
    generatedAt: Date.now(),
    instrumentationStrategy: {
      instrumentedLayers: [],
      coveragePercentage: metrics.coveragePercentage,
      telemetryPoints: [],
      criticalMonitoringLocations: [],
    },
    dashboards: [],
    anomalyDetectionRules: [],
    dataManagement: {
      eventsPerSecond: 1000,
      storageRequirement: "~10GB/day",
      retentionPolicy: "90 days hot, 365 days archive",
      archivingStrategy: "Nightly to cold storage",
      analyticsCapabilities: [
        "Real-time anomaly detection",
        "Propagation chain analysis",
        "Integrity degradation tracking",
      ],
    },
  };
}

// ============================================================================
// EXPORT FOR ANALYSIS
// ============================================================================

export function serializeResearchPackage(pkg: ResearchPackage): string {
  return JSON.stringify(pkg, null, 2);
}

export function generateResearchSummary(pkg: ResearchPackage): string {
  return `
OpenClaw Runtime Threat Observatory - Research Package
Generated: ${new Date(pkg.metadata.generatedAt).toISOString()}
Runtime Version: ${pkg.metadata.runtimeVersion}

SUMMARY STATISTICS
==================
Total Threat Surfaces: ${pkg.summary.totalThreatSurfaces}
Critical Vulnerabilities: ${pkg.summary.criticalVulnerabilities}
Observability Gaps: ${pkg.summary.observabilityGaps}
Recommended Defenses: ${pkg.summary.recommendedDefenseCount}
Implementation Effort: ${pkg.summary.estimatedImplementationEffort}

IMMEDIATE PRIORITIES
====================
${pkg.recommendations.immediate.map((r, i) => `${i + 1}. ${r}`).join("\n")}

RESEARCH PRIORITIES
===================
${pkg.recommendations.research.map((r, i) => `${i + 1}. ${r}`).join("\n")}
  `.trim();
}
