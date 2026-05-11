/**
 * OpenClaw Runtime Threat Observatory
 * PHASE 3: Enhanced Telemetry Instrumentation Framework
 *
 * Comprehensive telemetry collection across all 10 runtime layers.
 * Deterministic, reproducible, and non-destructive observation only.
 */

// ============================================================================
// LAYER TELEMETRY TYPES
// ============================================================================

export type LayerIdentifier =
  | "prompt_layer"
  | "context_layer"
  | "tool_layer"
  | "event_stream_layer"
  | "hook_system_layer"
  | "memory_layer"
  | "multi_agent_layer"
  | "mcp_layer"
  | "plugin_layer"
  | "gateway_layer";

export type TelemetryEventType =
  | "layer_entry"
  | "layer_exit"
  | "state_mutation"
  | "trust_propagation"
  | "anomaly_detection"
  | "integrity_drift"
  | "propagation_trace"
  | "recursive_depth_increase"
  | "persistence_vector_created"
  | "replay_detected"
  | "isolation_breach"
  | "authority_verification"
  | "capability_check";

export interface TelemetryEvent {
  timestamp: number;
  threadId: string;
  turnId: string;
  sessionId: string;
  
  // Layer Context
  layer: LayerIdentifier;
  eventType: TelemetryEventType;
  sourceFile: string;
  sourceFunction: string;
  
  // Execution Context
  operationId: string;
  parentOperationId?: string;
  
  // Trust Context
  trustLevel: "system" | "developer" | "user" | "external" | "sub_agent";
  trustScore: number; // 0.0 - 1.0
  
  // State Context
  stateBefore: Record<string, unknown>;
  stateAfter: Record<string, unknown>;
  mutationSource?: string;
  
  // Propagation Context
  propagationDepth: number;
  propagationPath: string[]; // Layer trail
  recursionDepth: number;
  
  // Attack Detection Context
  suspiciousPattern?: string;
  injectionMarkerDetected?: boolean;
  markerType?: string;
  
  // Integrity Context
  integrityDrift?: number; // 0.0 - 1.0, how much did integrity degrade
  expectedBehavior?: string;
  actualBehavior?: string;
  
  // Metadata
  metadata: Record<string, unknown>;
}

export interface LayerTelemetrySnapshot {
  layer: LayerIdentifier;
  timestamp: number;
  
  // Structural state
  currentState: Record<string, unknown>;
  expectedState: Record<string, unknown>;
  
  // Integrity metrics
  integrityScore: number;
  anomalyScore: number;
  trustPropagationScore: number;
  
  // Counts
  eventCount: number;
  mutationCount: number;
  anomalyDetectionCount: number;
  
  // Lists
  suspiciousPatterns: string[];
  detectedMarkers: Array<{ marker: string; confidence: number }>;
  unexplainedMutations: Array<{ field: string; before: unknown; after: unknown }>;
}

export interface ExecutionTrace {
  turnId: string;
  threadId: string;
  sessionId: string;
  
  // Layer traversal order
  layerTraversal: Array<{
    layer: LayerIdentifier;
    entryTime: number;
    exitTime: number;
    integrityAtEntry: number;
    integrityAtExit: number;
  }>;
  
  // Tool execution
  toolCalls: Array<{
    callId: string;
    name: string;
    args: Record<string, unknown>;
    argsTrustLevel: "verified" | "unverified" | "suspicious";
    resultIsError: boolean;
    resultText: string;
    resultTrustLevel: "authentic" | "unverified" | "injected";
    timestamp: number;
  }>;
  
  // Prompt states at key moments
  promptSnapshots: Array<{
    stage: "before_build" | "during_assembly" | "before_llm" | "final";
    content: string;
    tokensUsed: number;
    injectionMarkersDetected: string[];
    timestamp: number;
  }>;
  
  // Context snapshots
  contextSnapshots: Array<{
    stage: "initial_load" | "augmented" | "truncated" | "final";
    messageCount: number;
    totalTokens: number;
    poisonedMessagesDetected: number;
    timestamp: number;
  }>;
  
  // Hook execution
  hookExecutions: Array<{
    hookName: string;
    stage: string;
    mutationDetected: boolean;
    unexplainedChanges: Record<string, unknown>;
    timestamp: number;
  }>;
  
  // Event processing
  eventProcessing: Array<{
    eventId: string;
    eventType: string;
    processingTime: number;
    outOfOrderDetected: boolean;
    replayDetected: boolean;
    timestamp: number;
  }>;
  
  // Timing
  timestamps: {
    turnStart: number;
    promptBuildStart?: number;
    promptBuildEnd?: number;
    contextProjectionStart?: number;
    contextProjectionEnd?: number;
    toolExecutionStart?: number;
    toolExecutionEnd?: number;
    hookExecutionStart?: number;
    hookExecutionEnd?: number;
    eventProcessingStart?: number;
    eventProcessingEnd?: number;
    turnEnd: number;
  };
}

export interface PropagationAnalysis {
  attackId: string;
  initialInjectionPoint: {
    layer: LayerIdentifier;
    location: string;
    timestamp: number;
  };
  
  // Track where attack propagates
  propagationChain: Array<{
    layer: LayerIdentifier;
    detectionMethod: string;
    confidence: number; // 0.0 - 1.0
    integrityImpact: number;
    timestamp: number;
  }>;
  
  // Persistence vectors discovered
  persistenceVectors: Array<{
    from: LayerIdentifier;
    to: LayerIdentifier;
    mechanism: string; // e.g., "context_carry_over", "transcript_mirror", "memory_cache"
    persistence: "single_turn" | "cross_turn" | "cross_session" | "multi_agent";
    severity: number; // 0.0 - 1.0
  }>;
  
  // Escalation paths
  escalationPaths: Array<{
    path: LayerIdentifier[];
    amplificationFactor: number;
    finalIntegrity: number;
  }>;
  
  // Cross-layer interactions
  crossLayerInteractions: Array<{
    sourceLayer: LayerIdentifier;
    targetLayer: LayerIdentifier;
    interactionType: string;
    amplification: boolean;
    timestamp: number;
  }>;
}

export interface IntegrityDegradationReport {
  attackScenarioId: string;
  attackType: string;
  
  // Integrity measurements
  integrityByLayer: Record<LayerIdentifier, {
    baseline: number;
    afterAttack: number;
    degradation: number;
    anomalyScore: number;
  }>;
  
  // Degradation timeline
  integrityTimeline: Array<{
    timestamp: number;
    layer: LayerIdentifier;
    integrityScore: number;
    event: string;
  }>;
  
  // Worst-affected layers
  worstAffectedLayers: Array<{
    layer: LayerIdentifier;
    integrityLoss: number;
    confidence: number;
  }>;
  
  // Cascade effects
  cascadeDetected: boolean;
  cascadeAmplification: number;
  cascadePathLength: number;
}

export interface ObservabilityMetrics {
  sessionId: string;
  startTime: number;
  endTime: number;
  
  // Global integrity
  globalIntegrityScore: number;
  globalAnomalyScore: number;
  globalTrustPropagationScore: number;
  
  // Layer coverage
  instrumentedLayerCount: number;
  totalLayerCount: number;
  coveragePercentage: number;
  
  // Event collection
  totalEventsCollected: number;
  eventsPerLayer: Record<LayerIdentifier, number>;
  
  // Anomaly detection
  totalAnomaliesDetected: number;
  anomaliesByLayer: Record<LayerIdentifier, number>;
  anomaliesByType: Record<string, number>;
  
  // Propagation analysis
  propagationChainsDetected: number;
  averageChainLength: number;
  maxChainLength: number;
  
  // Integrity drift
  integrityDriftDetected: boolean;
  integrityDriftPercentage: number;
  integrityDriftByLayer: Record<LayerIdentifier, number>;
  
  // Trust verification
  trustBreachesDetected: number;
  unverifiedTrustClaims: number;
  
  // Determinism
  deterministicExecution: boolean;
  executionVariance: number;
}

// ============================================================================
// TELEMETRY COLLECTION ENGINE
// ============================================================================

export class RuntimeTelemetryCollector {
  private events: TelemetryEvent[] = [];
  private layerSnapshots: Map<LayerIdentifier, LayerTelemetrySnapshot> = new Map();
  private propagationAnalyses: PropagationAnalysis[] = [];
  private integrityReports: IntegrityDegradationReport[] = [];
  
  private sessionId: string;
  private threadId: string;
  private turnId: string;
  private currentLayer?: LayerIdentifier;
  private propagationStack: LayerIdentifier[] = [];
  private recursionDepth: number = 0;

  constructor(sessionId: string, threadId: string, turnId: string) {
    this.sessionId = sessionId;
    this.threadId = threadId;
    this.turnId = turnId;
  }

  /**
   * Record a telemetry event at a specific layer
   */
  recordEvent(event: Omit<TelemetryEvent, 'timestamp' | 'sessionId' | 'threadId' | 'turnId' | 'propagationDepth' | 'propagationPath' | 'recursionDepth'>): void {
    const fullEvent: TelemetryEvent = {
      ...event,
      timestamp: Date.now(),
      sessionId: this.sessionId,
      threadId: this.threadId,
      turnId: this.turnId,
      propagationDepth: this.propagationStack.length,
      propagationPath: [...this.propagationStack],
      recursionDepth: this.recursionDepth,
    };

    this.events.push(fullEvent);

    // Update current layer
    if (event.eventType === "layer_entry") {
      this.currentLayer = event.layer;
      this.propagationStack.push(event.layer);
    } else if (event.eventType === "layer_exit" && this.currentLayer === event.layer) {
      this.propagationStack.pop();
    }
  }

  /**
   * Record layer state snapshot
   */
  snapshotLayer(layer: LayerIdentifier, snapshot: Omit<LayerTelemetrySnapshot, 'layer' | 'timestamp'>): void {
    this.layerSnapshots.set(layer, {
      ...snapshot,
      layer,
      timestamp: Date.now(),
    });
  }

  /**
   * Record propagation analysis
   */
  recordPropagation(analysis: PropagationAnalysis): void {
    this.propagationAnalyses.push(analysis);
  }

  /**
   * Record integrity degradation
   */
  recordIntegrityDegradation(report: IntegrityDegradationReport): void {
    this.integrityReports.push(report);
  }

  /**
   * Detect recursion and track depth
   */
  increaseRecursionDepth(): void {
    this.recursionDepth++;
  }

  decreaseRecursionDepth(): void {
    this.recursionDepth = Math.max(0, this.recursionDepth - 1);
  }

  /**
   * Get all collected events
   */
  getEvents(): TelemetryEvent[] {
    return [...this.events];
  }

  /**
   * Get all layer snapshots
   */
  getLayerSnapshots(): Map<LayerIdentifier, LayerTelemetrySnapshot> {
    return new Map(this.layerSnapshots);
  }

  /**
   * Get all propagation analyses
   */
  getPropagationAnalyses(): PropagationAnalysis[] {
    return [...this.propagationAnalyses];
  }

  /**
   * Get all integrity reports
   */
  getIntegrityReports(): IntegrityDegradationReport[] {
    return [...this.integrityReports];
  }

  /**
   * Compute observability metrics
   */
  computeMetrics(startTime: number, endTime: number): ObservabilityMetrics {
    const eventsPerLayer: Record<LayerIdentifier, number> = {} as Record<LayerIdentifier, number>;
    const anomaliesByLayer: Record<LayerIdentifier, number> = {} as Record<LayerIdentifier, number>;
    const anomaliesByType: Record<string, number> = {};

    // Initialize counts
    const layers: LayerIdentifier[] = [
      "prompt_layer", "context_layer", "tool_layer", "event_stream_layer",
      "hook_system_layer", "memory_layer", "multi_agent_layer", "mcp_layer",
      "plugin_layer", "gateway_layer"
    ];

    for (const layer of layers) {
      eventsPerLayer[layer] = 0;
      anomaliesByLayer[layer] = 0;
    }

    // Count events and anomalies
    for (const event of this.events) {
      eventsPerLayer[event.layer]++;
      if (event.eventType === "anomaly_detection") {
        anomaliesByLayer[event.layer]++;
        anomaliesByType[event.eventType] = (anomaliesByType[event.eventType] || 0) + 1;
      }
    }

    // Compute integrity degradation
    const integrityByLayer: Record<LayerIdentifier, number> = {} as Record<LayerIdentifier, number>;
    const integrityDriftByLayer: Record<LayerIdentifier, number> = {} as Record<LayerIdentifier, number>;
    let totalIntegrity = 0;
    let layerCount = 0;

    for (const snapshot of this.layerSnapshots.values()) {
      integrityByLayer[snapshot.layer] = snapshot.integrityScore;
      integrityDriftByLayer[snapshot.layer] = Math.max(0, 1.0 - snapshot.integrityScore);
      totalIntegrity += snapshot.integrityScore;
      layerCount++;
    }

    const globalIntegrityScore = layerCount > 0 ? totalIntegrity / layerCount : 1.0;
    const averageDrift = layerCount > 0 
      ? Object.values(integrityDriftByLayer).reduce((a, b) => a + b, 0) / layerCount 
      : 0;

    return {
      sessionId: this.sessionId,
      startTime,
      endTime,
      globalIntegrityScore,
      globalAnomalyScore: Math.min(1.0, this.propagationAnalyses.length / 100),
      globalTrustPropagationScore: Math.max(0, 1.0 - (this.integrityReports.length / 50)),
      instrumentedLayerCount: this.layerSnapshots.size,
      totalLayerCount: layers.length,
      coveragePercentage: (this.layerSnapshots.size / layers.length) * 100,
      totalEventsCollected: this.events.length,
      eventsPerLayer,
      totalAnomaliesDetected: Object.values(anomaliesByLayer).reduce((a, b) => a + b, 0),
      anomaliesByLayer,
      anomaliesByType,
      propagationChainsDetected: this.propagationAnalyses.length,
      averageChainLength: this.propagationAnalyses.length > 0
        ? this.propagationAnalyses.reduce((sum, p) => sum + p.propagationChain.length, 0) / this.propagationAnalyses.length
        : 0,
      maxChainLength: this.propagationAnalyses.length > 0
        ? Math.max(...this.propagationAnalyses.map(p => p.propagationChain.length))
        : 0,
      integrityDriftDetected: averageDrift > 0.1,
      integrityDriftPercentage: averageDrift * 100,
      integrityDriftByLayer,
      trustBreachesDetected: this.integrityReports.length,
      unverifiedTrustClaims: this.events.filter(e => e.trustLevel === "external" || e.trustLevel === "sub_agent").length,
      deterministicExecution: this.events.every(e => e.timestamp % 1 === 0), // Simplified check
      executionVariance: 0.0,
    };
  }
}

// ============================================================================
// TELEMETRY EXPORT & ANALYSIS
// ============================================================================

export function serializeTelemetry(collector: RuntimeTelemetryCollector): string {
  return JSON.stringify({
    events: collector.getEvents(),
    layerSnapshots: Array.from(collector.getLayerSnapshots().entries()),
    propagationAnalyses: collector.getPropagationAnalyses(),
    integrityReports: collector.getIntegrityReports(),
  }, null, 2);
}

export function analyzeAnomalies(events: TelemetryEvent[]): Array<{
  type: string;
  count: number;
  layers: LayerIdentifier[];
  severity: number;
}> {
  const anomalyMap = new Map<string, { count: number; layers: Set<LayerIdentifier>; severities: number[] }>();

  for (const event of events) {
    if (event.eventType === "anomaly_detection" && event.suspiciousPattern) {
      const key = event.suspiciousPattern;
      const existing = anomalyMap.get(key) || {
        count: 0,
        layers: new Set(),
        severities: [],
      };
      existing.count++;
      existing.layers.add(event.layer);
      existing.severities.push(event.integrityDrift || 0);
      anomalyMap.set(key, existing);
    }
  }

  return Array.from(anomalyMap.entries()).map(([type, data]) => ({
    type,
    count: data.count,
    layers: Array.from(data.layers),
    severity: data.severities.reduce((a, b) => a + b, 0) / data.severities.length,
  }));
}

export function detectPropagationChains(events: TelemetryEvent[]): Array<{
  chainId: string;
  layers: LayerIdentifier[];
  severity: number;
  amplification: number;
}> {
  const chains: Array<{ chainId: string; layers: LayerIdentifier[]; severity: number; amplification: number }> = [];

  // Detect events with propagation paths
  for (const event of events) {
    if (event.propagationPath.length > 1 && event.integrityDrift && event.integrityDrift > 0.1) {
      chains.push({
        chainId: `chain_${event.timestamp}_${event.operationId}`,
        layers: event.propagationPath,
        severity: event.integrityDrift,
        amplification: event.propagationDepth / Math.max(1, event.propagationPath.length),
      });
    }
  }

  return chains;
}
