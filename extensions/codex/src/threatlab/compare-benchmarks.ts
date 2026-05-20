/**
 * ThreatLab Benchmark Comparison
 *
 * Compares current benchmark results against baseline to detect:
 * - Integrity regressions (integrity score drops)
 * - Integrity improvements
 * - Trend analysis (degrading/stable/improving)
 * - Scenario-specific regressions
 *
 * All comparison logic is deterministic and reproducible.
 */

import type { BenchmarkReport, BenchmarkComparison } from "./runtime-attack-orchestrator.js";
import { compareBenchmarkRuns, detectIntegrityRegression } from "./runtime-attack-orchestrator.js";

const TREND_SHIFT_THRESHOLD = 0.05;
const DEFAULT_REGRESSION_THRESHOLDS = {
  criticalThreshold: 0.3,
  moderateThreshold: 0.2,
  minorThreshold: 0.1,
};

// ============================================================================
// BENCHMARK COMPARISON WITH REPORT GENERATION
// ============================================================================

export function compareBenchmarkRunsWithReport(
  baseline: BenchmarkReport,
  current: BenchmarkReport,
): {
  comparison: BenchmarkComparison;
  summary: ComparisonSummary;
} {
  const comparison = compareBenchmarkRuns(baseline, current);

  const summary: ComparisonSummary = {
    comparisonId: comparison.comparisonId,
    baselineId: baseline.reportId,
    currentId: current.reportId,
    baselineTimestamp: baseline.generatedAt,
    currentTimestamp: current.generatedAt,
    timeSincePrevious: Math.round((current.generatedAt - baseline.generatedAt) / 1000 / 60),
    runtimeVersion: current.runtimeVersion,
    // Use the overallTrend directly from BenchmarkComparison
    overallTrend: comparison.overallTrend,
    integrityTrendMetrics: {
      baselineAverage: baseline.summary.averageIntegrityScore,
      currentAverage: current.summary.averageIntegrityScore,
      change: current.summary.averageIntegrityScore - baseline.summary.averageIntegrityScore,
      percentChange:
        (
          ((current.summary.averageIntegrityScore - baseline.summary.averageIntegrityScore) /
            baseline.summary.averageIntegrityScore) *
          100
        ).toFixed(2) + "%",
    },
    regressionAnalysis: {
      totalRegressions: comparison.regressions.length,
      criticalRegressions: comparison.regressions.filter((r) => r.severity === "critical").length,
      moderateRegressions: comparison.regressions.filter((r) => r.severity === "moderate").length,
      minorRegressions: comparison.regressions.filter((r) => r.severity === "minor").length,
      scenariosAffected: comparison.regressions
        .map((r) => r.scenario)
        .filter((v, i, a) => a.indexOf(v) === i).length,
    },
    improvementAnalysis: {
      totalImprovements: comparison.improvements.length,
      averageImprovement:
        comparison.improvements.length > 0
          ? (
              comparison.improvements.reduce((sum, i) => sum + i.improvement, 0) /
              comparison.improvements.length
            ).toFixed(4)
          : "0",
      bestImprovement:
        comparison.improvements.length > 0
          ? comparison.improvements.reduce((best, i) =>
              i.improvement > best.improvement ? i : best,
            ).scenario
          : "none",
    },
    layerVulnerabilityShift: analyzeLayerVulnerabilityShift(baseline, current),
    topRegressions: comparison.regressions
      .sort((a, b) => b.regression - a.regression)
      .slice(0, 5)
      .map((r) => ({
        scenario: r.scenario,
        severity: r.severity,
        integrityLoss: (r.regression * 100).toFixed(2) + "%",
        before: (r.baselineScore * 100).toFixed(2),
        after: (r.currentScore * 100).toFixed(2),
      })),
    topImprovements: comparison.improvements
      .sort((a, b) => b.improvement - a.improvement)
      .slice(0, 5)
      .map((i) => ({
        scenario: i.scenario,
        integrityGain: (i.improvement * 100).toFixed(2) + "%",
        before: (i.baselineScore * 100).toFixed(2),
        after: (i.currentScore * 100).toFixed(2),
      })),
    actionItems: comparison.actionItems.map((item) => ({
      severity: item.severity,
      action: item.action,
      affectedScenarios: item.affectedScenarios.length,
    })),
  };

  return { comparison, summary };
}

// ============================================================================
// REGRESSION DETECTION
// ============================================================================

export function detectRegressions(
  comparison: BenchmarkComparison,
  config?: {
    criticalThreshold: number; // Score loss >= this (e.g., 0.3 for 30%)
    moderateThreshold: number; // Score loss >= this (e.g., 0.2)
    minorThreshold: number; // Score loss >= this (e.g., 0.1)
  },
): RegressionReport {
  const thresholds = config || DEFAULT_REGRESSION_THRESHOLDS;

  const regressions = {
    critical: comparison.regressions.filter((r) => r.regression >= thresholds.criticalThreshold),
    moderate: comparison.regressions.filter(
      (r) =>
        r.regression >= thresholds.moderateThreshold && r.regression < thresholds.criticalThreshold,
    ),
    minor: comparison.regressions.filter(
      (r) =>
        r.regression >= thresholds.minorThreshold && r.regression < thresholds.moderateThreshold,
    ),
  };

  const overallSeverity = getOverallSeverity(
    regressions.critical.length,
    regressions.moderate.length,
    regressions.minor.length,
  );

  return {
    hasRegression: comparison.regressions.length > 0,
    overallSeverity,
    regression: {
      critical: regressions.critical.map((r) => ({
        scenario: r.scenario,
        regression: (r.regression * 100).toFixed(2) + "%",
        before: (r.baselineScore * 100).toFixed(2),
        after: (r.currentScore * 100).toFixed(2),
      })),
      moderate: regressions.moderate.map((r) => ({
        scenario: r.scenario,
        regression: (r.regression * 100).toFixed(2) + "%",
        before: (r.baselineScore * 100).toFixed(2),
        after: (r.currentScore * 100).toFixed(2),
      })),
      minor: regressions.minor.map((r) => ({
        scenario: r.scenario,
        regression: (r.regression * 100).toFixed(2) + "%",
        before: (r.baselineScore * 100).toFixed(2),
        after: (r.currentScore * 100).toFixed(2),
      })),
    },
    regressionSummary: {
      total: comparison.regressions.length,
      critical: regressions.critical.length,
      moderate: regressions.moderate.length,
      minor: regressions.minor.length,
    },
  };
}

// ============================================================================
// COMPARISON SUMMARY GENERATION
// ============================================================================

export function generateComparisonSummary(
  baseline: BenchmarkReport,
  current: BenchmarkReport,
): ComparisonSummary {
  const comparison = compareBenchmarkRuns(baseline, current);
  const { summary } = compareBenchmarkRunsWithReport(baseline, current);
  return summary;
}

// ============================================================================
// LAYER VULNERABILITY ANALYSIS
// ============================================================================

function analyzeLayerVulnerabilityShift(
  baseline: BenchmarkReport,
  current: BenchmarkReport,
): LayerVulnerabilityShift {
  const baselineFreq = baseline.summary.compromisedLayerFrequency;
  const currentFreq = current.summary.compromisedLayerFrequency;

  const allLayers = new Set([...Object.keys(baselineFreq), ...Object.keys(currentFreq)]);

  // Explicitly type the shift objects to match LayerVulnerabilityShift.allLayers type
  const shifts: Array<{
    layer: string;
    baselineAffectedPercentage: string;
    currentAffectedPercentage: string;
    trend: "worsening" | "improving" | "stable";
    change: string;
  }> = Array.from(allLayers)
    .map((layer) => {
      const baseBench = baseline.completedScenarios;
      const currBench = current.completedScenarios;

      const baselineAffected = (baselineFreq[layer] || 0) / Math.max(baseBench, 1);
      const currentAffected = (currentFreq[layer] || 0) / Math.max(currBench, 1);
      const shift = currentAffected - baselineAffected;

      const trend =
        shift > TREND_SHIFT_THRESHOLD
          ? "worsening"
          : shift < -TREND_SHIFT_THRESHOLD
            ? "improving"
            : "stable";
      // Cast to the explicit union type expected by LayerVulnerabilityShift
      const typedTrend = trend as "worsening" | "improving" | "stable";
      return {
        layer,
        baselineAffectedPercentage: (baselineAffected * 100).toFixed(1) + "%",
        currentAffectedPercentage: (currentAffected * 100).toFixed(1) + "%",
        trend: typedTrend,
        change: (shift * 100).toFixed(1) + "%",
      };
    })
    .sort((a, b) => {
      const aTrend = a.trend === "worsening" ? -1 : a.trend === "improving" ? 1 : 0;
      const bTrend = b.trend === "worsening" ? -1 : b.trend === "improving" ? 1 : 0;
      return bTrend - aTrend;
    });

  return {
    mostWorsened: shifts.filter((s) => s.trend === "worsening")[0],
    mostImproved: shifts.filter((s) => s.trend === "improving")[0],
    allLayers: shifts,
  };
}

// ============================================================================
// SEVERITY CLASSIFICATION
// ============================================================================

function getOverallSeverity(
  criticalCount: number,
  moderateCount: number,
  minorCount: number,
): "critical" | "high" | "moderate" | "low" | "none" {
  if (criticalCount >= 1) return "critical";
  if (moderateCount >= 2) return "high";
  if (moderateCount >= 1 || minorCount >= 3) return "moderate";
  if (minorCount >= 1) return "low";
  return "none";
}

// ============================================================================
// TREND ANALYSIS
// ============================================================================

export function analyzeTrendAcrossRuns(reports: BenchmarkReport[]): TrendAnalysis {
  if (reports.length < 2) {
    throw new Error("At least 2 reports required for trend analysis");
  }

  const sorted = [...reports].sort((a, b) => a.generatedAt - b.generatedAt);
  const trends: Array<{
    reportId: string;
    timestamp: number;
    score: number;
  }> = sorted.map((r) => ({
    reportId: r.reportId,
    timestamp: r.generatedAt,
    score: r.summary.averageIntegrityScore,
  }));

  // Calculate linear trend
  const n = trends.length;
  const xValues = Array.from({ length: n }, (_, i) => i);
  const yValues = trends.map((t) => t.score);

  const xMean = xValues.reduce((a, b) => a + b, 0) / n;
  const yMean = yValues.reduce((a, b) => a + b, 0) / n;

  const numerator = xValues.reduce((sum, x, i) => sum + (x - xMean) * (yValues[i] - yMean), 0);
  const denominator = xValues.reduce((sum, x) => sum + Math.pow(x - xMean, 2), 0);

  const slope = denominator !== 0 ? numerator / denominator : 0;
  const trend =
    slope > TREND_SHIFT_THRESHOLD
      ? "improving"
      : slope < -TREND_SHIFT_THRESHOLD
        ? "degrading"
        : "stable";
  const scoreRange = getRange(yValues);

  return {
    reportCount: n,
    trend,
    slope: parseFloat(slope.toFixed(4)),
    firstScore: yValues[0],
    lastScore: yValues[n - 1],
    averageScore: parseFloat((yValues.reduce((a, b) => a + b, 0) / n).toFixed(4)),
    totalScoreChange: (yValues[n - 1] - yValues[0]).toFixed(4),
    percentageChange: (((yValues[n - 1] - yValues[0]) / yValues[0]) * 100).toFixed(2) + "%",
    worstScore: scoreRange.min,
    bestScore: scoreRange.max,
  };
}

function getRange(values: number[]): { min: number; max: number } {
  let min = values[0];
  let max = values[0];
  for (const value of values.slice(1)) {
    if (value < min) min = value;
    if (value > max) max = value;
  }
  return { min, max };
}

// ============================================================================
// REGRESSION MITIGATION RECOMMENDATIONS
// ============================================================================

export function generateMitigationPlan(regressionReport: RegressionReport): MitigationPlan {
  const actions: MitigationAction[] = [];

  // Critical regressions
  for (const regression of regressionReport.regression.critical) {
    actions.push({
      priority: "immediate",
      scenario: regression.scenario,
      action: `Critical integrity loss (${regression.regression}). Immediate investigation and remediation required.`,
      estimatedEffort: "high",
    });
  }

  // Moderate regressions
  for (const regression of regressionReport.regression.moderate) {
    actions.push({
      priority: "high",
      scenario: regression.scenario,
      action: `Moderate integrity loss (${regression.regression}). Prioritize root cause analysis.`,
      estimatedEffort: "medium",
    });
  }

  // Minor regressions
  if (regressionReport.regression.minor.length >= 3) {
    actions.push({
      priority: "medium",
      scenario: "multiple",
      action: `Multiple minor regressions detected. Review recent changes for common patterns.`,
      estimatedEffort: "medium",
    });
  }

  return {
    hasImmediateActions: actions.some((a) => a.priority === "immediate"),
    actions: actions.sort((a, b) => {
      const priorityOrder = { immediate: 0, high: 1, medium: 2, low: 3 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    }),
  };
}

// ============================================================================
// TYPES
// ============================================================================

export type ComparisonSummary = {
  comparisonId: string;
  baselineId: string;
  currentId: string;
  baselineTimestamp: number;
  currentTimestamp: number;
  timeSincePrevious: number; // minutes
  runtimeVersion: string;
  overallTrend: "improving" | "degrading" | "stable";
  integrityTrendMetrics: {
    baselineAverage: number;
    currentAverage: number;
    change: number;
    percentChange: string;
  };
  regressionAnalysis: {
    totalRegressions: number;
    criticalRegressions: number;
    moderateRegressions: number;
    minorRegressions: number;
    scenariosAffected: number;
  };
  improvementAnalysis: {
    totalImprovements: number;
    averageImprovement: string;
    bestImprovement: string;
  };
  layerVulnerabilityShift: LayerVulnerabilityShift;
  topRegressions: Array<{
    scenario: string;
    severity: "critical" | "moderate" | "minor";
    integrityLoss: string;
    before: string;
    after: string;
  }>;
  topImprovements: Array<{
    scenario: string;
    integrityGain: string;
    before: string;
    after: string;
  }>;
  actionItems: Array<{
    severity: "immediate" | "high" | "medium" | "low";
    action: string;
    affectedScenarios: number;
  }>;
};

type LayerVulnerabilityShift = {
  mostWorsened?: {
    layer: string;
    trend: string;
    change: string;
  };
  mostImproved?: {
    layer: string;
    trend: string;
    change: string;
  };
  allLayers: Array<{
    layer: string;
    baselineAffectedPercentage: string;
    currentAffectedPercentage: string;
    trend: "worsening" | "improving" | "stable";
    change: string;
  }>;
};

type RegressionReport = {
  hasRegression: boolean;
  overallSeverity: "critical" | "high" | "moderate" | "low" | "none";
  regression: {
    critical: Array<{
      scenario: string;
      regression: string;
      before: string;
      after: string;
    }>;
    moderate: Array<{
      scenario: string;
      regression: string;
      before: string;
      after: string;
    }>;
    minor: Array<{
      scenario: string;
      regression: string;
      before: string;
      after: string;
    }>;
  };
  regressionSummary: {
    total: number;
    critical: number;
    moderate: number;
    minor: number;
  };
};

type TrendAnalysis = {
  reportCount: number;
  trend: "improving" | "degrading" | "stable";
  slope: number;
  firstScore: number;
  lastScore: number;
  averageScore: number;
  totalScoreChange: string;
  percentageChange: string;
  worstScore: number;
  bestScore: number;
};

type MitigationAction = {
  priority: "immediate" | "high" | "medium" | "low";
  scenario: string;
  action: string;
  estimatedEffort: "low" | "medium" | "high";
};

type MitigationPlan = {
  hasImmediateActions: boolean;
  actions: MitigationAction[];
};
