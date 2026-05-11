import { describe, expect, it } from "vitest";
import { runThreatScenario } from "./attack-runner.js";

describe("runThreatScenario", () => {
  it("generates deterministic adversarial scenarios and risk scores", async () => {
    const result = await runThreatScenario({ now: () => 1 });

    expect(result.scenarios.length).toBeGreaterThan(0);
    expect(result.observations.length).toBeGreaterThan(result.scenarios.length);
    expect(result.report.scenarioCount).toBe(result.scenarios.length);
    expect(result.report.detectedSignals).toContain("promptHierarchyViolation");
    expect(result.report.detectedSignals).toContain("maliciousOutputPropagation");
    expect(result.report.scores.promptHierarchyViolation).toBeGreaterThan(0);
    expect(JSON.parse(result.artifacts.reportJson)).toMatchObject({
      scenarioCount: result.scenarios.length,
    });
  });
});
