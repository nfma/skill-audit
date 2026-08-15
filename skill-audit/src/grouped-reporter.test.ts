import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { reportGroupedResults, shouldBlockResult } from "./grouped-reporter.js";
import { Finding, GroupedAuditResult } from "./types.js";

const fixtureRoots: string[] = [];

function finding(severity: Finding["severity"], category: Finding["category"] = "CE"): Finding {
  return {
    id: "TEST-001",
    category,
    asi: category === "COMP" ? "ASI04" : "ASI05",
    severity,
    file: "/fixture/SKILL.md",
    message: "Regression finding",
  };
}

function result(options: {
  riskScore: number;
  findings?: Finding[];
  complianceFindings?: Finding[];
}): GroupedAuditResult {
  return {
    skill: { name: "fixture", path: "/fixture", scope: "project", agents: [] },
    specFindings: [],
    securityFindings: options.findings || [],
    piiFindings: [],
    complianceFindings: options.complianceFindings || [],
    intelFindings: [],
    riskScore: options.riskScore,
    riskLevel: "risky",
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const root of fixtureRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("blocking enforcement", () => {
  it("blocks high and critical findings independently of their weighted score", () => {
    expect(shouldBlockResult(result({ riskScore: 2.6, findings: [finding("critical")] }), 3)).toBe(true);
    expect(shouldBlockResult(result({ riskScore: 1.1, findings: [finding("high")] }), 3)).toBe(true);
    expect(shouldBlockResult(result({ riskScore: 2.9, findings: [finding("medium")] }), 3)).toBe(false);
  });

  it("treats a score equal to the threshold as blocking", () => {
    expect(shouldBlockResult(result({ riskScore: 3 }), 3)).toBe(true);
  });

  it("uses the weighted threshold instead of severity alone for compliance findings", () => {
    const complianceFinding = finding("high", "COMP");

    expect(shouldBlockResult(result({ riskScore: 1, complianceFindings: [complianceFinding] }), 3)).toBe(false);
    expect(shouldBlockResult(result({ riskScore: 1, complianceFindings: [complianceFinding] }), 1)).toBe(true);
  });

  it("preserves blocking for JSON output", () => {
    vi.spyOn(console, "log").mockImplementation(() => {});

    const blocked = reportGroupedResults(
      [result({ riskScore: 2.6, findings: [finding("critical")] })],
      { json: true, verbose: false, threshold: 3, mode: "audit", block: true },
    );

    expect(blocked).toBe(true);
  });

  it("preserves blocking for file output", () => {
    const root = mkdtempSync(join(tmpdir(), "skill-audit-report-"));
    fixtureRoots.push(root);
    const output = join(root, "report.json");

    const blocked = reportGroupedResults(
      [result({ riskScore: 1.1, findings: [finding("high")] })],
      { json: true, output, verbose: false, threshold: 3, mode: "audit", block: true },
    );

    const report = JSON.parse(readFileSync(output, "utf8"));
    expect(blocked).toBe(true);
    expect(report.summary.blocked).toBe(1);
    expect(report.results[0].securityFindings[0]).toHaveProperty("asi", "ASI05");
    expect(report.results[0].securityFindings[0]).not.toHaveProperty("asixx");
  });

  it("prints compliance findings in verbose human output", () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const complianceFinding = finding("high", "COMP");

    const blocked = reportGroupedResults(
      [result({ riskScore: 1, complianceFindings: [complianceFinding] })],
      { json: false, verbose: true, threshold: 3, mode: "audit", block: true },
    );

    const output = consoleSpy.mock.calls.flat().join("\n");
    expect(blocked).toBe(false);
    expect(output).toContain("Compliance findings: 1");
    expect(output).toContain("Compliance Findings (1)");
    expect(output).toContain("TEST-001: Regression finding");
  });
});
