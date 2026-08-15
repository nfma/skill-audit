import { describe, expect, it } from "vitest";
import { auditCompliance, checkCompliance } from "./compliance.js";
import { SkillManifest } from "./types.js";

function manifest(content: string): SkillManifest {
  return {
    name: "fixture",
    description: "AI assistant fixture",
    content,
    files: []
  };
}

describe("compliance audit", () => {
  it("evaluates the validated manifest content", () => {
    const reports = checkCompliance(manifest("Users have a right to access and right to delete their data."));
    const gdpr = reports.find(report => report.framework === "GDPR");

    expect(gdpr?.findings.some(finding => finding.requirement === "GDPR-002")).toBe(false);
    expect(gdpr?.findings.some(finding => finding.requirement === "GDPR-003")).toBe(true);
  });

  it("returns canonical findings for the CLI audit path", () => {
    const findings = auditCompliance(manifest("Minimal skill documentation."), "/fixture/SKILL.md");

    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every(finding => finding.category === "COMP")).toBe(true);
    expect(findings.every(finding => finding.asi === "ASI04")).toBe(true);
    expect(findings.every(finding => finding.file === "/fixture/SKILL.md")).toBe(true);
  });
});
