import { describe, expect, it } from "vitest";
import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { auditCompliance, checkCompliance } from "./compliance.js";
import { SkillManifest } from "./types.js";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

function manifest(content: string): SkillManifest {
  return {
    name: "fixture",
    description: "AI assistant fixture",
    content,
    files: [],
  };
}

describe("compliance audit", () => {
  it("evaluates the validated manifest content", () => {
    const reports = checkCompliance(
      manifest("Users have a right to access and right to delete their data."),
    );
    const gdpr = reports.find((report) => report.framework === "GDPR");

    expect(
      gdpr?.findings.some((finding) => finding.requirement === "GDPR-002"),
    ).toBe(false);
    expect(
      gdpr?.findings.some((finding) => finding.requirement === "GDPR-003"),
    ).toBe(true);
  });

  it("returns canonical findings for the CLI audit path", () => {
    const findings = auditCompliance(
      manifest("Minimal skill documentation."),
      "/fixture/SKILL.md",
    );

    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((finding) => finding.category === "COMP")).toBe(true);
    expect(findings.every((finding) => finding.asi === "ASI04")).toBe(true);
    expect(
      findings.every((finding) => finding.file === "/fixture/SKILL.md"),
    ).toBe(true);
  });

  it("ships heuristic guidance with the current Vietnam AI Law citation", () => {
    const reference = readFileSync(
      join(packageRoot, "references", "compliance-frameworks.md"),
      "utf8",
    );
    const example = readFileSync(
      join(packageRoot, "examples", "example-compliance-report.md"),
      "utf8",
    );
    const guidance = `${reference}\n${example}`;

    expect(reference).toContain("do not validate legal compliance");
    expect(guidance).toContain("134/2025/QH15");
    expect(guidance).toContain("March 1, 2026");
    expect(guidance).not.toMatch(/24\/2024\/QH15|January 1, 2026/);
    expect(example).not.toMatch(
      /✅ Compliant|Non-Compliant|law violation|GDPR violation/i,
    );
  });
});
