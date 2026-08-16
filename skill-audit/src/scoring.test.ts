import { describe, expect, it } from "vitest";
import { calculateRiskScore, groupSecurityFindings } from "./scoring.js";
import { Finding } from "./types.js";

const piiFinding: Finding = {
  id: "PII-001",
  category: "PII",
  asi: "ASI03",
  severity: "high",
  file: "/fixture/SKILL.md",
  message: "PII regression finding",
};

describe("canonical PII handling", () => {
  it("groups PII separately from general security findings", () => {
    const grouped = groupSecurityFindings([piiFinding]);

    expect(grouped.piiFindings).toEqual([piiFinding]);
    expect(grouped.securityFindings).toEqual([]);
    expect(grouped.complianceFindings).toEqual([]);
  });

  it("applies the PII category weight of 2.5", () => {
    const score = calculateRiskScore([piiFinding]);

    expect(score.total).toBe(7.5);
    expect(score.categories).toEqual({ PII: 1 });
    expect(score.asi).toEqual({ ASI03: 1 });
  });

  it("serializes findings and risk scores with asi only", () => {
    const serialized = JSON.parse(
      JSON.stringify({
        finding: piiFinding,
        riskScore: calculateRiskScore([piiFinding]),
      }),
    );

    expect(serialized.finding).toHaveProperty("asi", "ASI03");
    expect(serialized.finding).not.toHaveProperty("asixx");
    expect(serialized.riskScore).toHaveProperty("asi.ASI03", 1);
    expect(serialized.riskScore).not.toHaveProperty("asixx");
  });
});
