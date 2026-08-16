import { writeFileSync } from "fs";
import { Finding, GroupedAuditResult } from "./types.js";

export interface GroupedReportOptions {
  json: boolean;
  output?: string;
  verbose: boolean;
  threshold?: number;
  mode: string;
  block?: boolean;
}

function severityBlockingFindings(result: GroupedAuditResult): Finding[] {
  return [
    ...result.specFindings,
    ...result.securityFindings,
    ...result.piiFindings,
    ...result.intelFindings,
  ];
}

export function hasHighSeverityFinding(result: GroupedAuditResult): boolean {
  return severityBlockingFindings(result).some(
    (finding) => finding.severity === "critical" || finding.severity === "high",
  );
}

export function shouldBlockResult(
  result: GroupedAuditResult,
  threshold?: number,
): boolean {
  return (
    hasHighSeverityFinding(result) ||
    (threshold !== undefined && result.riskScore >= threshold)
  );
}

function uniqueResults(results: GroupedAuditResult[]): GroupedAuditResult[] {
  return [
    ...new Map(results.map((result) => [result.skill.path, result])).values(),
  ];
}

export function reportGroupedResults(
  results: GroupedAuditResult[],
  options: GroupedReportOptions,
): boolean {
  const { json, output, verbose, threshold, mode, block } = options;
  const thresholdFailures =
    threshold === undefined
      ? []
      : results.filter((result) => result.riskScore >= threshold);
  const severityFailures = results.filter(hasHighSeverityFinding);
  const blockingResults = block
    ? uniqueResults([...thresholdFailures, ...severityFailures])
    : [];

  if (output) {
    const report = {
      generated: new Date().toISOString(),
      mode,
      summary: {
        total: results.length,
        safe: results.filter((r) => r.riskLevel === "safe").length,
        risky: results.filter((r) => r.riskLevel === "risky").length,
        dangerous: results.filter((r) => r.riskLevel === "dangerous").length,
        malicious: results.filter((r) => r.riskLevel === "malicious").length,
        specIssues: results.filter((r) => r.specFindings.length > 0).length,
        securityIssues: results.filter((r) => r.securityFindings.length > 0)
          .length,
        piiIssues: results.filter((r) => r.piiFindings.length > 0).length,
        intelIssues: results.filter((r) => r.intelFindings.length > 0).length,
        complianceIssues: results.filter((r) => r.complianceFindings.length > 0)
          .length,
        blocked: blockingResults.length,
      },
      results,
    };
    writeFileSync(output, JSON.stringify(report, null, 2));
    if (!json) console.log(`\n📄 Report saved to: ${output}`);
  } else if (json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    let safeCount = 0,
      riskyCount = 0,
      dangerousCount = 0,
      maliciousCount = 0;
    let specErrors = 0,
      securityIssues = 0,
      piiIssues = 0,
      intelIssues = 0,
      complianceIssues = 0;

    for (const result of results) {
      if (result.riskLevel === "safe") safeCount++;
      else if (result.riskLevel === "risky") riskyCount++;
      else if (result.riskLevel === "dangerous") dangerousCount++;
      else maliciousCount++;

      if (result.specFindings.length > 0) specErrors++;
      if (result.securityFindings.length > 0) securityIssues++;
      if (result.piiFindings.length > 0) piiIssues++;
      if (result.intelFindings.length > 0) intelIssues++;
      if (result.complianceFindings.length > 0) complianceIssues++;
    }

    console.log(`\n📊 Summary (${mode} mode):`);
    console.log(
      `   Safe: ${safeCount} | Risky: ${riskyCount} | Dangerous: ${dangerousCount} | Malicious: ${maliciousCount}`,
    );
    console.log(
      `   Skills with spec issues: ${specErrors} | Security issues: ${securityIssues} | PII issues: ${piiIssues}`,
    );
    console.log(
      `   Intelligence issues: ${intelIssues} | Compliance issues: ${complianceIssues}`,
    );

    if (threshold !== undefined) {
      if (thresholdFailures.length > 0) {
        console.log(
          `\n❌ ${thresholdFailures.length} skills meet or exceed threshold ${threshold}`,
        );
        for (const result of thresholdFailures) {
          console.log(`   - ${result.skill.name}: ${result.riskScore}`);
        }
      } else {
        console.log(`\n✅ All skills pass threshold ${threshold}`);
      }
    }

    const severityOnlyFailures = severityFailures.filter(
      (result) => !thresholdFailures.includes(result),
    );
    if (block && severityOnlyFailures.length > 0) {
      console.log(
        `\n❌ ${severityOnlyFailures.length} skills contain high or critical findings`,
      );
      for (const result of severityOnlyFailures) {
        console.log(`   - ${result.skill.name}`);
      }
    }

    if (verbose) {
      for (const result of results) {
        console.log(`\n--- ${result.skill.name} ---`);

        if (result.specFindings.length > 0) {
          console.log(`\n📋 Spec Issues (${result.specFindings.length}):`);
          for (const finding of result.specFindings) {
            console.log(
              `   [${finding.severity.toUpperCase()}] ${finding.id}: ${finding.message}`,
            );
          }
        }

        if (result.securityFindings.length > 0) {
          console.log(
            `\n🔒 Security Issues (${result.securityFindings.length}):`,
          );
          for (const finding of result.securityFindings) {
            console.log(
              `   [${finding.severity.toUpperCase()}] ${finding.id}: ${finding.message}`,
            );
          }
        }

        if (result.piiFindings.length > 0) {
          console.log(`\n🔐 PII Findings (${result.piiFindings.length}):`);
          for (const finding of result.piiFindings) {
            console.log(
              `   [${finding.severity.toUpperCase()}] ${finding.id}: ${finding.message}`,
            );
          }
        }

        if (result.intelFindings.length > 0) {
          console.log(
            `\n🛰️ Intelligence Findings (${result.intelFindings.length}):`,
          );
          for (const finding of result.intelFindings) {
            console.log(
              `   [${finding.severity.toUpperCase()}] ${finding.id}: ${finding.message}`,
            );
          }
        }

        if (result.complianceFindings.length > 0) {
          console.log(
            `\n📋 Compliance Findings (${result.complianceFindings.length}):`,
          );
          for (const finding of result.complianceFindings) {
            console.log(
              `   [${finding.severity.toUpperCase()}] ${finding.id}: ${finding.message}`,
            );
          }
        }
      }
    }
  }

  return blockingResults.length > 0;
}
