import { writeFileSync } from "fs";
import { isCacheStale } from "./intel.js";
import { Finding, GroupedAuditResult } from "./types.js";

export interface GroupedReportOptions {
  json: boolean;
  output?: string;
  verbose: boolean;
  threshold?: number;
  mode: string;
  block?: boolean;
}

function allFindings(result: GroupedAuditResult): Finding[] {
  return [
    ...result.specFindings,
    ...result.securityFindings,
    ...result.piiFindings,
    ...result.complianceFindings,
    ...result.intelFindings,
  ];
}

export function hasHighSeverityFinding(result: GroupedAuditResult): boolean {
  return allFindings(result).some(finding => finding.severity === "critical" || finding.severity === "high");
}

export function shouldBlockResult(result: GroupedAuditResult, threshold?: number): boolean {
  return hasHighSeverityFinding(result) || (threshold !== undefined && result.riskScore >= threshold);
}

function uniqueResults(results: GroupedAuditResult[]): GroupedAuditResult[] {
  return [...new Map(results.map(result => [result.skill.path, result])).values()];
}

export function reportGroupedResults(results: GroupedAuditResult[], options: GroupedReportOptions): boolean {
  const { json, output, verbose, threshold, mode, block } = options;
  const thresholdFailures = threshold === undefined
    ? []
    : results.filter(result => result.riskScore >= threshold);
  const severityFailures = results.filter(hasHighSeverityFinding);
  const blockingResults = block ? uniqueResults([...thresholdFailures, ...severityFailures]) : [];

  if (output) {
    const report = {
      generated: new Date().toISOString(),
      mode,
      summary: {
        total: results.length,
        safe: results.filter(r => r.riskLevel === "safe").length,
        risky: results.filter(r => r.riskLevel === "risky").length,
        dangerous: results.filter(r => r.riskLevel === "dangerous").length,
        malicious: results.filter(r => r.riskLevel === "malicious").length,
        specIssues: results.filter(r => r.specFindings.length > 0).length,
        securityIssues: results.filter(r => r.securityFindings.length > 0).length,
        blocked: blockingResults.length,
      },
      results,
    };
    writeFileSync(output, JSON.stringify(report, null, 2));
    if (!json) console.log(`\n📄 Report saved to: ${output}`);
  } else if (json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    let safeCount = 0, riskyCount = 0, dangerousCount = 0, maliciousCount = 0;
    let specErrors = 0, securityIssues = 0;

    for (const result of results) {
      if (result.riskLevel === "safe") safeCount++;
      else if (result.riskLevel === "risky") riskyCount++;
      else if (result.riskLevel === "dangerous") dangerousCount++;
      else maliciousCount++;

      if (result.specFindings.length > 0) specErrors++;
      if (result.securityFindings.length > 0) securityIssues++;
    }

    console.log(`\n📊 Summary (${mode} mode):`);
    console.log(`   Safe: ${safeCount} | Risky: ${riskyCount} | Dangerous: ${dangerousCount} | Malicious: ${maliciousCount}`);
    console.log(`   Skills with spec issues: ${specErrors} | Security issues: ${securityIssues}`);

    const kevStale = isCacheStale("kev");
    const epssStale = isCacheStale("epss");
    const nvdStale = isCacheStale("nvd");
    if (kevStale.warn || epssStale.warn || nvdStale.warn) {
      const ages = [];
      if (kevStale.age) ages.push(`${kevStale.age.toFixed(1)} days for KEV`);
      if (epssStale.age) ages.push(`${epssStale.age.toFixed(1)} days for EPSS`);
      if (nvdStale.age) ages.push(`${nvdStale.age.toFixed(1)} days for NVD`);
      console.log(`\n⚠️  Vulnerability DB is stale (${ages.join(", ")})`);
      console.log("   Run: npx skill-audit --update-db");
    }

    if (threshold !== undefined) {
      if (thresholdFailures.length > 0) {
        console.log(`\n❌ ${thresholdFailures.length} skills meet or exceed threshold ${threshold}`);
        for (const result of thresholdFailures) {
          console.log(`   - ${result.skill.name}: ${result.riskScore}`);
        }
      } else {
        console.log(`\n✅ All skills pass threshold ${threshold}`);
      }
    }

    const severityOnlyFailures = severityFailures.filter(result => !thresholdFailures.includes(result));
    if (block && severityOnlyFailures.length > 0) {
      console.log(`\n❌ ${severityOnlyFailures.length} skills contain high or critical findings`);
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
            console.log(`   [${finding.severity.toUpperCase()}] ${finding.id}: ${finding.message}`);
          }
        }

        if (result.securityFindings.length > 0) {
          console.log(`\n🔒 Security Issues (${result.securityFindings.length}):`);
          for (const finding of result.securityFindings) {
            console.log(`   [${finding.severity.toUpperCase()}] ${finding.id}: ${finding.message}`);
          }
        }
      }
    }
  }

  return blockingResults.length > 0;
}
