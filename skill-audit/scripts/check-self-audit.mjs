#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const SCHEMA_VERSION = 1;
const FINDING_BUCKETS = [
  "specFindings",
  "securityFindings",
  "piiFindings",
  "complianceFindings",
  "intelFindings",
];

function parseArguments(argv) {
  const values = new Map();
  let writeBaseline = false;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--write-baseline") {
      writeBaseline = true;
      continue;
    }
    if (!["--report", "--baseline", "--skill-root"].includes(argument)) {
      throw new Error(`Unknown argument: ${argument}`);
    }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for ${argument}`);
    }
    values.set(argument, value);
    index += 1;
  }

  for (const required of ["--report", "--baseline", "--skill-root"]) {
    if (!values.has(required)) {
      throw new Error(`Missing required argument: ${required}`);
    }
  }

  return {
    baselinePath: resolve(values.get("--baseline")),
    reportPath: resolve(values.get("--report")),
    skillRoot: realpathSync(values.get("--skill-root")),
    writeBaseline,
  };
}

function hashEvidence(evidence) {
  return createHash("sha256")
    .update(evidence ?? "")
    .digest("hex");
}

function normalizeFindingPath(file, skillRoot) {
  const suffix = " (code block)";
  const hasCodeBlockSuffix = file.endsWith(suffix);
  const path = hasCodeBlockSuffix ? file.slice(0, -suffix.length) : file;
  const canonicalPath = realpathSync(resolve(path));
  const relativePath = relative(skillRoot, canonicalPath);

  if (
    relativePath === "" ||
    relativePath === ".." ||
    relativePath.startsWith(`..${sep}`) ||
    resolve(skillRoot, relativePath) === resolve(skillRoot)
  ) {
    throw new Error(
      `Finding path is not a file inside the skill root: ${file}`,
    );
  }

  return `${relativePath.split(sep).join("/")}${hasCodeBlockSuffix ? suffix : ""}`;
}

function normalizeReport(report, skillRoot) {
  const results = Array.isArray(report) ? report : report.results;
  if (!Array.isArray(results)) {
    throw new TypeError(
      "Audit report must be an array or contain a results array",
    );
  }

  return results
    .flatMap((result) =>
      FINDING_BUCKETS.flatMap((bucket) => {
        const findings = result[bucket];
        if (!Array.isArray(findings)) {
          throw new TypeError(`Audit result is missing ${bucket}`);
        }
        return findings.map((finding) => ({
          bucket,
          id: finding.id,
          category: finding.category,
          asi: finding.asi,
          severity: finding.severity,
          file: normalizeFindingPath(finding.file, skillRoot),
          message: finding.message,
          evidenceSha256: hashEvidence(finding.evidence),
        }));
      }),
    )
    .sort(compareFindings);
}

function compareFindings(left, right) {
  return findingKey(left).localeCompare(findingKey(right));
}

function findingKey(finding) {
  return JSON.stringify([
    finding.bucket,
    finding.id,
    finding.category,
    finding.asi,
    finding.severity,
    finding.file,
    finding.message,
    finding.evidenceSha256,
  ]);
}

function rationaleFor(file) {
  if (file === "package-lock.json") {
    return "Reviewed false positive in an npm registry integrity hash.";
  }
  if (file.startsWith("rules/") || /(^|\/)security\.(js|ts)$/.test(file)) {
    return "Reviewed self-reference in a detector definition.";
  }
  if (file.includes(".test.") || file === "scripts/test-audit.sh") {
    return "Reviewed malicious or PII regression fixture.";
  }
  return "Reviewed security documentation or example fixture.";
}

function baselineFinding(finding) {
  return { ...finding, rationale: rationaleFor(finding.file) };
}

function validateBaseline(baseline) {
  if (baseline.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(
      `Unsupported baseline schema: ${String(baseline.schemaVersion)}`,
    );
  }
  if (!Array.isArray(baseline.findings)) {
    throw new TypeError("Baseline must contain a findings array");
  }
  for (const finding of baseline.findings) {
    if (typeof finding.rationale !== "string" || finding.rationale === "") {
      throw new Error(
        `Baseline finding lacks a rationale: ${findingKey(finding)}`,
      );
    }
  }
  return baseline.findings;
}

function countFindings(findings) {
  const counts = new Map();
  for (const finding of findings) {
    const key = findingKey(finding);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

function difference(source, target) {
  const sourceCounts = countFindings(source);
  const targetCounts = countFindings(target);
  const findings = [];

  for (const [key, count] of sourceCounts) {
    const excess = count - (targetCounts.get(key) ?? 0);
    for (let index = 0; index < excess; index += 1) {
      findings.push(JSON.parse(key));
    }
  }
  return findings;
}

function describeFinding(fields) {
  const [bucket, id, , , severity, file, message] = fields;
  return `${bucket}: ${id} [${severity}] ${file} — ${message}`;
}

function checkBaseline(actual, expected) {
  const added = difference(actual, expected);
  const stale = difference(expected, actual);

  if (added.length === 0 && stale.length === 0) {
    return;
  }

  const lines = ["Self-audit baseline mismatch."];
  if (added.length > 0) {
    lines.push(
      "",
      "New findings:",
      ...added.map((item) => `  + ${describeFinding(item)}`),
    );
  }
  if (stale.length > 0) {
    lines.push(
      "",
      "Stale baseline entries:",
      ...stale.map((item) => `  - ${describeFinding(item)}`),
    );
  }
  throw new Error(lines.join("\n"));
}

function main(argv) {
  const options = parseArguments(argv);
  const report = JSON.parse(readFileSync(options.reportPath, "utf8"));
  const findings = normalizeReport(report, options.skillRoot);

  if (options.writeBaseline) {
    const baseline = {
      schemaVersion: SCHEMA_VERSION,
      findings: findings.map(baselineFinding),
    };
    writeFileSync(
      options.baselinePath,
      `${JSON.stringify(baseline, null, 2)}\n`,
    );
    console.log(
      `Wrote ${findings.length} reviewed findings to ${options.baselinePath}`,
    );
    return;
  }

  const baseline = JSON.parse(readFileSync(options.baselinePath, "utf8"));
  checkBaseline(findings, validateBaseline(baseline));
  console.log(
    `Self-audit matches ${findings.length} reviewed baseline findings.`,
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}

export { checkBaseline, normalizeReport };
