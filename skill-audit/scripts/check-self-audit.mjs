#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseBaselineArguments } from "./baseline-cli.mjs";

const SCHEMA_VERSION = 2;
const EXCLUDED_FINDING_DIRECTORIES = ["coverage/", "dist/"];
const EXCLUDED_FINDING_FILES = new Set(["package-lock.json"]);
const FINDING_BUCKETS = [
  "specFindings",
  "securityFindings",
  "piiFindings",
  "complianceFindings",
  "intelFindings",
];

function parseArguments(argv) {
  const options = parseBaselineArguments(argv, "--skill-root");
  return {
    baselinePath: options.baselinePath,
    reportPath: options.reportPath,
    skillRoot: options.root,
    writeBaseline: options.writeBaseline,
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
  return normalizeReportWithSummary(report, skillRoot).findings;
}

function normalizeReportWithSummary(report, skillRoot) {
  const results = Array.isArray(report) ? report : report.results;
  if (!Array.isArray(results)) {
    throw new TypeError(
      "Audit report must be an array or contain a results array",
    );
  }

  const normalizedFindings = results.flatMap((result) =>
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
  );
  const findings = normalizedFindings.filter((finding) => {
    const inExcludedDirectory = EXCLUDED_FINDING_DIRECTORIES.some((directory) =>
      finding.file.startsWith(directory),
    );
    return !inExcludedDirectory && !EXCLUDED_FINDING_FILES.has(finding.file);
  });

  return {
    excludedFindingCount: normalizedFindings.length - findings.length,
    findings: findings.toSorted(compareFindings),
  };
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

function baselineFinding(finding) {
  return {
    ...finding,
    review: {
      status: "unreviewed",
      rationale: "",
    },
  };
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
    if (
      finding.review?.status !== "reviewed" ||
      typeof finding.review.rationale !== "string" ||
      finding.review.rationale.trim() === ""
    ) {
      throw new Error(
        `Baseline finding is not explicitly reviewed: ${findingKey(finding)}`,
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
  const { excludedFindingCount, findings } = normalizeReportWithSummary(
    report,
    options.skillRoot,
  );
  const excludedFindingLabel =
    excludedFindingCount === 1 ? "finding" : "findings";

  console.log(
    `Self-audit excluded ${excludedFindingCount} generated or dependency-lock ${excludedFindingLabel} from baseline matching.`,
  );

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
      `Wrote ${findings.length} unreviewed findings to ${options.baselinePath}; explicit review is required before use.`,
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
