#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const SCHEMA_VERSION = 1;

function parseArguments(argv) {
  const values = new Map();
  let writeBaseline = false;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--write-baseline") {
      writeBaseline = true;
      continue;
    }
    if (!["--report", "--baseline", "--repo-root"].includes(argument)) {
      throw new Error(`Unknown argument: ${argument}`);
    }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for ${argument}`);
    }
    values.set(argument, value);
    index += 1;
  }

  for (const required of ["--report", "--baseline", "--repo-root"]) {
    if (!values.has(required)) {
      throw new Error(`Missing required argument: ${required}`);
    }
  }

  return {
    baselinePath: resolve(values.get("--baseline")),
    reportPath: resolve(values.get("--report")),
    repoRoot: realpathSync(values.get("--repo-root")),
    writeBaseline,
  };
}

function normalizeFindingPath(file, repoRoot) {
  const canonicalPath = realpathSync(resolve(repoRoot, file));
  const relativePath = relative(repoRoot, canonicalPath);

  if (
    relativePath === "" ||
    relativePath === ".." ||
    relativePath.startsWith(`..${sep}`) ||
    resolve(repoRoot, relativePath) === resolve(repoRoot)
  ) {
    throw new Error(`Semgrep finding path escapes the repository: ${file}`);
  }

  return {
    canonicalPath,
    relativePath: relativePath.split(sep).join("/"),
  };
}

function sourceHash(canonicalPath, startLine, endLine) {
  const lines = readFileSync(canonicalPath, "utf8").split(/\r?\n/);
  if (
    !Number.isInteger(startLine) ||
    !Number.isInteger(endLine) ||
    startLine < 1 ||
    endLine < startLine ||
    endLine > lines.length
  ) {
    throw new Error(
      `Invalid Semgrep finding range: ${canonicalPath}:${startLine}-${endLine}`,
    );
  }
  return createHash("sha256")
    .update(lines.slice(startLine - 1, endLine).join("\n"))
    .digest("hex");
}

function findingKey(finding) {
  return JSON.stringify([
    finding.checkId,
    finding.path,
    finding.severity,
    finding.message,
    finding.sourceSha256,
    finding.count,
  ]);
}

function normalizeReport(report, repoRoot) {
  if (!Array.isArray(report.results)) {
    throw new TypeError("Semgrep report must contain a results array");
  }

  const grouped = new Map();
  for (const result of report.results) {
    const { canonicalPath, relativePath } = normalizeFindingPath(
      result.path,
      repoRoot,
    );
    const finding = {
      checkId: result.check_id,
      path: relativePath,
      severity: result.extra?.severity,
      message: result.extra?.message,
      sourceSha256: sourceHash(
        canonicalPath,
        result.start?.line,
        result.end?.line,
      ),
      count: 1,
    };
    const key = findingKey(finding);
    const existing = grouped.get(key);
    if (existing) {
      existing.count += 1;
    } else {
      grouped.set(key, finding);
    }
  }

  return [...grouped.values()].sort((left, right) =>
    findingKey(left).localeCompare(findingKey(right)),
  );
}

function scanErrorKey(error) {
  return JSON.stringify([
    error.code,
    error.level,
    error.type,
    error.path,
    error.message,
    error.sources,
  ]);
}

function normalizeScanErrors(report, repoRoot) {
  if (!Array.isArray(report.errors)) {
    throw new TypeError("Semgrep report must contain an errors array");
  }

  return report.errors
    .map((error) => {
      if (typeof error.path !== "string" || !Array.isArray(error.spans)) {
        throw new TypeError("Semgrep scan error is missing path or span data");
      }
      const { relativePath } = normalizeFindingPath(error.path, repoRoot);
      const sources = error.spans
        .map((span) => {
          const { canonicalPath, relativePath: sourcePath } =
            normalizeFindingPath(span.file, repoRoot);
          return {
            path: sourcePath,
            sourceSha256: sourceHash(
              canonicalPath,
              span.start?.line,
              span.end?.line,
            ),
          };
        })
        .sort((left, right) =>
          JSON.stringify(left).localeCompare(JSON.stringify(right)),
        );

      return {
        code: error.code,
        level: error.level,
        type: Array.isArray(error.type) ? error.type[0] : error.type,
        path: relativePath,
        message: error.message,
        sources,
      };
    })
    .sort((left, right) =>
      scanErrorKey(left).localeCompare(scanErrorKey(right)),
    );
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

function baselineScanError(error) {
  return {
    ...error,
    review: {
      status: "unreviewed",
      rationale: "",
    },
  };
}

function validateBaseline(baseline) {
  if (baseline.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(
      `Unsupported Semgrep baseline schema: ${String(baseline.schemaVersion)}`,
    );
  }
  if (
    !Array.isArray(baseline.findings) ||
    !Array.isArray(baseline.scanErrors)
  ) {
    throw new TypeError(
      "Semgrep baseline must contain findings and scanErrors arrays",
    );
  }

  const findings = baseline.findings.map((finding) => {
    if (
      finding.review?.status !== "reviewed" ||
      typeof finding.review.rationale !== "string" ||
      finding.review.rationale.trim() === ""
    ) {
      throw new Error(
        `Semgrep baseline finding is not explicitly reviewed: ${findingKey(finding)}`,
      );
    }
    const { review: _review, ...normalizedFinding } = finding;
    return normalizedFinding;
  });
  const scanErrors = baseline.scanErrors.map((error) => {
    if (
      error.review?.status !== "reviewed" ||
      typeof error.review.rationale !== "string" ||
      error.review.rationale.trim() === ""
    ) {
      throw new Error(
        `Semgrep scan error is not explicitly reviewed: ${scanErrorKey(error)}`,
      );
    }
    const { review: _review, ...normalizedError } = error;
    return normalizedError;
  });

  return { findings, scanErrors };
}

function difference(source, target, key = findingKey) {
  const targetKeys = new Set(target.map(key));
  return source.filter((item) => !targetKeys.has(key(item)));
}

function describeFinding(finding) {
  return `${finding.checkId} [${finding.severity}] ${finding.path} (${finding.count} occurrence${finding.count === 1 ? "" : "s"})`;
}

function checkBaseline(actual, expected) {
  const added = difference(actual, expected);
  const stale = difference(expected, actual);
  if (added.length === 0 && stale.length === 0) {
    return;
  }

  const lines = ["Semgrep baseline mismatch."];
  if (added.length > 0) {
    lines.push(
      "",
      "New findings:",
      ...added.map((finding) => `  + ${describeFinding(finding)}`),
    );
  }
  if (stale.length > 0) {
    lines.push(
      "",
      "Stale baseline entries:",
      ...stale.map((finding) => `  - ${describeFinding(finding)}`),
    );
  }
  throw new Error(lines.join("\n"));
}

function checkScanErrors(actual, expected) {
  const added = difference(actual, expected, scanErrorKey);
  const stale = difference(expected, actual, scanErrorKey);
  if (added.length === 0 && stale.length === 0) {
    return;
  }

  const describe = (error) =>
    `${error.type} [${error.level}] ${error.path}: ${error.message}`;
  const lines = ["Semgrep scan-error baseline mismatch."];
  if (added.length > 0) {
    lines.push(
      "",
      "New scan errors:",
      ...added.map((error) => `  + ${describe(error)}`),
    );
  }
  if (stale.length > 0) {
    lines.push(
      "",
      "Stale scan-error entries:",
      ...stale.map((error) => `  - ${describe(error)}`),
    );
  }
  throw new Error(lines.join("\n"));
}

function main(argv) {
  const options = parseArguments(argv);
  const report = JSON.parse(readFileSync(options.reportPath, "utf8"));
  const findings = normalizeReport(report, options.repoRoot);
  const scanErrors = normalizeScanErrors(report, options.repoRoot);

  if (options.writeBaseline) {
    const baseline = {
      schemaVersion: SCHEMA_VERSION,
      findings: findings.map(baselineFinding),
      scanErrors: scanErrors.map(baselineScanError),
    };
    writeFileSync(
      options.baselinePath,
      `${JSON.stringify(baseline, null, 2)}\n`,
    );
    console.log(
      `Wrote ${findings.length} unreviewed Semgrep finding groups to ${options.baselinePath}; explicit review is required before use.`,
    );
    return;
  }

  const baseline = JSON.parse(readFileSync(options.baselinePath, "utf8"));
  const expected = validateBaseline(baseline);
  checkBaseline(findings, expected.findings);
  checkScanErrors(scanErrors, expected.scanErrors);
  const occurrences = findings.reduce(
    (total, finding) => total + finding.count,
    0,
  );
  console.log(
    `Semgrep matches ${findings.length} reviewed finding groups (${occurrences} occurrence${occurrences === 1 ? "" : "s"}).`,
  );
  console.log(
    `Semgrep scan errors match ${scanErrors.length} reviewed baseline ${scanErrors.length === 1 ? "entry" : "entries"}.`,
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

export { checkBaseline, normalizeReport, normalizeScanErrors };
