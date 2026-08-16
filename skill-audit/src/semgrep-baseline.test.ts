import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { spawnSync } from "child_process";
import { afterEach, describe, expect, it } from "vitest";

const packageRoot = realpathSync(join(import.meta.dirname, ".."));
const checker = join(packageRoot, "scripts", "check-semgrep.mjs");
const temporaryDirectories: string[] = [];

function readExcludedFindingFiles() {
  const source = readFileSync(checker, "utf8");
  const match = source.match(
    /const EXCLUDED_FINDING_FILES = new Set\(\[([\s\S]*?)\]\);/,
  );
  if (!match) throw new Error("Could not read Semgrep file exclusions");
  return [...match[1].matchAll(/"([^"]+)"/g)].map((entry) => entry[1]);
}

function createFixture() {
  const directory = mkdtempSync(join(tmpdir(), "skill-audit-semgrep-"));
  temporaryDirectories.push(directory);
  const findingFile = join(directory, "fixture.ts");
  const reportPath = join(directory, "report.json");
  const baselinePath = join(directory, "baseline.json");
  writeFileSync(findingFile, "const fixture = input;\n");
  writeFileSync(
    reportPath,
    JSON.stringify({
      results: [
        {
          check_id: "example.security.rule",
          path: "fixture.ts",
          start: { line: 1 },
          end: { line: 1 },
          extra: { severity: "WARNING", message: "Regression fixture" },
        },
      ],
      errors: [],
      time: { fixpoint_timeouts: [] },
    }),
  );
  return { directory, findingFile, reportPath, baselinePath };
}

function runChecker(
  fixture: ReturnType<typeof createFixture>,
  additionalArguments: string[] = [],
) {
  return spawnSync(
    process.execPath,
    [
      checker,
      "--report",
      fixture.reportPath,
      "--baseline",
      fixture.baselinePath,
      "--repo-root",
      fixture.directory,
      ...additionalArguments,
    ],
    { encoding: "utf8" },
  );
}

function markBaselineReviewed(baselinePath: string) {
  const baseline = JSON.parse(readFileSync(baselinePath, "utf8"));
  for (const finding of baseline.findings) {
    finding.review = {
      status: "reviewed",
      rationale: "Reviewed regression fixture.",
    };
  }
  for (const error of baseline.scanErrors) {
    error.review = {
      status: "reviewed",
      rationale: "Reviewed regression fixture.",
    };
  }
  writeFileSync(baselinePath, JSON.stringify(baseline));
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("Semgrep baseline checker", () => {
  it("pins exact file exclusions", () => {
    expect(readExcludedFindingFiles()).toEqual([
      "skill-audit/src/generated/release-data.ts",
    ]);
  });

  it("accepts an exact reviewed baseline", () => {
    const fixture = createFixture();
    const writeResult = runChecker(fixture, ["--write-baseline"]);
    expect(writeResult.status, writeResult.stderr).toBe(0);
    markBaselineReviewed(fixture.baselinePath);

    const result = runChecker(fixture);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Semgrep taint fixpoint timeouts: 0.");
    expect(result.stdout).toContain(
      "matches 1 reviewed finding groups (1 occurrence)",
    );
  });

  it.each([
    [
      "missing time metadata",
      (report: Record<string, unknown>) => {
        delete report.time;
      },
    ],
    [
      "missing fixpoint timeout metadata",
      (report: Record<string, unknown>) => {
        report.time = {};
      },
    ],
  ])("fails closed on %s", (_name, mutateReport) => {
    const fixture = createFixture();
    const report = JSON.parse(readFileSync(fixture.reportPath, "utf8"));
    mutateReport(report);
    writeFileSync(fixture.reportPath, JSON.stringify(report));

    const result = runChecker(fixture, ["--write-baseline"]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Semgrep report");
  });

  it("records a fixpoint timeout when findings match the reviewed baseline", () => {
    const fixture = createFixture();
    const writeResult = runChecker(fixture, ["--write-baseline"]);
    expect(writeResult.status, writeResult.stderr).toBe(0);
    markBaselineReviewed(fixture.baselinePath);
    const report = JSON.parse(readFileSync(fixture.reportPath, "utf8"));
    report.time.fixpoint_timeouts = [
      {
        location: {
          path: "fixture.ts",
          start: { line: 1, col: 7 },
        },
      },
    ];
    writeFileSync(fixture.reportPath, JSON.stringify(report));

    const result = runChecker(fixture);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Semgrep taint fixpoint timeouts: 1.");
    expect(result.stdout).toContain("fixture.ts:1:7");
  });

  it("fails when a fixpoint timeout accompanies finding drift", () => {
    const fixture = createFixture();
    const writeResult = runChecker(fixture, ["--write-baseline"]);
    expect(writeResult.status, writeResult.stderr).toBe(0);
    markBaselineReviewed(fixture.baselinePath);
    const report = JSON.parse(readFileSync(fixture.reportPath, "utf8"));
    report.time.fixpoint_timeouts = [
      {
        location: {
          path: "fixture.ts",
          start: { line: 1, col: 7 },
        },
      },
    ];
    writeFileSync(fixture.reportPath, JSON.stringify(report));
    writeFileSync(fixture.findingFile, "const fixture = changedInput;\n");

    const result = runChecker(fixture);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain("Semgrep taint fixpoint timeouts: 1.");
    expect(result.stderr).toContain("Semgrep baseline mismatch");
  });

  it("refuses to create a baseline from a degraded scan", () => {
    const fixture = createFixture();
    const report = JSON.parse(readFileSync(fixture.reportPath, "utf8"));
    report.time.fixpoint_timeouts = [
      {
        location: {
          path: "fixture.ts",
          start: { line: 1, col: 7 },
        },
      },
    ];
    writeFileSync(fixture.reportPath, JSON.stringify(report));

    const result = runChecker(fixture, ["--write-baseline"]);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain("Semgrep taint fixpoint timeouts: 1.");
    expect(result.stderr).toContain(
      "Cannot write a Semgrep baseline from a scan with taint fixpoint timeouts",
    );
  });

  it("rejects a generated baseline without explicit review", () => {
    const fixture = createFixture();
    const writeResult = runChecker(fixture, ["--write-baseline"]);
    expect(writeResult.status, writeResult.stderr).toBe(0);

    const result = runChecker(fixture);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("is not explicitly reviewed");
  });

  it("excludes the embedded generated rule data", () => {
    const fixture = createFixture();
    const generatedDirectory = join(
      fixture.directory,
      "skill-audit",
      "src",
      "generated",
    );
    const generatedPath = join(generatedDirectory, "release-data.ts");
    mkdirSync(generatedDirectory, { recursive: true });
    writeFileSync(generatedPath, "generated rule data\n");
    const report = JSON.parse(readFileSync(fixture.reportPath, "utf8"));
    report.results.push({
      ...report.results[0],
      path: "skill-audit/src/generated/release-data.ts",
    });
    writeFileSync(fixture.reportPath, JSON.stringify(report));

    const result = runChecker(fixture, ["--write-baseline"]);
    expect(result.status, result.stderr).toBe(0);
    const baseline = JSON.parse(readFileSync(fixture.baselinePath, "utf8"));

    expect(baseline.findings).toHaveLength(1);
    expect(baseline.findings[0].path).toBe("fixture.ts");
  });

  it("fails on both new findings and stale reviewed entries", () => {
    const fixture = createFixture();
    const writeResult = runChecker(fixture, ["--write-baseline"]);
    expect(writeResult.status, writeResult.stderr).toBe(0);
    markBaselineReviewed(fixture.baselinePath);
    writeFileSync(fixture.findingFile, "const fixture = changedInput;\n");

    const result = runChecker(fixture);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("New findings:");
    expect(result.stderr).toContain("Stale baseline entries:");
  });

  it("fails when Semgrep reports a new parser warning", () => {
    const fixture = createFixture();
    const writeResult = runChecker(fixture, ["--write-baseline"]);
    expect(writeResult.status, writeResult.stderr).toBe(0);
    markBaselineReviewed(fixture.baselinePath);
    const report = JSON.parse(readFileSync(fixture.reportPath, "utf8"));
    report.errors.push({
      code: 3,
      level: "warn",
      type: ["PartialParsing", []],
      message: "Regression parser warning",
      path: "fixture.ts",
      spans: [
        {
          file: "fixture.ts",
          start: { line: 1 },
          end: { line: 1 },
        },
      ],
    });
    writeFileSync(fixture.reportPath, JSON.stringify(report));

    const result = runChecker(fixture);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("New scan errors:");
  });

  it("fails when a reviewed parser warning disappears", () => {
    const fixture = createFixture();
    const report = JSON.parse(readFileSync(fixture.reportPath, "utf8"));
    report.errors.push({
      code: 3,
      level: "warn",
      type: ["PartialParsing", []],
      message: "Regression parser warning",
      path: "fixture.ts",
      spans: [
        {
          file: "fixture.ts",
          start: { line: 1 },
          end: { line: 1 },
        },
      ],
    });
    writeFileSync(fixture.reportPath, JSON.stringify(report));
    const writeResult = runChecker(fixture, ["--write-baseline"]);
    expect(writeResult.status, writeResult.stderr).toBe(0);
    markBaselineReviewed(fixture.baselinePath);
    report.errors = [];
    writeFileSync(fixture.reportPath, JSON.stringify(report));

    const result = runChecker(fixture);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Stale scan-error entries:");
  });
});
