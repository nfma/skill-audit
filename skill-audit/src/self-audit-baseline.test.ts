import {
  mkdtempSync,
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
const checker = join(packageRoot, "scripts", "check-self-audit.mjs");
const temporaryDirectories: string[] = [];

function createFixture() {
  const directory = mkdtempSync(join(tmpdir(), "skill-audit-baseline-"));
  temporaryDirectories.push(directory);
  const findingFile = join(directory, "fixture.ts");
  const reportPath = join(directory, "report.json");
  const baselinePath = join(directory, "baseline.json");
  writeFileSync(findingFile, "fixture\n");
  writeFileSync(
    reportPath,
    JSON.stringify([
      {
        specFindings: [],
        securityFindings: [
          {
            id: "TEST-001",
            category: "CE",
            asi: "ASI05",
            severity: "high",
            file: findingFile,
            message: "Regression fixture",
            evidence: "fixture evidence",
          },
        ],
        piiFindings: [],
        complianceFindings: [],
        intelFindings: [],
      },
    ]),
  );
  return { directory, reportPath, baselinePath };
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
      "--skill-root",
      fixture.directory,
      ...additionalArguments,
    ],
    { encoding: "utf8" },
  );
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("self-audit baseline checker", () => {
  it("accepts an exact reviewed baseline", () => {
    const fixture = createFixture();
    const writeResult = runChecker(fixture, ["--write-baseline"]);
    expect(writeResult.status, writeResult.stderr).toBe(0);

    const result = runChecker(fixture);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("matches 1 reviewed baseline finding");
  });

  it("fails on both new findings and stale baseline entries", () => {
    const fixture = createFixture();
    const writeResult = runChecker(fixture, ["--write-baseline"]);
    expect(writeResult.status, writeResult.stderr).toBe(0);
    const report = JSON.parse(readFileSync(fixture.reportPath, "utf8"));
    report[0].securityFindings[0].message = "Changed finding";
    writeFileSync(fixture.reportPath, JSON.stringify(report));

    const result = runChecker(fixture);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("New findings:");
    expect(result.stderr).toContain("Stale baseline entries:");
  });
});
