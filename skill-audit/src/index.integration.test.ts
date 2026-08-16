import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { spawnSync } from "child_process";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = join(packageRoot, "node_modules", "tsx", "dist", "cli.mjs");
const entrypointPath = join(packageRoot, "src", "index.ts");
let fixtureRoot: string;
let fixtureSkillPath: string;
let piiSkillPath: string;
let fixtureBinPath: string;

beforeAll(() => {
  fixtureRoot = mkdtempSync(join(tmpdir(), "skill-audit-cli-"));
  fixtureSkillPath = join(fixtureRoot, "fixture");
  piiSkillPath = join(fixtureRoot, "pii");
  fixtureBinPath = join(fixtureRoot, "bin");
  mkdirSync(fixtureSkillPath);
  mkdirSync(piiSkillPath);
  mkdirSync(fixtureBinPath);
  writeFileSync(
    join(fixtureSkillPath, "SKILL.md"),
    `---
name: fixture
description: Documents a local sample workflow.
---

# Fixture

Describe a local workflow and its expected result.
`,
  );
  writeFileSync(
    join(piiSkillPath, "SKILL.md"),
    `---
name: pii
description: Documents a local sample containing sensitive data.
---

# PII fixture

Contact test@example.com with SSN 123-45-6789.
`,
  );
  const fakeNpx = join(fixtureBinPath, "npx");
  writeFileSync(
    fakeNpx,
    "#!/bin/sh\nprintf '%s\\n' \"$SKILL_AUDIT_TEST_DISCOVERY\"\n",
  );
  chmodSync(fakeNpx, 0o755);
});

afterAll(() => {
  rmSync(fixtureRoot, { recursive: true, force: true });
});

function runCli(
  args: string[],
  skill = { name: "fixture", path: fixtureSkillPath },
) {
  return spawnSync(process.execPath, [cliPath, entrypointPath, ...args], {
    cwd: packageRoot,
    encoding: "utf8",
    timeout: 10_000,
    env: {
      ...process.env,
      HOME: fixtureRoot,
      PATH: `${fixtureBinPath}:${process.env.PATH || ""}`,
      SKILL_AUDIT_TEST_DISCOVERY: JSON.stringify([
        {
          name: skill.name,
          path: skill.path,
          scope: "project",
          agents: [],
        },
      ]),
    },
  });
}

describe("CLI option validation", () => {
  it("describes threshold and feed snapshots without implying inactive behavior", () => {
    const result = runCli(["--help"]);

    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    const output = result.stdout.replace(/\s+/g, " ");
    expect(output).toContain(
      "Risk score threshold (default with --block: 3.0)",
    );
    expect(output).toContain(
      "Export vulnerability-feed snapshots to directory",
    );
    expect(output).not.toContain(
      "Fail if risk score meets or exceeds threshold",
    );
  });

  it("rejects --strict outside --update-db", () => {
    const result = runCli(["--strict"]);

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "option '--strict' can only be used with '--update-db'",
    );
  });

  it("audits an explicit skill path without invoking discovery", () => {
    const result = runCli(["--path", piiSkillPath, "--no-deps", "--json"]);

    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    const report = JSON.parse(result.stdout);
    expect(report).toHaveLength(1);
    expect(report[0].skill.name).toBe("pii");
    expect(report[0].skill.path).toBe(realpathSync(piiSkillPath));
  });
});

describe("CLI compliance wiring", () => {
  it("does not run compliance heuristics by default", () => {
    const result = runCli(["--project", "--no-deps", "--json"]);

    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    const report = JSON.parse(result.stdout);
    expect(report).toHaveLength(1);
    expect(report[0].complianceFindings).toEqual([]);
  });

  it("routes --compliance through the real audit path", () => {
    const result = runCli(["--project", "--no-deps", "--compliance", "--json"]);

    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    const report = JSON.parse(result.stdout);
    expect(report[0].complianceFindings.length).toBeGreaterThan(0);
    expect(
      report[0].complianceFindings.every(
        (finding: { category: string }) => finding.category === "COMP",
      ),
    ).toBe(true);
  });

  it("prints compliance findings without blocking below the weighted threshold", () => {
    const result = runCli([
      "--project",
      "--no-deps",
      "--compliance",
      "--block",
      "--verbose",
    ]);

    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("All skills pass threshold 3");
    expect(result.stdout).toContain("Compliance Findings");
    expect(result.stdout).toContain("VN-AI-");
  });
});

describe("CLI PII reporting", () => {
  it("prints the PII findings that cause a blocked audit", () => {
    const result = runCli(["--project", "--no-deps", "--block", "--verbose"], {
      name: "pii",
      path: piiSkillPath,
    });

    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(1);
    expect(result.stdout).toContain("PII issues: 1");
    expect(result.stdout).toContain("PII Findings (2)");
    expect(result.stdout).toContain("PII-010: US Social Security Number (SSN)");
    expect(result.stdout).toContain("PII-022: Email Address");
  });
});
