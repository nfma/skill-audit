import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { spawnSync } from "child_process";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = join(packageRoot, "node_modules", "tsx", "dist", "cli.mjs");
const entrypointPath = join(packageRoot, "src", "index.ts");
let fixtureRoot: string;
let fixtureSkillPath: string;
let fixtureBinPath: string;

beforeAll(() => {
  fixtureRoot = mkdtempSync(join(tmpdir(), "skill-audit-cli-"));
  fixtureSkillPath = join(fixtureRoot, "fixture");
  fixtureBinPath = join(fixtureRoot, "bin");
  mkdirSync(fixtureSkillPath);
  mkdirSync(fixtureBinPath);
  writeFileSync(join(fixtureSkillPath, "SKILL.md"), `---
name: fixture
description: Documents a local sample workflow.
---

# Fixture

Describe a local workflow and its expected result.
`);
  const fakeNpx = join(fixtureBinPath, "npx");
  writeFileSync(fakeNpx, "#!/bin/sh\nprintf '%s\\n' \"$SKILL_AUDIT_TEST_DISCOVERY\"\n");
  chmodSync(fakeNpx, 0o755);
});

afterAll(() => {
  rmSync(fixtureRoot, { recursive: true, force: true });
});

function runCli(args: string[]) {
  return spawnSync(process.execPath, [cliPath, entrypointPath, ...args], {
    cwd: packageRoot,
    encoding: "utf8",
    timeout: 10_000,
    env: {
      ...process.env,
      HOME: fixtureRoot,
      PATH: `${fixtureBinPath}:${process.env.PATH || ""}`,
      SKILL_AUDIT_TEST_DISCOVERY: JSON.stringify([{
        name: "fixture",
        path: fixtureSkillPath,
        scope: "project",
        agents: [],
      }]),
    },
  });
}

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
    expect(report[0].complianceFindings.every((finding: { category: string }) => finding.category === "COMP")).toBe(true);
  });

  it("prints compliance findings without blocking below the weighted threshold", () => {
    const result = runCli(["--project", "--no-deps", "--compliance", "--block", "--verbose"]);

    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("All skills pass threshold 3");
    expect(result.stdout).toContain("Compliance Findings");
    expect(result.stdout).toContain("VN-AI-");
  });
});
