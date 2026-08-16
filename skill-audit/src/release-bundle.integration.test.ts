import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RELEASE_EXPORTS, RELEASE_MAX_BYTES } from "./release-assets.js";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const tsxPath = join(packageRoot, "node_modules", "tsx", "dist", "cli.mjs");
let releaseDirectory: string;

function runScript(script: string) {
  return spawnSync(process.execPath, [tsxPath, join(packageRoot, script)], {
    cwd: packageRoot,
    encoding: "utf8",
    timeout: 30_000,
    env: {
      ...process.env,
      RELEASE_OUTPUT_DIR: releaseDirectory,
      RELEASE_TAG: "v0.10.0",
      SOURCE_COMMIT: "a".repeat(40),
    },
  });
}

beforeAll(() => {
  releaseDirectory = mkdtempSync(join(tmpdir(), "skill-audit-bundle-"));
  const build = runScript("scripts/build-release.ts");
  expect(build.error).toBeUndefined();
  expect(build.status, build.stderr).toBe(0);
});

afterAll(() => {
  rmSync(releaseDirectory, { recursive: true, force: true });
});

describe("release bundle", () => {
  it("creates exactly the three content-addressed assets", () => {
    expect(readdirSync(releaseDirectory).sort()).toEqual([
      "skill-audit-v0.10.0-release.json",
      "skill-audit-v0.10.0.mjs",
      "skill-audit-v0.10.0.mjs.sha256",
    ]);

    const executable = readFileSync(
      join(releaseDirectory, "skill-audit-v0.10.0.mjs"),
    );
    const text = executable.toString("utf8");
    expect(executable.byteLength).toBeGreaterThan(0);
    expect(executable.byteLength).toBeLessThanOrEqual(RELEASE_MAX_BYTES);
    expect(text.startsWith("#!/usr/bin/env node\n")).toBe(true);
    expect(text.indexOf("#!", 2)).toBe(-1);
  });

  it("passes the executable, import, parity, symlink, and descriptor verifier", () => {
    const verification = runScript("scripts/verify-release.ts");
    expect(verification.error).toBeUndefined();
    expect(verification.status, verification.stderr).toBe(0);
    expect(verification.stdout).toContain("Verified skill-audit-v0.10.0.mjs");
  });

  it("exports exactly the six supported functions", async () => {
    const executablePath = join(releaseDirectory, "skill-audit-v0.10.0.mjs");
    const imported = await import(
      `${pathToFileURL(executablePath).href}?test=${Date.now()}`
    );
    expect(Object.keys(imported).sort()).toEqual([...RELEASE_EXPORTS].sort());
  });
});
