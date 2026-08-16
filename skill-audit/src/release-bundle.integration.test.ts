import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildRelease } from "../scripts/build-release.js";
import { verifyRelease } from "../scripts/verify-release.js";
import {
  compareUtf8Bytes,
  RELEASE_EXPORTS,
  RELEASE_MAX_BYTES,
} from "./release-assets.js";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
let releaseDirectory: string;

beforeAll(async () => {
  releaseDirectory = mkdtempSync(join(tmpdir(), "skill-audit-bundle-"));
  await buildRelease({
    packageRoot,
    outputDirectory: releaseDirectory,
    releaseTag: "v0.10.0",
    sourceCommit: "a".repeat(40),
  });
});

afterAll(() => {
  rmSync(releaseDirectory, { recursive: true, force: true });
});

describe("release bundle", () => {
  it("creates exactly the three content-addressed assets", () => {
    expect(readdirSync(releaseDirectory).sort(compareUtf8Bytes)).toEqual([
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

  it("passes the executable, import, parity, symlink, and descriptor verifier", async () => {
    const verification = await verifyRelease({
      packageRoot,
      releaseDirectory,
      releaseTag: "v0.10.0",
      sourceCommit: "a".repeat(40),
    });
    expect(verification.message).toContain("Verified skill-audit-v0.10.0.mjs");
  });

  it("exports exactly the six supported functions", async () => {
    const executablePath = join(releaseDirectory, "skill-audit-v0.10.0.mjs");
    const imported = await import(
      `${pathToFileURL(executablePath).href}?test=${Date.now()}`
    );
    expect(Object.keys(imported).sort(compareUtf8Bytes)).toEqual(
      [...RELEASE_EXPORTS].sort(compareUtf8Bytes),
    );
  });

  it("rejects inconsistent release identities before building", async () => {
    await expect(
      buildRelease({
        packageRoot,
        outputDirectory: releaseDirectory,
        releaseTag: "v0.10.1",
        sourceCommit: "a".repeat(40),
      }),
    ).rejects.toThrow("does not match package version");
    await expect(
      buildRelease({
        packageRoot,
        outputDirectory: releaseDirectory,
        sourceCommit: "short",
      }),
    ).rejects.toThrow("full lowercase commit SHA");
  });

  it("rejects missing descriptors and unexpected release assets", async () => {
    const temporaryRoot = mkdtempSync(join(tmpdir(), "skill-audit-verify-"));
    try {
      const emptyRelease = join(temporaryRoot, "empty");
      const copiedRelease = join(temporaryRoot, "copied");
      mkdirSync(emptyRelease);
      cpSync(releaseDirectory, copiedRelease, { recursive: true });
      writeFileSync(join(copiedRelease, "unexpected.txt"), "unexpected\n");

      await expect(
        verifyRelease({ packageRoot, releaseDirectory: emptyRelease }),
      ).rejects.toThrow("exactly one descriptor");
      await expect(
        verifyRelease({ packageRoot, releaseDirectory: copiedRelease }),
      ).rejects.toThrow("Release directory contents differ");
    } finally {
      rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });
});
