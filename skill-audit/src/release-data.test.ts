import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { generateReleaseData } from "../scripts/generate-release-data.js";
import {
  canonicalizeJson,
  compareUtf8Bytes,
  sha256Hex,
} from "./release-assets.js";
import {
  EMBEDDED_DEFAULT_PATTERNS_BASE64,
  EMBEDDED_RULES_SHA256,
} from "./generated/release-data.js";
import { decodeEmbeddedPatterns, loadEmbeddedPatterns } from "./patterns.js";
import "./cli.js";
import "./release.js";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
  vi.restoreAllMocks();
});

function encodeCanonical(value: unknown) {
  const canonical = canonicalizeJson(value);
  return {
    encoded: Buffer.from(canonical, "utf8").toString("base64"),
    digest: sha256Hex(canonical),
  };
}

describe("canonical rule identity", () => {
  it("sorts object keys by UTF-8 bytes while preserving array order", () => {
    const left = { z: 1, a: { y: true, b: [3, 2, 1] } };
    const right = { a: { b: [3, 2, 1], y: true }, z: 1 };

    expect(canonicalizeJson(left)).toBe(canonicalizeJson(right));
    expect(canonicalizeJson(left)).toBe('{"a":{"b":[3,2,1],"y":true},"z":1}');
    expect(["é", "z", "a"].sort(compareUtf8Bytes)).toEqual(["a", "z", "é"]);
  });

  it("rejects values outside the JSON data model", () => {
    for (const value of [undefined, 1n, Number.POSITIVE_INFINITY, new Date()]) {
      expect(() => canonicalizeJson(value)).toThrow(TypeError);
    }
  });

  it("binds the embedded rules to canonical decoded file content", () => {
    const fileBackedRules: unknown = JSON.parse(
      readFileSync(join(packageRoot, "rules", "default-patterns.json"), "utf8"),
    );
    const canonical = canonicalizeJson(fileBackedRules);

    expect(sha256Hex(canonical)).toBe(EMBEDDED_RULES_SHA256);
    expect(
      decodeEmbeddedPatterns(
        EMBEDDED_DEFAULT_PATTERNS_BASE64,
        EMBEDDED_RULES_SHA256,
      ),
    ).toEqual(fileBackedRules);
    expect(loadEmbeddedPatterns()).toBe(loadEmbeddedPatterns());
  });

  it("fails closed for malformed, corrupted, or empty embedded rules", () => {
    expect(() => decodeEmbeddedPatterns("", EMBEDDED_RULES_SHA256)).toThrow(
      "could not be decoded",
    );

    const invalidJson = Buffer.from("not-json", "utf8").toString("base64");
    expect(() =>
      decodeEmbeddedPatterns(invalidJson, sha256Hex("not-json")),
    ).toThrow("could not be decoded");

    const empty = encodeCanonical({
      version: "1",
      updated: "today",
      description: "empty",
      categories: {},
    });
    expect(() => decodeEmbeddedPatterns(empty.encoded, empty.digest)).toThrow(
      "could not be decoded",
    );

    expect(() =>
      decodeEmbeddedPatterns(EMBEDDED_DEFAULT_PATTERNS_BASE64, "0".repeat(64)),
    ).toThrow("could not be decoded");
  });
});

describe("release data generation", () => {
  function fixture() {
    const root = mkdtempSync(join(tmpdir(), "skill-audit-release-data-"));
    temporaryDirectories.push(root);
    mkdirSync(join(root, "rules"));
    mkdirSync(join(root, "src", "generated"), { recursive: true });
    writeFileSync(join(root, "package.json"), '{"version":"1.2.3"}\n');
    return {
      root,
      output: join(root, "src", "generated", "release-data.ts"),
      rules: join(root, "rules", "default-patterns.json"),
    };
  }

  it("generates identical bytes for equivalent JSON encodings", async () => {
    const paths = fixture();
    const firstRules = {
      version: "1",
      updated: "today",
      description: "fixture",
      categories: {
        test: {
          name: "Test",
          description: "Fixture",
          patterns: [
            { pattern: "x", id: "T-1", severity: "low", message: "x" },
          ],
        },
      },
    };
    writeFileSync(paths.rules, `${JSON.stringify(firstRules, null, 2)}\n`);
    const first = await generateReleaseData({
      packageRoot: paths.root,
      outputPath: paths.output,
    });

    writeFileSync(
      paths.rules,
      JSON.stringify({
        categories: firstRules.categories,
        description: firstRules.description,
        updated: firstRules.updated,
        version: firstRules.version,
      }),
    );
    const second = await generateReleaseData({
      packageRoot: paths.root,
      outputPath: paths.output,
    });

    expect(second.rulesSha256).toBe(first.rulesSha256);
    expect(second.generatedSource).toBe(first.generatedSource);
    await expect(
      generateReleaseData({
        packageRoot: paths.root,
        outputPath: paths.output,
        check: true,
      }),
    ).resolves.toMatchObject({ packageVersion: "1.2.3" });
  });

  it("fails its check when generated bytes are stale", async () => {
    const paths = fixture();
    writeFileSync(paths.rules, "{}\n");
    await generateReleaseData({
      packageRoot: paths.root,
      outputPath: paths.output,
    });
    writeFileSync(paths.output, "stale\n");

    await expect(
      generateReleaseData({
        packageRoot: paths.root,
        outputPath: paths.output,
        check: true,
      }),
    ).rejects.toThrow("Generated release data is stale");
  });

  it("rejects a package manifest without a string version", async () => {
    const paths = fixture();
    writeFileSync(join(paths.root, "package.json"), '{"version":1}\n');
    writeFileSync(paths.rules, "{}\n");

    await expect(
      generateReleaseData({
        packageRoot: paths.root,
        outputPath: paths.output,
      }),
    ).rejects.toThrow("string version");
  });
});

describe("release entry imports", () => {
  it("imports guarded entry modules without running the CLI", () => {
    const tsxPath = join(packageRoot, "node_modules", "tsx", "dist", "cli.mjs");
    const probe = spawnSync(
      process.execPath,
      [
        tsxPath,
        "--eval",
        'Promise.all([import("./src/cli.ts"), import("./src/release.ts")]).catch((error) => { console.error(error); process.exitCode = 1; });',
      ],
      { cwd: packageRoot, encoding: "utf8", timeout: 20_000 },
    );

    expect(probe.error).toBeUndefined();
    expect(probe.status, probe.stderr).toBe(0);
    expect(probe.stdout).toBe("");
    expect(probe.stderr).toBe("");
  });
});
