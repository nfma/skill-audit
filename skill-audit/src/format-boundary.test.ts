import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

const packageRoot = join(import.meta.dirname, "..");
const repositoryRoot = join(packageRoot, "..");
const ignoredLegacyFiles = [
  "skill-audit/src/deps.ts",
  "skill-audit/src/discover.ts",
  "skill-audit/src/reporter.ts",
  "skill-audit/src/scoring.ts",
];

function readIgnoredFiles() {
  return readFileSync(join(repositoryRoot, ".prettierignore"), "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
}

describe("legacy format-debt boundary", () => {
  it("keeps the Prettier exclusion list exact and existing", () => {
    expect(readIgnoredFiles()).toEqual(ignoredLegacyFiles);
    for (const file of ignoredLegacyFiles) {
      expect(existsSync(join(repositoryRoot, file)), file).toBe(true);
    }
  });

  it("fails stale exclusions once their formatting debt is cleared", () => {
    const prettier = join(
      packageRoot,
      "node_modules",
      "prettier",
      "bin",
      "prettier.cjs",
    );

    for (const file of ignoredLegacyFiles) {
      const result = spawnSync(
        process.execPath,
        [prettier, "--check", "--ignore-path", ".gitignore", file],
        { cwd: repositoryRoot, encoding: "utf8" },
      );
      expect(result.status, `${file} unexpectedly became formatted`).not.toBe(
        0,
      );
    }
  });
});
