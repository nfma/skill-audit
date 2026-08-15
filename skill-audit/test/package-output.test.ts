import { execFileSync } from "child_process";
import { existsSync, mkdirSync, readdirSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { describe, expect, it } from "vitest";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const distPath = join(packageRoot, "dist");
const cleanScript = join(packageRoot, "scripts", "clean.cjs");
const tscScript = join(packageRoot, "node_modules", "typescript", "bin", "tsc");

function listFiles(directory: string, prefix = ""): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const relativePath = join(prefix, entry.name);
    return entry.isDirectory()
      ? listFiles(join(directory, entry.name), relativePath)
      : [relativePath];
  });
}

describe("package build output", () => {
  it("cleans stale output and emits production modules without compiled tests", () => {
    mkdirSync(distPath, { recursive: true });
    writeFileSync(join(distPath, "stale.test.js"), "stale");

    execFileSync(process.execPath, [cleanScript], { cwd: packageRoot });
    expect(existsSync(distPath)).toBe(false);

    execFileSync(process.execPath, [tscScript, "--project", packageRoot], { cwd: packageRoot });
    const emittedFiles = listFiles(distPath);

    expect(emittedFiles.length).toBeGreaterThan(0);
    expect(emittedFiles.filter(file => file.endsWith(".test.js"))).toEqual([]);
  });
});
