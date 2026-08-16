import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { isDirectExecution } from "./direct-execution.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("direct execution detection", () => {
  it("matches canonical and symlinked entry paths", () => {
    const directory = mkdtempSync(join(tmpdir(), "skill-audit-direct-"));
    temporaryDirectories.push(directory);
    const nested = join(directory, "nested");
    mkdirSync(nested);
    const entry = join(nested, "skill-audit.mjs");
    const link = join(directory, "skill-audit-link.mjs");
    writeFileSync(entry, "export {};\n");
    symlinkSync(entry, link);

    const moduleUrl = pathToFileURL(entry).href;
    expect(isDirectExecution(moduleUrl, entry)).toBe(true);
    expect(isDirectExecution(moduleUrl, link)).toBe(true);
  });

  it("fails closed for missing or different entry paths", () => {
    const directory = mkdtempSync(join(tmpdir(), "skill-audit-direct-"));
    temporaryDirectories.push(directory);
    const entry = join(directory, "skill-audit.mjs");
    const other = join(directory, "other.mjs");
    writeFileSync(entry, "export {};\n");
    writeFileSync(other, "export {};\n");

    const moduleUrl = pathToFileURL(entry).href;
    expect(isDirectExecution(moduleUrl, undefined)).toBe(false);
    expect(isDirectExecution(moduleUrl, join(directory, "missing.mjs"))).toBe(
      false,
    );
    expect(isDirectExecution(moduleUrl, other)).toBe(false);
  });
});
