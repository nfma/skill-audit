import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  assertReleaseDescriptor,
  computeDocumentationDigests,
  createReleaseDescriptor,
  normalizeDocumentationText,
  RELEASE_EXPORTS,
  RELEASE_MAX_BYTES,
} from "./release-assets.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function documentationFixture() {
  const root = mkdtempSync(join(tmpdir(), "skill-audit-docs-"));
  temporaryDirectories.push(root);
  mkdirSync(join(root, "references", "nested"), { recursive: true });
  writeFileSync(join(root, "SKILL.md"), "skill\r\nline\r");
  writeFileSync(join(root, "references", "z.md"), "z\r\n");
  writeFileSync(join(root, "references", "a.md"), "a\n");
  writeFileSync(join(root, "references", "nested", "b.md"), "b\r");
  return root;
}

function releaseDescriptorFixture() {
  return createReleaseDescriptor({
    version: "0.10.0",
    sourceCommit: "a".repeat(40),
    executableName: "skill-audit-v0.10.0.mjs",
    executableSha256: "b".repeat(64),
    executableSizeBytes: 123,
    embeddedRulesSha256: "c".repeat(64),
    documentation: computeDocumentationDigests(documentationFixture()),
  });
}

describe("release documentation digests", () => {
  it("normalizes line endings and sorts paths by UTF-8 bytes", () => {
    const root = documentationFixture();
    const digests = computeDocumentationDigests(root);

    expect(digests.files.map((file) => file.path)).toEqual([
      "SKILL.md",
      "references/a.md",
      "references/nested/b.md",
      "references/z.md",
    ]);
    expect(normalizeDocumentationText(Buffer.from("a\r\nb\rc\n"))).toBe(
      "a\nb\nc\n",
    );

    writeFileSync(join(root, "SKILL.md"), "skill\nline\n");
    expect(computeDocumentationDigests(root)).toEqual(digests);
  });

  it("rejects documentation symlinks", () => {
    const root = documentationFixture();
    symlinkSync(
      join(root, "references", "a.md"),
      join(root, "references", "link.md"),
    );

    expect(() => computeDocumentationDigests(root)).toThrow(
      "must not be a symlink",
    );
  });
});

describe("release descriptor", () => {
  it("binds the exact executable and documentation contract", () => {
    const descriptor = releaseDescriptorFixture();

    expect(descriptor.tag).toBe("v0.10.0");
    expect(descriptor.minimumNode).toBe("24.0.0");
    expect(descriptor.executable.exports).toEqual(RELEASE_EXPORTS);
    expect(descriptor.buildWorkflow).toBe(
      `.github/workflows/release.yml@${"a".repeat(40)}`,
    );
    expect(() => assertReleaseDescriptor(descriptor)).not.toThrow();
  });

  it("rejects non-canonical documentation paths", () => {
    for (const path of [
      "/tmp/SKILL.md",
      "../SKILL.md",
      "references/../SKILL.md",
      "references/./a.md",
      "references//a.md",
      "references\\a.md",
      "references/a\u0000b.md",
    ]) {
      const descriptor = releaseDescriptorFixture();
      descriptor.documentation.files[1].path = path;
      expect(() => assertReleaseDescriptor(descriptor), path).toThrow(
        "invalid documentation entries",
      );
    }
  });

  it("rejects malformed and internally inconsistent documentation sets", () => {
    const malformed = releaseDescriptorFixture() as unknown as {
      documentation: { files: unknown; upstreamDocsSha256: string };
    };
    malformed.documentation.files = null;
    expect(() => assertReleaseDescriptor(malformed)).toThrow(
      "invalid documentation entries",
    );

    const inconsistent = releaseDescriptorFixture();
    inconsistent.documentation.upstreamDocsSha256 = "d".repeat(64);
    expect(() => assertReleaseDescriptor(inconsistent)).toThrow(
      "invalid documentation aggregate",
    );
  });

  it("refuses to create a descriptor from an inconsistent documentation set", () => {
    const documentation = computeDocumentationDigests(documentationFixture());
    documentation.upstreamDocsSha256 = "d".repeat(64);

    expect(() =>
      createReleaseDescriptor({
        version: "0.10.0",
        sourceCommit: "a".repeat(40),
        executableName: "skill-audit-v0.10.0.mjs",
        executableSha256: "b".repeat(64),
        executableSizeBytes: 123,
        embeddedRulesSha256: "c".repeat(64),
        documentation,
      }),
    ).toThrow("invalid documentation aggregate");
  });

  it("rejects zero, placeholder, mismatched-scale, and oversized lengths", () => {
    const documentation = computeDocumentationDigests(documentationFixture());
    const base = {
      version: "0.10.0",
      sourceCommit: "a".repeat(40),
      executableName: "skill-audit-v0.10.0.mjs",
      executableSha256: "b".repeat(64),
      embeddedRulesSha256: "c".repeat(64),
      documentation,
    };

    for (const executableSizeBytes of [
      0,
      Number.NaN,
      "123" as unknown as number,
      RELEASE_MAX_BYTES + 1,
    ]) {
      expect(() =>
        createReleaseDescriptor({ ...base, executableSizeBytes }),
      ).toThrow("Executable size");
    }
  });
});
