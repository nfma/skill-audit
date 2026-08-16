import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildRelease } from "../scripts/build-release.js";
import { verifyRelease } from "../scripts/verify-release.js";
import {
  canonicalizeJson,
  compareUtf8Bytes,
  type ReleaseDescriptor,
  RELEASE_EXPORTS,
  RELEASE_MAX_BYTES,
  sha256Hex,
} from "./release-assets.js";
import {
  EMBEDDED_DEFAULT_PATTERNS_BASE64,
  EMBEDDED_RULES_SHA256,
} from "./generated/release-data.js";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
let releaseDirectory: string;

function copyReleaseDirectory(): { root: string; release: string } {
  const root = mkdtempSync(join(tmpdir(), "skill-audit-release-copy-"));
  const release = join(root, "release");
  cpSync(releaseDirectory, release, { recursive: true });
  return { root, release };
}

function descriptorPath(release: string): string {
  return join(release, "skill-audit-v0.10.0-release.json");
}

function readDescriptor(release: string): ReleaseDescriptor {
  return JSON.parse(readFileSync(descriptorPath(release), "utf8"));
}

function writeDescriptor(release: string, descriptor: ReleaseDescriptor): void {
  writeFileSync(
    descriptorPath(release),
    `${JSON.stringify(descriptor, null, 2)}\n`,
  );
}

function rebindExecutable(release: string, executableText: string): void {
  const descriptor = readDescriptor(release);
  const executablePath = join(release, descriptor.executable.name);
  const executableBytes = Buffer.from(executableText, "utf8");
  descriptor.executable.sha256 = sha256Hex(executableBytes);
  descriptor.executable.sizeBytes = executableBytes.byteLength;
  writeFileSync(executablePath, executableBytes);
  writeFileSync(
    `${executablePath}.sha256`,
    `${descriptor.executable.sha256}  ${descriptor.executable.name}\n`,
  );
  writeDescriptor(release, descriptor);
}

function replaceEmbeddedTransport(
  executable: string,
  replacement: string,
): string {
  if (replacement.length !== EMBEDDED_DEFAULT_PATTERNS_BASE64.length) {
    throw new Error("replacement transport must preserve encoded length");
  }
  let updated = executable;
  const generatedChunkWidth = 96;
  for (
    let offset = 0;
    offset < EMBEDDED_DEFAULT_PATTERNS_BASE64.length;
    offset += generatedChunkWidth
  ) {
    const sourceChunk = EMBEDDED_DEFAULT_PATTERNS_BASE64.slice(
      offset,
      offset + generatedChunkWidth,
    );
    const replacementChunk = replacement.slice(
      offset,
      offset + generatedChunkWidth,
    );
    if (!updated.includes(sourceChunk)) {
      throw new Error(`release bundle is missing generated chunk ${offset}`);
    }
    updated = updated.replace(sourceChunk, replacementChunk);
  }
  return updated;
}

interface MutableRuleDatabase {
  categories: Record<
    string,
    { patterns: Array<{ message: string; pattern: string }> }
  >;
}

function alterEmbeddedRules(
  executable: string,
  mutate: (rules: MutableRuleDatabase) => void,
): string {
  const decoded = JSON.parse(
    Buffer.from(EMBEDDED_DEFAULT_PATTERNS_BASE64, "base64").toString("utf8"),
  ) as MutableRuleDatabase;
  mutate(decoded);
  const alteredCanonical = canonicalizeJson(decoded);
  const alteredBase64 = Buffer.from(alteredCanonical, "utf8").toString(
    "base64",
  );
  const alteredSha256 = sha256Hex(alteredCanonical);
  return replaceEmbeddedTransport(executable, alteredBase64).replaceAll(
    EMBEDDED_RULES_SHA256,
    alteredSha256,
  );
}

async function expectVerificationFailure(
  mutate: (release: string) => void,
  message: string,
): Promise<void> {
  const copied = copyReleaseDirectory();
  try {
    mutate(copied.release);
    await expect(
      verifyRelease({
        packageRoot,
        releaseDirectory: copied.release,
        releaseTag: "v0.10.0",
        sourceCommit: "a".repeat(40),
      }),
    ).rejects.toThrow(message);
  } finally {
    rmSync(copied.root, { recursive: true, force: true });
  }
}

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

  it("fails closed at the API and CLI boundaries when embedded rules are corrupted", async () => {
    const copied = copyReleaseDirectory();
    try {
      const executablePath = join(copied.release, "skill-audit-v0.10.0.mjs");
      const executableText = readFileSync(executablePath, "utf8");
      const replacementPrefix =
        EMBEDDED_DEFAULT_PATTERNS_BASE64[0] === "A" ? "B" : "A";
      const corruptedText = replaceEmbeddedTransport(
        executableText,
        `${replacementPrefix}${EMBEDDED_DEFAULT_PATTERNS_BASE64.slice(1)}`,
      );
      writeFileSync(executablePath, corruptedText);

      const fixtureSkill = join(copied.root, "fixture");
      mkdirSync(fixtureSkill);
      writeFileSync(
        join(fixtureSkill, "SKILL.md"),
        "---\nname: fixture\ndescription: Corrupted release fixture.\n---\n\n# Fixture\n",
      );
      const skill = {
        name: "fixture",
        path: fixtureSkill,
        agents: [],
        scope: "project" as const,
      };
      const bundled = await import(
        `${pathToFileURL(executablePath).href}?corrupted=${Date.now()}`
      );
      expect(() => bundled.auditSecurity(skill, undefined)).toThrow(
        "Embedded rule database could not be decoded",
      );

      const cli = spawnSync(
        process.execPath,
        [executablePath, "--path", fixtureSkill, "--no-deps", "--json"],
        { encoding: "utf8", timeout: 20_000 },
      );
      expect(cli.error).toBeUndefined();
      expect(cli.status).not.toBe(0);
      expect(cli.stdout).toBe("");
      expect(cli.stderr).toContain(
        "Embedded rule database could not be decoded",
      );
    } finally {
      rmSync(copied.root, { recursive: true, force: true });
    }
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

  it("requires the descriptor to match generated data, tag, and current commit", async () => {
    await expectVerificationFailure((release) => {
      const descriptor = readDescriptor(release);
      descriptor.executable.embeddedRulesSha256 = "d".repeat(64);
      writeDescriptor(release, descriptor);
    }, "differs from the generated source data");

    await expect(
      verifyRelease({
        packageRoot,
        releaseDirectory,
        releaseTag: "v0.10.1",
        sourceCommit: "a".repeat(40),
      }),
    ).rejects.toThrow("tag does not match");
    await expect(
      verifyRelease({ packageRoot, releaseDirectory }),
    ).rejects.toThrow("commit does not match");
  });

  it("rejects executable digest, size, and checksum drift", async () => {
    await expectVerificationFailure((release) => {
      const descriptor = readDescriptor(release);
      writeFileSync(
        join(release, descriptor.executable.name),
        `${readFileSync(join(release, descriptor.executable.name), "utf8")} `,
      );
    }, "SHA-256 does not match");

    await expectVerificationFailure((release) => {
      const descriptor = readDescriptor(release);
      descriptor.executable.sizeBytes += 1;
      writeDescriptor(release, descriptor);
    }, "size does not match");

    await expectVerificationFailure((release) => {
      const descriptor = readDescriptor(release);
      writeFileSync(
        join(release, `${descriptor.executable.name}.sha256`),
        "incorrect\n",
      );
    }, "checksum file does not match");
  });

  it("rejects invalid and duplicate executable shebangs", async () => {
    await expectVerificationFailure((release) => {
      const descriptor = readDescriptor(release);
      const executable = readFileSync(
        join(release, descriptor.executable.name),
        "utf8",
      );
      rebindExecutable(
        release,
        executable.replace("#!/usr/bin/env node\n", "// missing shebang\n"),
      );
    }, "invalid shebang");

    await expectVerificationFailure((release) => {
      const descriptor = readDescriptor(release);
      const executable = readFileSync(
        join(release, descriptor.executable.name),
        "utf8",
      );
      rebindExecutable(
        release,
        executable.replace(
          "#!/usr/bin/env node\n",
          "#!/usr/bin/env node\n#!/usr/bin/env node\n",
        ),
      );
    }, "more than one shebang");
  });

  it("rejects non-files, invalid JavaScript, and import contract drift", async () => {
    await expectVerificationFailure((release) => {
      const descriptor = readDescriptor(release);
      const executablePath = join(release, descriptor.executable.name);
      const target = join(release, "..", "linked-executable.mjs");
      writeFileSync(target, readFileSync(executablePath));
      rmSync(executablePath);
      symlinkSync(target, executablePath);
    }, "not a regular file");

    await expectVerificationFailure((release) => {
      const descriptor = readDescriptor(release);
      const executable = readFileSync(
        join(release, descriptor.executable.name),
        "utf8",
      );
      rebindExecutable(release, `${executable}\nthis is not valid JavaScript`);
    }, "Node command failed");

    await expectVerificationFailure((release) => {
      const descriptor = readDescriptor(release);
      const executable = readFileSync(
        join(release, descriptor.executable.name),
        "utf8",
      );
      rebindExecutable(
        release,
        `${executable}\nexport const unexpectedReleaseExport = true;\n`,
      );
    }, "import contract or side effects differ");
  });

  it("rejects a bundle whose valid embedded rules diverge from source", async () => {
    await expectVerificationFailure((release) => {
      const descriptor = readDescriptor(release);
      const executablePath = join(release, descriptor.executable.name);
      const executable = readFileSync(executablePath, "utf8");
      expect(executable).toContain(EMBEDDED_RULES_SHA256);
      rebindExecutable(
        release,
        alterEmbeddedRules(executable, (rules) => {
          const originalMessage =
            rules.categories.promptInjection.patterns[0].message;
          rules.categories.promptInjection.patterns[0].message = `X${originalMessage.slice(1)}`;
        }),
      );
    }, "Embedded rules differ from the file-backed development rules");
  });

  it("rejects a parity corpus that no longer exercises every rule category", async () => {
    await expectVerificationFailure((release) => {
      const descriptor = readDescriptor(release);
      const executable = readFileSync(
        join(release, descriptor.executable.name),
        "utf8",
      );
      rebindExecutable(
        release,
        alterEmbeddedRules(executable, (rules) => {
          const promptRule =
            rules.categories.promptInjection.patterns[0].pattern;
          rules.categories.promptInjection.patterns[0].pattern = `X${promptRule.slice(1)}`;
        }),
      );
    }, "did not exercise the complete parity corpus");
  });

  it("rejects documentation digest drift", async () => {
    await expectVerificationFailure((release) => {
      const descriptor = readDescriptor(release);
      descriptor.documentation.files[0].sha256 = "d".repeat(64);
      const aggregate = descriptor.documentation.files
        .map(({ path, sha256 }) => `${path}\0${sha256}\n`)
        .join("");
      descriptor.documentation.upstreamDocsSha256 = sha256Hex(aggregate);
      writeDescriptor(release, descriptor);
    }, "documentation digests do not match");
  });
});
