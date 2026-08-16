#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
  mkdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import {
  assertReleaseDescriptor,
  computeDocumentationDigests,
  RELEASE_EXPORTS,
  sha256Hex,
} from "../src/release-assets.js";
import { auditSecurity as auditSecurityFromSource } from "../src/security.js";
import { validateSkillSpec as validateSkillSpecFromSource } from "../src/spec.js";
import {
  EMBEDDED_RULES_SHA256,
  PACKAGE_VERSION,
} from "../src/generated/release-data.js";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const releaseDirectory = resolve(
  process.env.RELEASE_OUTPUT_DIR ?? join(packageRoot, "release"),
);
const descriptorPath = readdirSync(releaseDirectory)
  .filter((name) => name.endsWith("-release.json"))
  .map((name) => join(releaseDirectory, name));
if (descriptorPath.length !== 1) {
  throw new Error("Release directory must contain exactly one descriptor");
}

const descriptorValue: unknown = JSON.parse(
  readFileSync(descriptorPath[0], "utf8"),
);
assertReleaseDescriptor(descriptorValue);
const descriptor = descriptorValue;
if (
  descriptor.version !== PACKAGE_VERSION ||
  descriptor.executable.embeddedRulesSha256 !== EMBEDDED_RULES_SHA256
) {
  throw new Error("Release descriptor differs from the generated source data");
}
const expectedFiles = [
  descriptor.executable.name,
  `${descriptor.executable.name}.sha256`,
  `skill-audit-${descriptor.tag}-release.json`,
].sort();
const actualFiles = readdirSync(releaseDirectory).sort();
if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
  throw new Error(
    `Release directory contents differ: ${JSON.stringify(actualFiles)}`,
  );
}
if (process.env.RELEASE_TAG && descriptor.tag !== process.env.RELEASE_TAG) {
  throw new Error("Release descriptor tag does not match RELEASE_TAG");
}
if (
  process.env.SOURCE_COMMIT &&
  descriptor.sourceCommit !== process.env.SOURCE_COMMIT
) {
  throw new Error("Release descriptor commit does not match SOURCE_COMMIT");
}

const executablePath = join(releaseDirectory, descriptor.executable.name);
const executableBytes = readFileSync(executablePath);
const executableText = executableBytes.toString("utf8");
if (sha256Hex(executableBytes) !== descriptor.executable.sha256) {
  throw new Error("Release executable SHA-256 does not match the descriptor");
}
if (executableBytes.byteLength !== descriptor.executable.sizeBytes) {
  throw new Error("Release executable size does not match the descriptor");
}
const checksum = readFileSync(`${executablePath}.sha256`, "utf8");
if (
  checksum !==
  `${descriptor.executable.sha256}  ${descriptor.executable.name}\n`
) {
  throw new Error("Release checksum file does not match the descriptor");
}
if (!executableText.startsWith("#!/usr/bin/env node\n")) {
  throw new Error("Release executable has an invalid shebang");
}
if (executableText.indexOf("#!", 2) !== -1) {
  throw new Error("Release executable contains more than one shebang");
}
if (!lstatSync(executablePath).isFile()) {
  throw new Error("Release executable is not a regular file");
}

const documentation = computeDocumentationDigests(packageRoot);
if (
  JSON.stringify(documentation) !== JSON.stringify(descriptor.documentation)
) {
  throw new Error("Release documentation digests do not match the source tree");
}

function runNode(arguments_: string[]) {
  const result = spawnSync(process.execPath, arguments_, {
    cwd: packageRoot,
    encoding: "utf8",
    timeout: 20_000,
    env: {
      ...process.env,
      SKILL_AUDIT_CACHE_DIR: join(tmpdir(), "skill-audit-release-verify-cache"),
    },
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `Node command failed: ${result.error?.message ?? result.stderr}`,
    );
  }
  return result;
}

runNode(["--check", executablePath]);
const versionResult = runNode([executablePath, "--version"]);
if (versionResult.stdout.trim() !== descriptor.version) {
  throw new Error("Release executable reports the wrong version");
}

const importProbe = runNode([
  "--input-type=module",
  "--eval",
  `const value = await import(${JSON.stringify(pathToFileURL(executablePath).href)}); process.stdout.write(JSON.stringify(Object.keys(value).sort()));`,
]);
const expectedExports = [...RELEASE_EXPORTS].sort();
if (
  importProbe.stderr !== "" ||
  importProbe.stdout !== JSON.stringify(expectedExports)
) {
  throw new Error("Release executable import contract or side effects differ");
}

const fixtureRoot = mkdtempSync(join(tmpdir(), "skill-audit-release-"));
try {
  const fixtureSkill = join(fixtureRoot, "fixture");
  // example.com is reserved for documentation by RFC 2606; compose the fixture
  // so source scanning does not mistake it for real PII.
  const reservedEmailFixture = ["test", "example.com"].join("@");
  mkdirSync(fixtureSkill);
  writeFileSync(
    join(fixtureSkill, "SKILL.md"),
    `---\nname: fixture\ndescription: Contains a deterministic ${reservedEmailFixture} fixture.\n---\n\n# Fixture\n`,
  );

  const auditResult = runNode([
    executablePath,
    "--path",
    fixtureSkill,
    "--no-deps",
    "--json",
  ]);
  const parsedAudit = JSON.parse(auditResult.stdout);
  if (parsedAudit[0]?.piiFindings?.[0]?.id !== "PII-022") {
    throw new Error(
      "Release executable did not use the embedded rule database",
    );
  }

  const symlinkPath = join(fixtureRoot, "skill-audit-link.mjs");
  symlinkSync(executablePath, symlinkPath);
  const symlinkResult = runNode([symlinkPath, "--version"]);
  if (symlinkResult.stdout.trim() !== descriptor.version) {
    throw new Error("Symlinked direct execution did not run the CLI");
  }

  const skill = {
    name: "fixture",
    path: fixtureSkill,
    agents: [],
    scope: "project" as const,
  };
  const sourceSpec = validateSkillSpecFromSource(fixtureSkill, "fixture");
  const sourceSecurity = auditSecurityFromSource(skill, sourceSpec.manifest);
  const bundled = await import(pathToFileURL(executablePath).href);
  const bundledSpec = bundled.validateSkillSpec(fixtureSkill, "fixture");
  const bundledSecurity = bundled.auditSecurity(skill, bundledSpec.manifest);
  if (
    JSON.stringify({
      spec: sourceSpec.findings,
      security: sourceSecurity.findings,
    }) !==
    JSON.stringify({
      spec: bundledSpec.findings,
      security: bundledSecurity.findings,
    })
  ) {
    throw new Error(
      "Embedded rules differ from the file-backed development rules",
    );
  }
} finally {
  rmSync(fixtureRoot, { recursive: true, force: true });
}

console.log(
  `Verified ${descriptor.executable.name} (${descriptor.executable.sizeBytes} bytes)`,
);
