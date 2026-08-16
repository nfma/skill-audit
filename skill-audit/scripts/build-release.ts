#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { builtinModules } from "node:module";
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import {
  computeDocumentationDigests,
  createReleaseDescriptor,
  RELEASE_MAX_BYTES,
  sha256Hex,
} from "../src/release-assets.js";
import {
  EMBEDDED_RULES_SHA256,
  PACKAGE_VERSION,
} from "../src/generated/release-data.js";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(packageRoot, "..");
const gitExecutable = "/usr/bin/git";
const outputDirectory = resolve(
  process.env.RELEASE_OUTPUT_DIR ?? join(packageRoot, "release"),
);
const expectedTag = `v${PACKAGE_VERSION}`;
const releaseTag = process.env.RELEASE_TAG ?? expectedTag;
const sourceCommit =
  process.env.SOURCE_COMMIT ??
  execFileSync(gitExecutable, ["rev-parse", "HEAD"], {
    cwd: repositoryRoot,
    encoding: "utf8",
  }).trim();

if (releaseTag !== expectedTag) {
  throw new Error(
    `Release tag ${releaseTag} does not match package version ${PACKAGE_VERSION}`,
  );
}
if (!/^[0-9a-f]{40}$/.test(sourceCommit)) {
  throw new Error("SOURCE_COMMIT must be a full lowercase commit SHA");
}

const executableName = `skill-audit-${releaseTag}.mjs`;
const checksumName = `${executableName}.sha256`;
const descriptorName = `skill-audit-${releaseTag}-release.json`;
const executablePath = join(outputDirectory, executableName);
const checksumPath = join(outputDirectory, checksumName);
const descriptorPath = join(outputDirectory, descriptorName);

rmSync(outputDirectory, { recursive: true, force: true });
mkdirSync(outputDirectory, { recursive: true });

const result = await build({
  entryPoints: [join(packageRoot, "src", "release.ts")],
  outfile: executablePath,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node24",
  minify: true,
  treeShaking: true,
  legalComments: "inline",
  sourcemap: false,
  metafile: true,
  define: {
    __SKILL_AUDIT_RELEASE__: "true",
  },
  banner: {
    js:
      "#!/usr/bin/env node\n" +
      'import { createRequire as __skillAuditCreateRequire } from "node:module";\n' +
      "const require = __skillAuditCreateRequire(import.meta.url);",
  },
});

const allowedBuiltins = new Set([
  ...builtinModules,
  ...builtinModules.map((name) => `node:${name}`),
]);
const unresolvedImports = Object.values(result.metafile.outputs)
  .flatMap((output) => output.imports)
  .filter((entry) => entry.external && !allowedBuiltins.has(entry.path));
if (unresolvedImports.length > 0) {
  throw new Error(
    `Release bundle contains unresolved package imports: ${unresolvedImports
      .map((entry) => entry.path)
      .join(", ")}`,
  );
}

const executableBytes = readFileSync(executablePath);
const executableText = executableBytes.toString("utf8");
if (!executableText.startsWith("#!/usr/bin/env node\n")) {
  throw new Error("Release executable is missing the required Node shebang");
}
if (executableText.includes("#!", 2)) {
  throw new Error("Release executable contains more than one shebang");
}
if (executableBytes.byteLength > RELEASE_MAX_BYTES) {
  throw new Error(
    `Release executable is ${executableBytes.byteLength} bytes; maximum is ${RELEASE_MAX_BYTES}`,
  );
}
chmodSync(executablePath, 0o755);

const executableSha256 = sha256Hex(executableBytes);
const documentation = computeDocumentationDigests(packageRoot);
const descriptor = createReleaseDescriptor({
  version: PACKAGE_VERSION,
  sourceCommit,
  executableName,
  executableSha256,
  executableSizeBytes: statSync(executablePath).size,
  embeddedRulesSha256: EMBEDDED_RULES_SHA256,
  documentation,
});

writeFileSync(checksumPath, `${executableSha256}  ${executableName}\n`);
writeFileSync(descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`);

console.log(
  JSON.stringify({
    version: PACKAGE_VERSION,
    tag: releaseTag,
    sourceCommit,
    executableName,
    executableSha256,
    executableSizeBytes: executableBytes.byteLength,
    checksumName,
    descriptorName,
    descriptorSha256: sha256Hex(readFileSync(descriptorPath)),
  }),
);
