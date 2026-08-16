import { createHash } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { join, posix } from "node:path";

export const RELEASE_SCHEMA_VERSION = 1;
export const RELEASE_MAX_BYTES = 512 * 1024;
export const RELEASE_MINIMUM_NODE = "24.0.0";
export const RELEASE_EXPORTS = [
  "scanDependencies",
  "reportGroupedResults",
  "createGroupedAuditResult",
  "groupSecurityFindings",
  "auditSecurity",
  "validateSkillSpec",
] as const;

export interface DocumentationDigest {
  path: string;
  sha256: string;
}

export interface DocumentationDigestSet {
  files: DocumentationDigest[];
  upstreamDocsSha256: string;
}

export interface ReleaseDescriptor {
  schemaVersion: 1;
  version: string;
  tag: string;
  sourceRepository: "nfma/skill-audit";
  sourceCommit: string;
  buildWorkflow: string;
  minimumNode: "24.0.0";
  executable: {
    name: string;
    sha256: string;
    sizeBytes: number;
    exports: string[];
    embeddedRulesSha256: string;
  };
  documentation: DocumentationDigestSet;
}

export function sha256Hex(content: string | Uint8Array): string {
  return createHash("sha256").update(content).digest("hex");
}

export function normalizeDocumentationText(content: Uint8Array): string {
  const decoded = new TextDecoder("utf-8", { fatal: true }).decode(content);
  return decoded.replace(/\r\n?/g, "\n");
}

export function compareUtf8Bytes(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function isCanonicalDocumentationPath(path: string): boolean {
  if (path === "SKILL.md") {
    return true;
  }
  if (
    !path.startsWith("references/") ||
    path.includes("\\") ||
    [...path].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x1f || codePoint === 0x7f;
    })
  ) {
    return false;
  }

  const segments = path.split("/");
  return (
    segments.length > 1 &&
    segments[0] === "references" &&
    segments
      .slice(1)
      .every((segment) => segment !== "" && segment !== "." && segment !== "..")
  );
}

function assertDocumentationDigestSet(
  value: unknown,
): asserts value is DocumentationDigestSet {
  if (!value || typeof value !== "object") {
    throw new Error("Release descriptor has invalid documentation entries");
  }
  const documentation = value as Partial<DocumentationDigestSet>;
  if (!Array.isArray(documentation.files)) {
    throw new Error("Release descriptor has invalid documentation entries");
  }

  const documentationPaths = new Set<string>();
  for (const file of documentation.files) {
    if (
      !file ||
      typeof file.path !== "string" ||
      !isCanonicalDocumentationPath(file.path) ||
      documentationPaths.has(file.path) ||
      typeof file.sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(file.sha256)
    ) {
      throw new Error("Release descriptor has invalid documentation entries");
    }
    documentationPaths.add(file.path);
  }

  const sortedDocumentation = [...documentation.files].sort((left, right) =>
    Buffer.compare(
      Buffer.from(left.path, "utf8"),
      Buffer.from(right.path, "utf8"),
    ),
  );
  if (
    JSON.stringify(sortedDocumentation) !==
      JSON.stringify(documentation.files) ||
    !documentationPaths.has("SKILL.md") ||
    typeof documentation.upstreamDocsSha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(documentation.upstreamDocsSha256)
  ) {
    throw new Error("Release descriptor has invalid documentation ordering");
  }

  const aggregate = documentation.files
    .map(({ path, sha256 }) => `${path}\0${sha256}\n`)
    .join("");
  if (sha256Hex(aggregate) !== documentation.upstreamDocsSha256) {
    throw new Error(
      "Release descriptor has an invalid documentation aggregate",
    );
  }
}

function documentationPaths(packageRoot: string): string[] {
  const paths = ["SKILL.md"];
  const referencesRoot = join(packageRoot, "references");
  const referencesStat = lstatSync(referencesRoot);
  if (referencesStat.isSymbolicLink() || !referencesStat.isDirectory()) {
    throw new Error("references must be a regular directory, not a symlink");
  }

  const visit = (directory: string, relativeDirectory: string) => {
    const entries = readdirSync(directory, { withFileTypes: true });
    for (const entry of entries) {
      const absolutePath = join(directory, entry.name);
      const relativePath = posix.join(relativeDirectory, entry.name);
      const stat = lstatSync(absolutePath);
      if (stat.isSymbolicLink()) {
        throw new Error(
          `Documentation path must not be a symlink: ${relativePath}`,
        );
      }
      if (stat.isDirectory()) {
        visit(absolutePath, relativePath);
      } else if (stat.isFile()) {
        paths.push(relativePath);
      } else {
        throw new Error(
          `Documentation path must be a regular file: ${relativePath}`,
        );
      }
    }
  };

  visit(referencesRoot, "references");
  return paths;
}

export function computeDocumentationDigests(
  packageRoot: string,
): DocumentationDigestSet {
  const seen = new Set<string>();
  const paths = documentationPaths(packageRoot).sort(compareUtf8Bytes);
  const files = paths.map((relativePath) => {
    if (seen.has(relativePath)) {
      throw new Error(
        `Duplicate normalized documentation path: ${relativePath}`,
      );
    }
    seen.add(relativePath);

    const absolutePath = join(packageRoot, ...relativePath.split("/"));
    const descriptor = openSync(
      absolutePath,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
    );
    try {
      if (!fstatSync(descriptor).isFile()) {
        throw new Error(
          `Documentation path must be a regular file: ${relativePath}`,
        );
      }
      const normalized = normalizeDocumentationText(readFileSync(descriptor));
      return { path: relativePath, sha256: sha256Hex(normalized) };
    } finally {
      closeSync(descriptor);
    }
  });
  const aggregate = files
    .map(({ path, sha256 }) => `${path}\0${sha256}\n`)
    .join("");

  return { files, upstreamDocsSha256: sha256Hex(aggregate) };
}

export function createReleaseDescriptor(input: {
  version: string;
  sourceCommit: string;
  executableName: string;
  executableSha256: string;
  executableSizeBytes: number;
  embeddedRulesSha256: string;
  documentation: DocumentationDigestSet;
}): ReleaseDescriptor {
  if (!/^\d+\.\d+\.\d+$/.test(input.version)) {
    throw new Error(`Release version must be plain semver: ${input.version}`);
  }
  if (!/^[0-9a-f]{40}$/.test(input.sourceCommit)) {
    throw new Error("sourceCommit must be a full lowercase commit SHA");
  }
  if (
    !Number.isSafeInteger(input.executableSizeBytes) ||
    input.executableSizeBytes <= 0 ||
    input.executableSizeBytes > RELEASE_MAX_BYTES
  ) {
    throw new Error(
      `Executable size must be between 1 and ${RELEASE_MAX_BYTES} bytes`,
    );
  }
  assertDocumentationDigestSet(input.documentation);
  for (const digest of [input.executableSha256, input.embeddedRulesSha256]) {
    if (!/^[0-9a-f]{64}$/.test(digest)) {
      throw new Error(`Invalid lowercase SHA-256 digest: ${digest}`);
    }
  }

  const tag = `v${input.version}`;
  return {
    schemaVersion: RELEASE_SCHEMA_VERSION,
    version: input.version,
    tag,
    sourceRepository: "nfma/skill-audit",
    sourceCommit: input.sourceCommit,
    buildWorkflow: `.github/workflows/release.yml@${input.sourceCommit}`,
    minimumNode: RELEASE_MINIMUM_NODE,
    executable: {
      name: input.executableName,
      sha256: input.executableSha256,
      sizeBytes: input.executableSizeBytes,
      exports: [...RELEASE_EXPORTS],
      embeddedRulesSha256: input.embeddedRulesSha256,
    },
    documentation: input.documentation,
  };
}

export function assertReleaseDescriptor(
  value: unknown,
): asserts value is ReleaseDescriptor {
  if (!value || typeof value !== "object") {
    throw new Error("Release descriptor must be an object");
  }
  const descriptor = value as Partial<ReleaseDescriptor>;
  if (
    descriptor.schemaVersion !== RELEASE_SCHEMA_VERSION ||
    descriptor.sourceRepository !== "nfma/skill-audit" ||
    descriptor.minimumNode !== RELEASE_MINIMUM_NODE ||
    !descriptor.executable ||
    !descriptor.documentation
  ) {
    throw new Error("Release descriptor has an unsupported schema or identity");
  }
  if (
    typeof descriptor.version !== "string" ||
    !/^\d+\.\d+\.\d+$/.test(descriptor.version) ||
    descriptor.tag !== `v${descriptor.version}` ||
    typeof descriptor.sourceCommit !== "string" ||
    !/^[0-9a-f]{40}$/.test(descriptor.sourceCommit) ||
    descriptor.buildWorkflow !==
      `.github/workflows/release.yml@${descriptor.sourceCommit}`
  ) {
    throw new Error("Release descriptor has inconsistent source identity");
  }
  if (
    !Number.isSafeInteger(descriptor.executable.sizeBytes) ||
    descriptor.executable.sizeBytes <= 0 ||
    descriptor.executable.sizeBytes > RELEASE_MAX_BYTES
  ) {
    throw new Error("Release descriptor has an invalid executable size");
  }
  if (
    JSON.stringify(descriptor.executable.exports) !==
    JSON.stringify(RELEASE_EXPORTS)
  ) {
    throw new Error("Release descriptor has an invalid export contract");
  }
  if (
    descriptor.executable.name !== `skill-audit-v${descriptor.version}.mjs` ||
    !/^[0-9a-f]{64}$/.test(descriptor.executable.sha256) ||
    !/^[0-9a-f]{64}$/.test(descriptor.executable.embeddedRulesSha256)
  ) {
    throw new Error("Release descriptor has invalid executable identity");
  }
  assertDocumentationDigestSet(descriptor.documentation);
}
