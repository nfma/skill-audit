import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { Finding, FindingCategory } from "./types.js";
import {
  EMBEDDED_DEFAULT_PATTERNS_BASE64,
  EMBEDDED_RULES_SHA256,
} from "./generated/release-data.js";

declare const __SKILL_AUDIT_RELEASE__: boolean;

const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(PACKAGE_ROOT, "rules");
export const DEFAULT_PATTERNS_FILE = join(RULES_DIR, "default-patterns.json");
export const DEFAULT_PATTERNS_SHA256 = EMBEDDED_RULES_SHA256;
const IS_RELEASE_BUNDLE =
  typeof __SKILL_AUDIT_RELEASE__ !== "undefined" && __SKILL_AUDIT_RELEASE__;
let embeddedPatterns: PatternsFile | undefined;

export interface PatternRule {
  pattern: string;
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  message: string;
  flags?: string;
}

export interface PatternCategory {
  name: string;
  description: string;
  patterns: PatternRule[];
}

export interface PatternsFile {
  version: string;
  updated: string;
  description: string;
  categories: Record<string, PatternCategory>;
}

function assertPatternsFile(value: unknown): asserts value is PatternsFile {
  if (!value || typeof value !== "object") {
    throw new TypeError("Embedded rule database must be an object");
  }
  const candidate = value as Partial<PatternsFile>;
  if (
    typeof candidate.version !== "string" ||
    typeof candidate.updated !== "string" ||
    typeof candidate.description !== "string" ||
    !candidate.categories ||
    typeof candidate.categories !== "object" ||
    Object.keys(candidate.categories).length === 0
  ) {
    throw new TypeError("Embedded rule database has invalid metadata");
  }

  let patternCount = 0;
  for (const category of Object.values(candidate.categories)) {
    if (
      !category ||
      typeof category.name !== "string" ||
      typeof category.description !== "string" ||
      !Array.isArray(category.patterns)
    ) {
      throw new TypeError("Embedded rule database has an invalid category");
    }
    for (const rule of category.patterns) {
      if (
        !rule ||
        typeof rule.pattern !== "string" ||
        typeof rule.id !== "string" ||
        !["critical", "high", "medium", "low"].includes(rule.severity) ||
        typeof rule.message !== "string" ||
        (rule.flags !== undefined && typeof rule.flags !== "string")
      ) {
        throw new TypeError("Embedded rule database has an invalid pattern");
      }
      patternCount += 1;
    }
  }
  if (patternCount === 0) {
    throw new TypeError("Embedded rule database must contain patterns");
  }
}

export function decodeEmbeddedPatterns(
  encoded: string,
  expectedSha256: string,
): PatternsFile {
  try {
    const bytes = Buffer.from(encoded, "base64");
    if (encoded === "" || bytes.toString("base64") !== encoded) {
      throw new TypeError("Embedded rule database is not canonical base64");
    }
    const canonicalJson = new TextDecoder("utf-8", { fatal: true }).decode(
      bytes,
    );
    const actualSha256 = createHash("sha256")
      .update(canonicalJson)
      .digest("hex");
    if (actualSha256 !== expectedSha256) {
      throw new TypeError("Embedded rule database digest does not match");
    }
    const parsed: unknown = JSON.parse(canonicalJson);
    assertPatternsFile(parsed);
    return parsed;
  } catch (error) {
    throw new Error("Embedded rule database could not be decoded", {
      cause: error,
    });
  }
}

export function loadEmbeddedPatterns(): PatternsFile {
  embeddedPatterns ??= decodeEmbeddedPatterns(
    EMBEDDED_DEFAULT_PATTERNS_BASE64,
    EMBEDDED_RULES_SHA256,
  );
  return embeddedPatterns;
}

export interface CompiledPattern {
  regex: RegExp;
  id: string;
  severity: Finding["severity"];
  message: string;
  category: FindingCategory;
  asi: string;
}

const EXTERNAL_CATEGORY_METADATA: Record<
  string,
  { category: FindingCategory; asi: string }
> = {
  promptInjection: { category: "PI", asi: "ASI01" },
  credentialLeaks: { category: "SC", asi: "ASI04" },
  shellInjection: { category: "CE", asi: "ASI05" },
  sqlInjection: { category: "CE", asi: "ASI06" },
  pathTraversal: { category: "TM", asi: "ASI07" },
  exfiltration: { category: "TM", asi: "ASI02" },
  secrets: { category: "SC", asi: "ASI04" },
  toolMisuse: { category: "TM", asi: "ASI02" },
  behavioral: { category: "BM", asi: "ASI09" },
  pii: { category: "PII", asi: "ASI03" },
};

/**
 * Load patterns from JSON file
 */
export function loadPatterns(patternsFile?: string): PatternsFile {
  if (patternsFile === undefined && IS_RELEASE_BUNDLE) {
    return loadEmbeddedPatterns();
  }

  const resolvedPatternsFile = patternsFile ?? DEFAULT_PATTERNS_FILE;
  if (!existsSync(resolvedPatternsFile)) {
    throw new Error(`Patterns file not found: ${resolvedPatternsFile}`);
  }

  const content = readFileSync(resolvedPatternsFile, "utf-8");
  return JSON.parse(content) as PatternsFile;
}

/**
 * Compile patterns to RegExp objects
 */
export function compilePatterns(
  patterns: PatternsFile,
): Map<string, CompiledPattern[]> {
  const compiled = new Map<string, CompiledPattern[]>();

  for (const [categoryKey, category] of Object.entries(patterns.categories)) {
    const categoryPatterns: CompiledPattern[] = [];
    const categoryMetadata = EXTERNAL_CATEGORY_METADATA[categoryKey] ?? {
      category: "SC" as const,
      asi: "ASI04",
    };

    for (const rule of category.patterns) {
      let regex: RegExp;
      try {
        regex = new RegExp(rule.pattern, rule.flags || "i");
      } catch (error) {
        throw new Error(`Pattern ${rule.id} could not be compiled`, {
          cause: error,
        });
      }
      categoryPatterns.push({
        regex,
        id: rule.id,
        severity: rule.severity,
        message: rule.message,
        category: categoryMetadata.category,
        asi: categoryMetadata.asi,
      });
    }

    compiled.set(categoryKey, categoryPatterns);
  }

  return compiled;
}

export function countCompiledPatterns(
  patterns: Map<string, CompiledPattern[]>,
): number {
  let count = 0;
  for (const categoryPatterns of patterns.values()) {
    count += categoryPatterns.length;
  }
  return count;
}

/**
 * Load and compile patterns in one step
 */
export function loadAndCompile(
  patternsFile?: string,
): Map<string, CompiledPattern[]> {
  const patterns = loadPatterns(patternsFile);
  return compilePatterns(patterns);
}

/**
 * Get pattern metadata (version, update date)
 */
export function getPatternMetadata(patternsFile?: string): {
  version: string;
  updated: string;
} {
  try {
    const patterns = loadPatterns(patternsFile);
    return { version: patterns.version, updated: patterns.updated };
  } catch (error) {
    if (patternsFile === undefined && IS_RELEASE_BUNDLE) {
      throw error;
    }
    return { version: "unknown", updated: "unknown" };
  }
}

/**
 * Check if patterns file exists
 */
export function hasPatternsFile(patternsFile?: string): boolean {
  if (patternsFile === undefined && IS_RELEASE_BUNDLE) {
    loadEmbeddedPatterns();
    return true;
  }
  return existsSync(patternsFile ?? DEFAULT_PATTERNS_FILE);
}
