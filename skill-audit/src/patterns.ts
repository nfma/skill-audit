import { readFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { Finding, FindingCategory } from "./types.js";

const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(PACKAGE_ROOT, "rules");
const DEFAULT_PATTERNS_FILE = join(RULES_DIR, "default-patterns.json");

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
export function loadPatterns(
  patternsFile: string = DEFAULT_PATTERNS_FILE,
): PatternsFile {
  if (!existsSync(patternsFile)) {
    throw new Error(`Patterns file not found: ${patternsFile}`);
  }

  const content = readFileSync(patternsFile, "utf-8");
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
      try {
        const regex = new RegExp(rule.pattern, rule.flags || "i");
        categoryPatterns.push({
          regex,
          id: rule.id,
          severity: rule.severity,
          message: rule.message,
          category: categoryMetadata.category,
          asi: categoryMetadata.asi,
        });
      } catch (error) {
        console.error(`Failed to compile pattern ${rule.id}:`, error);
      }
    }

    compiled.set(categoryKey, categoryPatterns);
  }

  return compiled;
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
export function getPatternMetadata(
  patternsFile: string = DEFAULT_PATTERNS_FILE,
): { version: string; updated: string } {
  try {
    const patterns = loadPatterns(patternsFile);
    return { version: patterns.version, updated: patterns.updated };
  } catch {
    return { version: "unknown", updated: "unknown" };
  }
}

/**
 * Check if patterns file exists
 */
export function hasPatternsFile(
  patternsFile: string = DEFAULT_PATTERNS_FILE,
): boolean {
  return existsSync(patternsFile);
}
