import { existsSync, readdirSync, statSync, lstatSync, realpathSync, readFileSync } from "fs";
import { isAbsolute, join, relative, resolve, sep } from "path";
import { execFileSync } from "child_process";
import { SkillInfo } from "./types.js";
import { homedir } from "os";

// ============================================================
// CONFIG FILE SUPPORT (~/.skill-audit/config.json)
// ============================================================

const CONFIG_DIR = ".skill-audit";
const CONFIG_FILE = "config.json";

export interface SkillAuditConfig {
  excludeSkills?: string[];
  excludePatterns?: string[];
  threshold?: number;
}

/**
 * Get the config file path
 */
export function getConfigPath(): string {
  return join(homedir(), CONFIG_DIR, CONFIG_FILE);
}

/**
 * Read and parse the global config file
 */
export function getGlobalConfig(): SkillAuditConfig {
  const configPath = getConfigPath();
  
  if (!existsSync(configPath)) {
    return {};
  }

  try {
    const content = readFileSync(configPath, "utf-8");
    return JSON.parse(content);
  } catch {
    return {};
  }
}

const AUDITOR_EXCLUDED_DIRECTORIES = new Set([".git", ".hg", ".svn", "node_modules"]);

function isWithinRoot(root: string, candidate: string): boolean {
  const relativePath = relative(root, candidate);
  return relativePath === "" || (
    relativePath !== ".."
    && !relativePath.startsWith(`..${sep}`)
    && !isAbsolute(relativePath)
  );
}

export function resolveSkillPath(skillPath: string): string {
  // Resolve symlinks to actual path, with boundary check
  try {
    const resolved = resolve(skillPath);
    // Ensure we don't escape the repository
    const realPath = realpathSync(resolved);
    return realPath;
  } catch {
    return skillPath;
  }
}

export function getSkillFiles(skillPath: string, basePath?: string): string[] {
  const files: string[] = [];

  if (!existsSync(skillPath)) {
    return files;
  }

  let root: string;
  let scanRoot: string;
  try {
    root = realpathSync(basePath || skillPath);
    scanRoot = realpathSync(skillPath);
  } catch {
    return files;
  }

  if (!isWithinRoot(root, scanRoot)) {
    return files;
  }

  const stat = statSync(scanRoot);

  if (stat.isFile()) {
    return [scanRoot];
  }

  const visitedDirectories = new Set<string>();

  // Recursively scan all directories with symlink boundary enforcement
  function scanDir(dir: string) {
    try {
      const realDir = realpathSync(dir);
      if (!isWithinRoot(root, realDir) || visitedDirectories.has(realDir)) {
        return;
      }
      visitedDirectories.add(realDir);

      const entries = readdirSync(realDir);

      for (const entry of entries) {
        const fullPath = join(realDir, entry);
        
        // Use lstat to detect symlinks without following them
        const lstat = lstatSync(fullPath);

        // Check for symlinks - ensure they don't escape the base path
        if (lstat.isSymbolicLink()) {
          try {
            const realPath = realpathSync(fullPath);
            // Verify the resolved path is still within the skill directory
            if (!isWithinRoot(root, realPath)) {
              // Symlink points outside - skip to prevent directory traversal
              continue;
            }
            // Follow the symlink for scanning
            const targetStat = statSync(fullPath);
            if (targetStat.isDirectory()) {
              if (!AUDITOR_EXCLUDED_DIRECTORIES.has(entry)) {
                scanDir(realPath);
              }
            } else if (targetStat.isFile()) {
              files.push(realPath);
            }
          } catch {
            // Broken symlink - skip
            continue;
          }
        } else if (lstat.isDirectory()) {
          if (!AUDITOR_EXCLUDED_DIRECTORIES.has(entry)) {
            scanDir(fullPath);
          }
        } else if (lstat.isFile()) {
          files.push(fullPath);
        }
      }
    } catch (e) {
      // Skip directories we cannot read
    }
  }

  scanDir(scanRoot);

  return files;
}

export async function discoverSkills(scope: "global" | "project" = "global"): Promise<SkillInfo[]> {
  const skills: SkillInfo[] = [];

  try {
    // Use execFileSync with argv array to prevent command injection
    const args = scope === "global" 
      ? ["skills", "list", "-g", "--json"]
      : ["skills", "list", "--json"];
    
    const output = execFileSync("npx", args, { 
      encoding: "utf-8", 
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 30000
    });

    const data = JSON.parse(output);

    if (Array.isArray(data)) {
      for (const item of data) {
        // Handle different output formats:
        // Format 1: { skill: { name, path, ... } }
        // Format 2: { name, path, ... }
        const skillData = item.skill || item;

        if (skillData && skillData.name && skillData.path) {
          // Filter by scope if project only
          const isGlobal = skillData.scope === "global";

          if (scope === "project" && isGlobal) continue;

          // Validate and sanitize the path to prevent traversal
          let safePath = skillData.path;
          try {
            safePath = resolveSkillPath(skillData.path);
          } catch {
            // Invalid path - skip this skill
            continue;
          }

          skills.push({
            name: skillData.name,
            path: safePath,
            agents: skillData.agents || [],
            scope: skillData.scope || "unknown"
          });
        }
      }
    }
  } catch (e) {
    console.error("Failed to discover skills:", e);
  }

  return skills;
}
