#!/usr/bin/env node

import { Command } from "commander";
import { discoverSkills, getGlobalConfig } from "./discover.js";
import { auditSecurity, SecurityAuditResult } from "./security.js";
import { validateSkillSpec, SpecValidationResult } from "./spec.js";
import { createGroupedAuditResult, groupSecurityFindings } from "./scoring.js";
import { scanDependencies } from "./deps.js";
import { getKEV, getEPSS, getNVD, downloadOfflineDB } from "./intel.js";
import { ensureIntelFeedsFresh } from "./auto-update.js";
import { installHook, uninstallHook, getHookStatus, getDefaultHookConfig } from "./hooks.js";
import { assessShellCommand, diffEnvironmentBaseline, getEnvironmentBaselinePath, reportCommandAssessment, reportEnvironmentBaseline, reportEnvironmentDiff, reportEnvironmentDoctor, runEnvironmentDoctor, writeEnvironmentBaseline } from "./environment.js";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { Finding, GroupedAuditResult } from "./types.js";
import { reportGroupedResults } from "./grouped-reporter.js";

function getVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8"));
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

// Build CLI - no subcommands, just options + action
const program = new Command();

if (process.argv[2] === "doctor") {
  process.argv.splice(2, 1, "--mode", "doctor");
}
if (process.argv[2] === "diff-env") {
  process.argv.splice(2, 1, "--mode", "diff-env");
}
if (process.argv[2] === "trust" && process.argv[3] === "env") {
  process.argv.splice(2, 2, "--mode", "trust-env");
}

program
  .name("skill-audit")
  .description("Security auditing CLI for AI agent skills")
  .version(getVersion())
  .option("-g, --global", "Audit global skills only (default: true)")
  .option("-p, --project", "Audit project-level skills only")
  .option("-a, --agent <agents...>", "Filter by specific agents")
  .option("-x, --exclude-skill <names...>", "Skills to exclude from audit (by name)")
  .option("-j, --json", "Output as JSON")
  .option("-o, --output <file>", "Save report to file (JSON format)")
  .option("-v, --verbose", "Show detailed findings")
  .option("-t, --threshold <score>", "Fail if risk score meets or exceeds threshold (default with --block: 3.0)", parseFloat)
  .option("--no-deps", "Skip dependency scanning (faster)")
  .option("--mode <mode>", "Audit mode: 'lint', 'audit', 'doctor', 'trust-env', or 'diff-env'", "audit")
  .option("--update-db", "Update advisory intelligence feeds")
  .option("--source <sources...>", "Sources for update-db: kev, epss, nvd, all", ["all"])
  .option("--strict", "Fail if feeds are stale")
  .option("--quiet", "Suppress non-error output")
  .option("--download-offline-db <dir>", "Download offline vulnerability databases to directory")
  .option("--check-command <command>", "Assess whether a shell command should trigger environment safety checks")
  .option("--install-hook", "Install PreToolUse hook for automatic skill auditing")
  .option("--uninstall-hook", "Remove the PreToolUse hook")
  .option("--hook-threshold <score>", "Risk threshold for hook (default: 3.0)", parseFloat)
  .option("--hook-status", "Show current hook status")
  .option("--block", "Exit with code 1 for high/critical findings or when the threshold is met");

program.parse(process.argv);

const options = program.opts();

// Load global config (~/.skill-audit/config.json) and merge with CLI options
const globalConfig = getGlobalConfig();

// Merge excludeSkills from config with CLI options
const excludeSkillsFromConfig = globalConfig.excludeSkills || [];
const excludeSkillsFromCLI = options.excludeSkill || [];
const allExcludeSkills = [...new Set([...excludeSkillsFromConfig, ...excludeSkillsFromCLI])];

// Handle download-offline-db action
if (options.downloadOfflineDb) {
  await downloadOfflineDB(options.downloadOfflineDb);
  process.exit(0);
}

// Handle hook-friendly shell command assessment
if (options.checkCommand) {
  const assessment = assessShellCommand(options.checkCommand);
  reportCommandAssessment(assessment, {
    json: options.json,
    verbose: options.verbose,
    block: options.block,
    threshold: options.threshold,
  });
  if (options.block && assessment.environment?.drift) {
    process.exit(1);
  }
  if (options.block && options.threshold !== undefined && (assessment.environment?.current.riskScore || 0) >= options.threshold) {
    process.exit(1);
  }
  process.exit(0);
}

// Handle update-db action
if (options.updateDb) {
  await updateAdvisoryDB({ source: options.source, strict: options.strict });
  process.exit(0);
}

// Handle hook-status action
if (options.hookStatus) {
  const status = getHookStatus();
  console.log("\n🪝 skill-audit Hook Status\n");
  console.log(`   Installed: ${status.installed ? "✅ Yes" : "❌ No"}`);
  if (status.installed && status.config) {
    console.log(`   Threshold: ${status.config.threshold}`);
    console.log(`   Block on failure: ${status.config.blockOnFailure ? "Yes" : "No"}`);
  }
  console.log(`   Settings file: ${status.settingsPath}\n`);
  process.exit(0);
}

// Handle install-hook action
if (options.installHook) {
  const config = getDefaultHookConfig();
  if (options.hookThreshold) {
    config.threshold = options.hookThreshold;
  }
  config.blockOnFailure = true;

  console.log("\n🪝 Installing skill-audit hook...\n");
  const result = installHook(config);
  
  if (result.success) {
    console.log(`✅ ${result.message}`);
    console.log(`   Settings file: ${getHookStatus().settingsPath}`);
    console.log("\n   Skills will now be audited before installation.");
    console.log("   Run 'skill-audit --uninstall-hook' to remove.\n");
  } else {
    console.error(`❌ ${result.message}`);
    process.exit(1);
  }
  process.exit(0);
}

// Handle uninstall-hook action
if (options.uninstallHook) {
  console.log("\n🪝 Removing skill-audit hook...\n");
  const result = uninstallHook();
  
  if (result.success) {
    console.log(`✅ ${result.message}\n`);
  } else {
    console.error(`❌ ${result.message}`);
    process.exit(1);
  }
  process.exit(0);
}

// Default to global skills
const scope = options.project ? "project" : "global";
const mode = options.mode || "audit";

if (mode === "doctor") {
  const result = runEnvironmentDoctor();
  reportEnvironmentDoctor(result, {
    json: options.json,
    verbose: options.verbose,
    output: options.output,
  });
  if (options.block && options.threshold !== undefined && result.riskScore >= options.threshold) {
    process.exit(1);
  }
  process.exit(0);
}

if (mode === "trust-env") {
  const baseline = writeEnvironmentBaseline();
  reportEnvironmentBaseline(baseline, getEnvironmentBaselinePath(), { json: options.json });
  process.exit(0);
}

if (mode === "diff-env") {
  const diff = diffEnvironmentBaseline();
  reportEnvironmentDiff(diff, {
    json: options.json,
    verbose: options.verbose,
    block: options.block,
    threshold: options.threshold,
  });
  if (options.block && diff.drift) {
    process.exit(1);
  }
  if (options.block && options.threshold !== undefined && diff.current.riskScore >= options.threshold) {
    process.exit(1);
  }
  process.exit(0);
}

// Auto-update intelligence feeds in background (silent)
if (mode === "audit") {
  ensureIntelFeedsFresh(); // Fire and forget - non-blocking
}

if (!options.json) {
  console.log(mode === "lint" 
    ? "📋 Linting skills (spec validation)..."
    : "🔍 Auditing skills (full security + intelligence)...");
}

const skills = await discoverSkills(scope);

// Filter by agents if specified
let filteredSkills = skills;
if (options.agent && options.agent.length > 0) {
  filteredSkills = skills.filter(s =>
    s.agents.some(a => options.agent.includes(a))
  );
}

// Filter by excluded skills (from config + CLI)
if (allExcludeSkills.length > 0) {
  filteredSkills = filteredSkills.filter(s =>
    !allExcludeSkills.includes(s.name)
  );
}

if (!options.json) {
  console.log("Found " + filteredSkills.length + " skills\n");
}

const results: GroupedAuditResult[] = [];

for (const skill of filteredSkills) {
  // Step 1: Spec validation (always runs first)
  const specResult: SpecValidationResult = validateSkillSpec(skill.path, skill.name);

  // Step 2: Security audit (full or lite based on mode)
  let securityResult: SecurityAuditResult = { findings: [], unreadableFiles: [] };
  let depFindings: Finding[] = [];

  if (mode === "audit") {
    securityResult = auditSecurity(skill, specResult.manifest);
    
    if (options.deps !== false) {
      depFindings = scanDependencies(skill.path);
    }
  }

  const allSecurityFindings = [...securityResult.findings, ...depFindings];
  
  const { securityFindings, piiFindings, complianceFindings } = groupSecurityFindings(allSecurityFindings);

  const result = createGroupedAuditResult(
    skill,
    specResult.manifest,
    specResult.findings,
    securityFindings,
    piiFindings,
    complianceFindings,
    []
  );
  results.push(result);
}

const shouldBlock = reportGroupedResults(results, {
  json: options.json,
  output: options.output,
  verbose: options.verbose,
  threshold: options.threshold ?? (options.block ? getDefaultHookConfig().threshold : undefined),
  mode,
  block: options.block
});
if (shouldBlock) process.exitCode = 1;

async function updateAdvisoryDB(opts: { source: string[]; strict: boolean }) {
  const sources = opts.source.includes("all") ? ["kev", "epss", "nvd"] : opts.source;
  const quiet = program.opts().quiet;

  if (!quiet) {
    console.log("📥 Updating advisory intelligence feeds...\n");
  }

  let hasErrors = false;

  for (const source of sources) {
    if (!quiet) {
      console.log(`Fetching ${source.toUpperCase()}...`);
    }

    try {
      if (source === "kev") {
        const result = await getKEV();
        if (!quiet) {
          console.log(`   ✓ CISA KEV: ${result.findings.length} vulnerabilities cached (stale: ${result.stale})`);
        }
      } else if (source === "epss") {
        const result = await getEPSS();
        if (!quiet) {
          console.log(`   ✓ EPSS: ${result.findings.length} scores cached (stale: ${result.stale})`);
        }
      } else if (source === "nvd") {
        const result = await getNVD();
        if (!quiet) {
          console.log(`   ✓ NVD: ${result.findings.length} CVEs cached (stale: ${result.stale})`);
        }
      }
    } catch (e) {
      console.error(`   ✗ Failed to fetch ${source}:`, e);
      hasErrors = true;
    }
  }

  if (!quiet) {
    console.log("\n✅ Advisory DB updated");
  }

  if (opts.strict && hasErrors) {
    process.exit(1);
  }
}
