import { Command } from "commander";
import {
  discoverSkills,
  getGlobalConfig,
  resolveSkillPath,
} from "./discover.js";
import { auditSecurity, SecurityAuditResult } from "./security.js";
import { validateSkillSpec, SpecValidationResult } from "./spec.js";
import { createGroupedAuditResult, groupSecurityFindings } from "./scoring.js";
import { scanDependencies } from "./deps.js";
import { getKEV, getEPSS, getNVD, downloadOfflineDB } from "./intel.js";
import { auditCompliance } from "./compliance.js";
import {
  installHook,
  uninstallHook,
  getHookStatus,
  getDefaultHookConfig,
} from "./hooks.js";
import {
  assessShellCommand,
  diffEnvironmentBaseline,
  getEnvironmentBaselinePath,
  reportCommandAssessment,
  reportEnvironmentBaseline,
  reportEnvironmentDiff,
  reportEnvironmentDoctor,
  runEnvironmentDoctor,
  writeEnvironmentBaseline,
} from "./environment.js";
import { basename } from "node:path";
import { Finding, GroupedAuditResult, SkillInfo } from "./types.js";
import { reportGroupedResults } from "./grouped-reporter.js";
import { PACKAGE_VERSION } from "./generated/release-data.js";

export async function runCli(argv: string[] = process.argv): Promise<void> {
  const cliArgv = [...argv];
  const program = new Command();

  if (cliArgv[2] === "doctor") {
    cliArgv.splice(2, 1, "--mode", "doctor");
  }
  if (cliArgv[2] === "diff-env") {
    cliArgv.splice(2, 1, "--mode", "diff-env");
  }
  if (cliArgv[2] === "trust" && cliArgv[3] === "env") {
    cliArgv.splice(2, 2, "--mode", "trust-env");
  }

  program
    .name("skill-audit")
    .description("Security auditing CLI for AI agent skills")
    .version(PACKAGE_VERSION)
    .option("-g, --global", "Audit global skills only (default: true)")
    .option("-p, --project", "Audit project-level skills only")
    .option("-a, --agent <agents...>", "Filter by specific agents")
    .option(
      "-x, --exclude-skill <names...>",
      "Skills to exclude from audit (by name)",
    )
    .option(
      "--path <paths...>",
      "Audit explicit skill directories instead of discovered skills",
    )
    .option("-j, --json", "Output as JSON")
    .option("-o, --output <file>", "Save report to file (JSON format)")
    .option("-v, --verbose", "Show detailed findings")
    .option(
      "-t, --threshold <score>",
      "Risk score threshold (default with --block: 3.0)",
      Number.parseFloat,
    )
    .option("--no-deps", "Skip dependency scanning (faster)")
    .option("--compliance", "Run heuristic compliance checks (audit mode only)")
    .option(
      "--mode <mode>",
      "Audit mode: 'lint', 'audit', 'doctor', 'trust-env', or 'diff-env'",
      "audit",
    )
    .option("--update-db", "Update advisory intelligence feeds")
    .option(
      "--source <sources...>",
      "Sources for update-db: kev, epss, nvd, all",
      ["all"],
    )
    .option("--strict", "Exit 1 if a feed update fails (requires --update-db)")
    .option("--quiet", "Suppress non-error output")
    .option(
      "--download-offline-db <dir>",
      "Export vulnerability-feed snapshots to directory",
    )
    .option(
      "--check-command <command>",
      "Assess whether a shell command should trigger environment safety checks",
    )
    .option(
      "--install-hook",
      "Install PreToolUse hook for automatic skill auditing",
    )
    .option("--uninstall-hook", "Remove the PreToolUse hook")
    .option(
      "--hook-threshold <score>",
      "Risk threshold for hook (default: 3.0)",
      Number.parseFloat,
    )
    .option("--hook-status", "Show current hook status")
    .option(
      "--block",
      "Exit with code 1 for high/critical findings or when the threshold is met",
    );

  program.parse(cliArgv);

  const options = program.opts();

  if (options.strict && !options.updateDb) {
    program.error(
      "error: option '--strict' can only be used with '--update-db'",
    );
  }

  // Load global config (~/.skill-audit/config.json) and merge with CLI options
  const globalConfig = getGlobalConfig();

  // Merge excludeSkills from config with CLI options
  const excludeSkillsFromConfig = globalConfig.excludeSkills || [];
  const excludeSkillsFromCLI = options.excludeSkill || [];
  const allExcludeSkills = [
    ...new Set([...excludeSkillsFromConfig, ...excludeSkillsFromCLI]),
  ];

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
    if (
      options.block &&
      options.threshold !== undefined &&
      (assessment.environment?.current.riskScore || 0) >= options.threshold
    ) {
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
      console.log(
        `   Block on failure: ${status.config.blockOnFailure ? "Yes" : "No"}`,
      );
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
    if (
      options.block &&
      options.threshold !== undefined &&
      result.riskScore >= options.threshold
    ) {
      process.exit(1);
    }
    process.exit(0);
  }

  if (mode === "trust-env") {
    const baseline = writeEnvironmentBaseline();
    reportEnvironmentBaseline(baseline, getEnvironmentBaselinePath(), {
      json: options.json,
    });
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
    if (
      options.block &&
      options.threshold !== undefined &&
      diff.current.riskScore >= options.threshold
    ) {
      process.exit(1);
    }
    process.exit(0);
  }

  if (!options.json) {
    console.log(
      mode === "lint"
        ? "📋 Linting skills (spec validation)..."
        : "🔍 Auditing skills (full security + intelligence)...",
    );
  }

  const skills: SkillInfo[] = options.path?.length
    ? options.path.map((path: string) => {
        const resolvedPath = resolveSkillPath(path);
        return {
          name: basename(resolvedPath),
          path: resolvedPath,
          agents: [],
          scope: "project" as const,
        };
      })
    : await discoverSkills(scope);

  // Filter by agents if specified
  let filteredSkills = skills;
  if (options.agent && options.agent.length > 0) {
    filteredSkills = skills.filter((s) =>
      s.agents.some((a) => options.agent.includes(a)),
    );
  }

  // Filter by excluded skills (from config + CLI)
  if (allExcludeSkills.length > 0) {
    filteredSkills = filteredSkills.filter(
      (s) => !allExcludeSkills.includes(s.name),
    );
  }

  if (!options.json) {
    console.log("Found " + filteredSkills.length + " skills\n");
  }

  const results: GroupedAuditResult[] = [];

  for (const skill of filteredSkills) {
    // Step 1: Spec validation (always runs first)
    const specResult: SpecValidationResult = validateSkillSpec(
      skill.path,
      skill.name,
    );

    // Step 2: Security audit (full or lite based on mode)
    let securityResult: SecurityAuditResult = {
      findings: [],
      unreadableFiles: [],
    };
    let depFindings: Finding[] = [];

    if (mode === "audit") {
      securityResult = auditSecurity(skill, specResult.manifest);

      if (options.deps !== false) {
        depFindings = scanDependencies(skill.path);
      }
    }

    const rawComplianceFindings =
      mode === "audit" && options.compliance && specResult.manifest
        ? auditCompliance(specResult.manifest, skill.path)
        : [];
    const allSecurityFindings = [
      ...securityResult.findings,
      ...depFindings,
      ...rawComplianceFindings,
    ];

    const { securityFindings, piiFindings, complianceFindings } =
      groupSecurityFindings(allSecurityFindings);

    const result = createGroupedAuditResult(
      skill,
      specResult.manifest,
      specResult.findings,
      securityFindings,
      piiFindings,
      complianceFindings,
      [],
    );
    results.push(result);
  }

  const shouldBlock = reportGroupedResults(results, {
    json: options.json,
    output: options.output,
    verbose: options.verbose,
    threshold:
      options.threshold ??
      (options.block ? getDefaultHookConfig().threshold : undefined),
    mode,
    block: options.block,
  });
  if (shouldBlock) process.exitCode = 1;

  async function updateAdvisoryDB(opts: { source: string[]; strict: boolean }) {
    const sources = opts.source.includes("all")
      ? ["kev", "epss", "nvd"]
      : opts.source;
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
            console.log(
              `   ✓ CISA KEV: ${result.findings.length} vulnerabilities cached (stale: ${result.stale})`,
            );
          }
        } else if (source === "epss") {
          const result = await getEPSS();
          if (!quiet) {
            console.log(
              `   ✓ EPSS: ${result.findings.length} scores cached (stale: ${result.stale})`,
            );
          }
        } else if (source === "nvd") {
          const result = await getNVD();
          if (!quiet) {
            console.log(
              `   ✓ NVD: ${result.findings.length} CVEs cached (stale: ${result.stale})`,
            );
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
}
