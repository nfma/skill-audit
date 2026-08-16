import { isDirectExecution } from "./direct-execution.js";
import { runCli } from "./index.js";

export { scanDependencies } from "./deps.js";
export { reportGroupedResults } from "./grouped-reporter.js";
export { createGroupedAuditResult, groupSecurityFindings } from "./scoring.js";
export { auditSecurity } from "./security.js";
export { validateSkillSpec } from "./spec.js";

if (isDirectExecution(import.meta.url, process.argv[1])) {
  await runCli();
}
