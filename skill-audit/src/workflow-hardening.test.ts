import { readFileSync, readdirSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { describe, expect, it } from "vitest";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const workflowsRoot = join(packageRoot, "..", ".github", "workflows");
const workflows = readdirSync(workflowsRoot)
  .filter((name) => name.endsWith(".yml"))
  .map((name) => ({
    name,
    content: readFileSync(join(workflowsRoot, name), "utf8"),
  }));

describe("repository workflow hardening", () => {
  it("pins every external action to a full commit SHA", () => {
    for (const workflow of workflows) {
      const references = [
        ...workflow.content.matchAll(/^\s*uses:\s+([^\s#]+)/gm),
      ];
      for (const reference of references) {
        expect(reference[1], `${workflow.name}: ${reference[1]}`).toMatch(
          /^[^@\s]+@[0-9a-f]{40}$/,
        );
      }
    }
  });

  it("disables persisted checkout credentials", () => {
    for (const workflow of workflows) {
      const steps = workflow.content.split(/\n(?=\s{6}- name:)/);
      for (const step of steps.filter((value) =>
        value.includes("uses: actions/checkout@"),
      )) {
        expect(step, workflow.name).toContain("persist-credentials: false");
      }
    }
  });

  it("keeps distribution Git-only and makes self-audit baseline blocking", () => {
    const combined = workflows.map((workflow) => workflow.content).join("\n");
    const selfAudit = workflows.find(
      (workflow) => workflow.name === "self-audit.yml",
    );

    expect(combined).not.toMatch(/\bnpm\s+publish\b/);
    expect(selfAudit?.content).toContain("--path .");
    expect(selfAudit?.content).toContain("check-self-audit.mjs");
    expect(selfAudit?.content).toContain(
      "--baseline ../.self-audit-baseline.json",
    );
  });
});
