import { readFileSync, readdirSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { describe, expect, it } from "vitest";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const workflowsRoot = join(packageRoot, "..", ".github", "workflows");
const packageManifest = JSON.parse(
  readFileSync(join(packageRoot, "package.json"), "utf8"),
) as { private?: boolean };
const workflows = readdirSync(workflowsRoot)
  .filter((name) => name.endsWith(".yml") || name.endsWith(".yaml"))
  .map((name) => ({
    name,
    // `name` comes directly from this one directory's entries.
    content: readFileSync(join(workflowsRoot, name), "utf8"), // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  }));

type Workflow = (typeof workflows)[number];

function assertExternalActionsArePinned(workflow: Workflow) {
  let checked = 0;
  const references = [
    ...workflow.content.matchAll(/^\s*(?:-\s+)?uses:\s+([^\s#]+)/gm),
  ];
  for (const reference of references) {
    if (reference[1].startsWith("./")) {
      continue;
    }
    checked += 1;
    expect(reference[1], `${workflow.name}: ${reference[1]}`).toMatch(
      /^[^@\s]+@[0-9a-f]{40}$/,
    );
  }
  return checked;
}

function assertCheckoutCredentialsAreDisabled(workflow: Workflow) {
  let checked = 0;
  const steps = workflow.content.split(/\n(?=[ \t]*-\s)/);
  for (const step of steps.filter((value) =>
    value.includes("uses: actions/checkout@"),
  )) {
    checked += 1;
    const disablesPersistedCredentials = step.split("\n").some((line) => {
      const uncommented = line.split("#", 1)[0].trim();
      return uncommented === "persist-credentials: false";
    });
    expect(disablesPersistedCredentials, workflow.name).toBe(true);
  }
  return checked;
}

describe("repository workflow hardening", () => {
  it("pins every external action to a full commit SHA", () => {
    const checked = workflows.reduce(
      (total, workflow) => total + assertExternalActionsArePinned(workflow),
      0,
    );

    expect(checked).toBeGreaterThan(0);
  });

  it("rejects an unpinned action-only list step", () => {
    const fixture = {
      name: "fixture.yaml",
      content: "jobs:\n  test:\n    steps:\n      - uses: owner/action@v1\n",
    };

    expect(() => assertExternalActionsArePinned(fixture)).toThrow();
  });

  it("disables persisted checkout credentials", () => {
    const checked = workflows.reduce(
      (total, workflow) =>
        total + assertCheckoutCredentialsAreDisabled(workflow),
      0,
    );

    expect(checked).toBeGreaterThan(0);
  });

  it("rejects an action-only checkout step with persisted credentials", () => {
    const fixtures = [
      {
        name: "comment-spoof.yml",
        content:
          "jobs:\n  test:\n    steps:\n" +
          "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n" +
          "        # persist-credentials: false\n",
      },
      {
        name: "four-space-indent.yml",
        content:
          "jobs:\n  test:\n    steps:\n" +
          "    - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n" +
          "    - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n" +
          "      with:\n" +
          "        persist-credentials: false\n",
      },
    ];

    for (const fixture of fixtures) {
      expect(() => assertCheckoutCredentialsAreDisabled(fixture)).toThrow();
    }
  });

  it("keeps distribution Git-only and makes self-audit baseline blocking", () => {
    const combined = workflows.map((workflow) => workflow.content).join("\n");
    const selfAudit = workflows.find(
      (workflow) => workflow.name === "self-audit.yml",
    );

    expect(combined).not.toMatch(/\bnpm\s+publish\b/);
    expect(packageManifest.private).toBe(true);
    expect(selfAudit?.content).toContain("check-self-audit.mjs");
    expect(selfAudit?.content).toContain("--path .");
    expect(selfAudit?.content).toContain(
      "--baseline ../.self-audit-baseline.json",
    );

    const quality = workflows.find(
      (workflow) => workflow.name === "quality.yml",
    );
    expect(quality?.content).toContain("FORMAT_BASE:");
    expect(quality?.content).toContain("uvx --no-build");

    const ci = workflows.find((workflow) => workflow.name === "ci.yml");
    expect(ci?.content).toContain("bash scripts/test-audit.sh");
  });

  it("runs full-tree Semgrep with an exact reviewed baseline", () => {
    const security = workflows.find(
      (workflow) => workflow.name === "security.yml",
    );

    expect(security?.content).toContain("Run full Semgrep scan");
    expect(security?.content).toContain("check-semgrep.mjs");
    expect(security?.content).toContain("--baseline .semgrep-baseline.json");
    expect(security?.content).toContain("--jobs 1");
    expect(security?.content).toContain("--timeout 0");
    expect(security?.content).toContain("--timeout-threshold 0");
    expect(security?.content).not.toContain("--baseline-commit");
    expect(security?.content).not.toContain("github.event_name != 'schedule'");
  });

  it("enables same-repository squash auto-merge only for Dependabot", () => {
    const autoMerge = workflows.find(
      (workflow) => workflow.name === "dependabot-auto-merge.yml",
    );

    expect(autoMerge?.content).toContain(
      "github.event.pull_request.user.login == 'dependabot[bot]'",
    );
    expect(autoMerge?.content).not.toContain(
      "github.event.pull_request.user.login == 'nfma'",
    );
    expect(autoMerge?.content).toContain(
      "github.event.pull_request.head.repo.full_name == github.repository",
    );
    expect(autoMerge?.content).toContain("--auto --squash");
  });
});
