import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { describe, expect, it } from "vitest";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const workflow = readFileSync(
  join(packageRoot, "..", ".github", "workflows", "sonar.yml"),
  "utf8",
);
const dependabotWorkflow = readFileSync(
  join(packageRoot, "..", ".github", "workflows", "dependabot-auto-merge.yml"),
  "utf8",
);
const releaseWorkflow = readFileSync(
  join(packageRoot, "..", ".github", "workflows", "release.yml"),
  "utf8",
);
const updateDbWorkflow = readFileSync(
  join(packageRoot, "..", ".github", "workflows", "update-db.yml"),
  "utf8",
);

function workflowStep(name: string): string {
  const marker = `      - name: ${name}\n`;
  const start = workflow.indexOf(marker);
  expect(start, `missing workflow step: ${name}`).toBeGreaterThanOrEqual(0);
  const next = workflow.indexOf("\n      - name:", start + marker.length);
  return workflow.slice(start, next === -1 ? workflow.length : next);
}

describe("Sonar workflow secret boundary", () => {
  it("classifies the pull request before checkout without loading secrets", () => {
    const classifier = workflowStep("Classify pull request trust");

    expect(workflow.indexOf("Classify pull request trust")).toBeLessThan(
      workflow.indexOf("Check out full history"),
    );
    expect(classifier).toContain(
      "github.event.pull_request.user.login == 'dependabot[bot]'",
    );
    expect(classifier).toContain(
      "github.event.pull_request.head.repo.full_name != github.repository",
    );
    expect(classifier).not.toContain(
      "github.event.pull_request.head.repo.fork",
    );
    expect(classifier).not.toContain("github.actor");
    expect(classifier).not.toContain("secrets.SONAR_TOKEN");
  });

  it("gates every repository-controlled and secret-bearing step", () => {
    const guardedSteps = [
      "Check out full history",
      "Set up Node.js",
      "Install dependencies",
      "Type-check",
      "Test with coverage",
      "Build",
      "Check for SonarQube Cloud token",
      "Scan and wait for the quality gate",
    ];

    for (const name of guardedSteps) {
      expect(workflowStep(name)).toContain(
        "if: steps.trust.outputs.trusted == 'true'",
      );
    }

    expect(workflowStep("Check for SonarQube Cloud token")).toContain(
      'if [ -z "$SONAR_TOKEN" ]',
    );
    expect(workflowStep("Scan and wait for the quality gate")).toContain(
      "-Dsonar.qualitygate.wait=true",
    );
  });
});

describe("Dependabot auto-merge boundary", () => {
  it("only accepts same-repository bot pull requests", () => {
    expect(dependabotWorkflow).toContain("pull_request:");
    expect(dependabotWorkflow).toContain(
      "github.event.pull_request.user.login == 'dependabot[bot]'",
    );
    expect(dependabotWorkflow).toContain(
      "github.event.pull_request.head.repo.full_name == github.repository",
    );
    expect(dependabotWorkflow).toContain(
      "github.event.pull_request.draft == false",
    );
    expect(dependabotWorkflow).not.toContain("pull_request_target:");
    expect(dependabotWorkflow).not.toContain("actions/checkout");
    expect(dependabotWorkflow).not.toContain("secrets.");
  });

  it("grants only merge permissions and forces squash auto-merge", () => {
    expect(dependabotWorkflow).toContain("permissions: {}");
    expect(dependabotWorkflow).toContain(
      "permissions:\n      contents: write\n      pull-requests: write",
    );
    expect(dependabotWorkflow).toContain(
      'gh pr merge --repo "$GH_REPO" --auto --squash "$PR_NUMBER"',
    );
    expect(dependabotWorkflow).not.toMatch(/--merge\b|--rebase\b/);
  });
});

describe("GitHub Release integrity boundary", () => {
  it("builds the executable once and validates the same handoff artifact", () => {
    expect(releaseWorkflow.match(/npm run build:release/g)).toHaveLength(1);
    expect(releaseWorkflow).toContain("needs: [build, validate, attest]");
    expect(releaseWorkflow).toContain(
      "name: ${{ needs.build.outputs.artifact-name }}",
    );
    expect(releaseWorkflow).toContain("os: [ubuntu-latest, macos-latest]");

    const publishJob = releaseWorkflow.slice(
      releaseWorkflow.indexOf("\n  publish:"),
    );
    expect(publishJob).not.toContain("build:release");
    expect(publishJob).not.toContain("esbuild");
    expect(publishJob).toContain("Reverify exact bytes before publication");
  });

  it("attests before publishing with narrowly scoped permissions", () => {
    expect(releaseWorkflow).toContain("permissions: {}\n");
    expect(releaseWorkflow).toContain(
      "id-token: write\n      attestations: write\n      artifact-metadata: write",
    );
    expect(releaseWorkflow).toContain(
      "publish:\n    name: Publish the validated GitHub Release",
    );
    expect(releaseWorkflow).toContain(
      "permissions:\n      contents: write\n    steps:",
    );
    expect(releaseWorkflow).toContain("gh release create");
    expect(releaseWorkflow).toContain("--draft");
    expect(releaseWorkflow).toContain("gh release verify");
  });

  it("keeps advisory refresh unable to mutate release assets", () => {
    expect(updateDbWorkflow).toContain("permissions:\n  contents: read");
    expect(updateDbWorkflow).not.toContain("contents: write");
    expect(updateDbWorkflow).not.toContain("gh release");
    expect(updateDbWorkflow).toContain("SKILL_AUDIT_CACHE_DIR:");
    expect(updateDbWorkflow).not.toContain("skill-audit/.cache/skill-audit");
  });
});
