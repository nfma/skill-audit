import { readFileSync, readdirSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { describe, expect, it } from "vitest";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const workflowDirectory = join(packageRoot, "..", ".github", "workflows");
const workflow = readFileSync(join(workflowDirectory, "sonar.yml"), "utf8");
const dependabotWorkflow = readFileSync(
  join(workflowDirectory, "dependabot-auto-merge.yml"),
  "utf8",
);
const releaseWorkflow = readFileSync(
  join(workflowDirectory, "release.yml"),
  "utf8",
);
const updateDbWorkflow = readFileSync(
  join(workflowDirectory, "update-db.yml"),
  "utf8",
);

interface WorkflowJob {
  body: string;
  name: string;
}

function workflowJobs(source: string): WorkflowJob[] {
  const marker = "\njobs:\n";
  const markerIndex = source.indexOf(marker);
  expect(
    markerIndex,
    "workflow is missing a jobs mapping",
  ).toBeGreaterThanOrEqual(0);
  const jobsSource = source.slice(markerIndex + marker.length);
  const matches = [...jobsSource.matchAll(/^ {2}([A-Za-z0-9_-]+):\s*$/gm)];
  return matches.map((match, index) => ({
    name: match[1],
    body: jobsSource.slice(
      match.index,
      matches[index + 1]?.index ?? jobsSource.length,
    ),
  }));
}

function workflowStepFrom(contents: string, name: string): string {
  const marker = `      - name: ${name}\n`;
  const start = contents.indexOf(marker);
  expect(start, `missing workflow step: ${name}`).toBeGreaterThanOrEqual(0);
  const next = contents.indexOf("\n      - name:", start + marker.length);
  return contents.slice(start, next === -1 ? contents.length : next);
}

function workflowStep(name: string): string {
  return workflowStepFrom(workflow, name);
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

  it("auto-merges only npm patch and minor updates", () => {
    const metadata = workflowStepFrom(
      dependabotWorkflow,
      "Inspect Dependabot update",
    );
    const merge = workflowStepFrom(
      dependabotWorkflow,
      "Enable squash auto-merge",
    );
    const manual = workflowStepFrom(
      dependabotWorkflow,
      "Explain manual review requirement",
    );

    expect(metadata).toContain(
      "dependabot/fetch-metadata@25dd0e34f4fe68f24cc83900b1fe3fe149efef98 # v3.1.0",
    );
    expect(merge).toContain("package-ecosystem == 'npm'");
    expect(merge).not.toContain("package-ecosystem == 'github-actions'");
    expect(merge).toContain("update-type == 'version-update:semver-patch'");
    expect(merge).toContain("update-type == 'version-update:semver-minor'");
    expect(merge).not.toContain("version-update:semver-major");
    expect(manual).toContain("package-ecosystem != 'npm'");
    expect(manual).toContain("update-type != 'version-update:semver-patch'");
    expect(manual).toContain("update-type != 'version-update:semver-minor'");
    expect(manual).not.toContain("gh pr merge");
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
    expect(releaseWorkflow).toContain("id-token: write # Mint the OIDC token");
    expect(releaseWorkflow).toContain(
      "attestations: write # Publish attestations",
    );
    expect(releaseWorkflow).toContain(
      "artifact-metadata: write # Associate attestation metadata",
    );
    expect(releaseWorkflow).toContain(
      "publish:\n    name: Publish the validated GitHub Release",
    );
    expect(releaseWorkflow).toContain(
      "contents: write # Create and publish the immutable GitHub Release.",
    );
    expect(releaseWorkflow).toContain("--draft");
    expect(releaseWorkflow).toContain(
      'gh api --paginate --slurp "repos/$GITHUB_REPOSITORY/releases?per_page=100"',
    );
    expect(releaseWorkflow).toContain(
      'gh api "repos/$GITHUB_REPOSITORY/releases/tags/$RELEASE_TAG"',
    );
    expect(releaseWorkflow).toContain("asset.digest");
    expect(releaseWorkflow).toContain("release.immutable !== true");
    expect(releaseWorkflow).not.toContain("gh release verify");
  });

  it("repo-scopes gh commands in every checkout-less workflow job", () => {
    const workflowFiles = readdirSync(workflowDirectory).filter(
      (filename) => filename.endsWith(".yml") || filename.endsWith(".yaml"),
    );
    const ghCommand =
      /\bgh\s+(?:api|attestation|issue|pr|release|repo|run|workflow)\b/;

    for (const filename of workflowFiles) {
      const source = readFileSync(join(workflowDirectory, filename), "utf8");
      for (const job of workflowJobs(source)) {
        if (
          !ghCommand.test(job.body) ||
          job.body.includes("actions/checkout@")
        ) {
          continue;
        }
        expect(
          job.body,
          `${filename}:${job.name} must set GH_REPO when it runs gh without a checkout`,
        ).toContain("GH_REPO: ${{ github.repository }}");
      }
    }

    const publishJob = workflowJobs(releaseWorkflow).find(
      (job) => job.name === "publish",
    );
    expect(publishJob).toBeDefined();
    expect(publishJob?.body).not.toContain("actions/checkout@");
    expect(publishJob?.body).toContain("GH_REPO: ${{ github.repository }}");
  });

  it("keeps advisory refresh unable to mutate release assets", () => {
    expect(updateDbWorkflow).toContain("permissions:\n  contents: read");
    expect(updateDbWorkflow).not.toContain("contents: write");
    expect(updateDbWorkflow).not.toContain("gh release");
    expect(updateDbWorkflow).toContain("SKILL_AUDIT_CACHE_DIR:");
    expect(updateDbWorkflow).not.toContain("skill-audit/.cache/skill-audit");
  });
});
