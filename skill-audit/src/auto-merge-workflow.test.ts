import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { describe, expect, it } from "vitest";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const workflowDirectory = join(packageRoot, "..", ".github", "workflows");
const signal = readFileSync(
  join(workflowDirectory, "dependabot-auto-merge.yml"),
  "utf8",
);
const reconciler = readFileSync(
  join(workflowDirectory, "auto-merge-reconcile.yml"),
  "utf8",
);

describe("App-token auto-merge boundary", () => {
  it("keeps pull-request event handling unprivileged", () => {
    for (const event of [
      "pull_request:",
      "pull_request_review:",
      "pull_request_review_comment:",
      "ready_for_review",
      "converted_to_draft",
      "labeled",
      "unlabeled",
    ]) {
      expect(signal).toContain(event);
    }
    expect(signal).toContain("permissions: {}");
    expect(signal).not.toMatch(
      /pull_request_target|workflow_run|actions\/checkout|secrets\.|artifacts?|cache/,
    );
  });

  it("uses a privileged default-branch reconciler without PR code", () => {
    expect(reconciler).toContain("workflow_run:");
    expect(reconciler).toContain("schedule:");
    expect(reconciler).toContain('cron: "*/5 * * * *"');
    expect(reconciler).toContain("workflow_dispatch:");
    expect(reconciler).toContain("cancel-in-progress: false");
    expect(reconciler).toContain(
      "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
    );
    expect(reconciler).toContain(
      "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3",
    );
    expect(reconciler).toContain("vars.NFMA_AUTO_MERGE_CLIENT_ID");
    expect(reconciler).toContain("secrets.NFMA_AUTO_MERGE_PRIVATE_KEY");
    expect(reconciler).toContain("permission-contents: write");
    expect(reconciler).toContain("permission-pull-requests: write");
    expect(reconciler).not.toMatch(
      /pull_request_target|actions\/checkout|download-artifact|upload-artifact|actions\/cache/,
    );
  });

  it("fails closed on every eligibility boundary", () => {
    for (const gate of [
      'new Set(["nfma", "dependabot[bot]"])',
      "pull.headRepository?.nameWithOwner === repositoryFullName",
      "pull.baseRepository?.nameWithOwner === repositoryFullName",
      "pull.baseRefName === defaultBranch",
      "!pull.isDraft",
      'author === "dependabot[bot]" || labelNames.has("automerge")',
      'pull.mergeable === "MERGEABLE"',
      'pull.mergeStateStatus === "CLEAN"',
      'pull.statusCheckRollup?.state === "SUCCESS"',
      'pull.reviewDecision === "APPROVED"',
      "allReviewThreadsResolved",
    ]) {
      expect(reconciler, `missing gate: ${gate}`).toContain(gate);
    }
    expect(reconciler).toContain("reviewThreads(first: 100, after: $cursor)");
    expect(reconciler).toContain("threads.pageInfo.hasNextPage");
    expect(reconciler).toContain("fresh.headRefOid !== initial.headRefOid");
  });

  it("reconciles both directions and permits only squash", () => {
    expect(reconciler).toContain("disablePullRequestAutoMerge");
    expect(reconciler).toContain("enablePullRequestAutoMerge");
    expect(reconciler).toContain("mergeMethod: SQUASH");
    expect(reconciler).toContain("expectedHeadOid: $expectedHeadOid");
    expect(reconciler).toContain(
      'fresh.armed && fresh.mergeMethod === "SQUASH"',
    );
    expect(reconciler).not.toMatch(/mergeMethod: (MERGE|REBASE)/);
  });
});
