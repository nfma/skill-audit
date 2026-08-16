import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { describe, expect, it } from "vitest";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const workflow = readFileSync(
  join(packageRoot, "..", ".github", "workflows", "sonar.yml"),
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
    expect(classifier).toContain("github.event.pull_request.head.repo.fork");
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
