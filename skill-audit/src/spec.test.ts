import { afterEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { validateSkillSpec } from "./spec.js";

const fixtureRoots: string[] = [];

function validSkill(name: string): string {
  return `---\nname: ${name}\ndescription: Valid fixture\n---\n# Fixture\n`;
}

afterEach(() => {
  for (const root of fixtureRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("validateSkillSpec SKILL.md containment", () => {
  it("rejects a sibling-prefix symlink outside the resolved skill root", () => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), "skill-audit-spec-"));
    fixtureRoots.push(fixtureRoot);
    const skillRoot = join(fixtureRoot, "fixture");
    const outsideRoot = `${skillRoot}-outside`;
    mkdirSync(skillRoot);
    mkdirSync(outsideRoot);
    writeFileSync(join(outsideRoot, "SKILL.md"), validSkill("fixture"));
    symlinkSync(join(outsideRoot, "SKILL.md"), join(skillRoot, "SKILL.md"));

    const result = validateSkillSpec(skillRoot, "fixture");

    expect(result.valid).toBe(false);
    expect(result.manifest).toBeUndefined();
    expect(result.findings).toContainEqual(expect.objectContaining({
      id: "SPEC-18",
      severity: "critical",
    }));
  });

  it("validates a normal SKILL.md inside the resolved skill root", () => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), "skill-audit-spec-"));
    fixtureRoots.push(fixtureRoot);
    const skillRoot = join(fixtureRoot, "fixture");
    mkdirSync(skillRoot);
    writeFileSync(join(skillRoot, "SKILL.md"), validSkill("fixture"));

    const result = validateSkillSpec(skillRoot, "fixture");

    expect(result.valid).toBe(true);
    expect(result.manifest?.name).toBe("fixture");
    expect(result.findings).not.toContainEqual(expect.objectContaining({ id: "SPEC-18" }));
  });
});

describe("validateSkillSpec portable frontmatter", () => {
  it("accepts the specification's space-separated allowed-tools string", () => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), "skill-audit-spec-"));
    fixtureRoots.push(fixtureRoot);
    const skillRoot = join(fixtureRoot, "fixture");
    mkdirSync(skillRoot);
    writeFileSync(
      join(skillRoot, "SKILL.md"),
      `---
name: fixture
description: Valid fixture
allowed-tools: Bash(git:*) Bash(jq:*) Read
---
# Fixture
`,
    );

    const result = validateSkillSpec(skillRoot, "fixture");

    expect(result.findings).not.toContainEqual(
      expect.objectContaining({ id: "SPEC-20" }),
    );
    expect(result.manifest?.allowedTools).toBe("Bash(git:*) Bash(jq:*) Read");
  });

  it("rejects a YAML list because the open specification requires a string", () => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), "skill-audit-spec-"));
    fixtureRoots.push(fixtureRoot);
    const skillRoot = join(fixtureRoot, "fixture");
    mkdirSync(skillRoot);
    writeFileSync(
      join(skillRoot, "SKILL.md"),
      `---
name: fixture
description: Invalid allowed-tools fixture
allowed-tools:
  - Read
  - Bash(git:*)
---
# Fixture
`,
    );

    const result = validateSkillSpec(skillRoot, "fixture");

    expect(result.findings).toContainEqual(
      expect.objectContaining({
        id: "SPEC-20",
        severity: "medium",
        message: "allowed-tools must be a non-empty space-separated string",
      }),
    );
  });

  it.each([
    ["empty", `allowed-tools: ""`],
    ["whitespace-only", `allowed-tools: "   "`],
    ["null", "allowed-tools:"],
  ])("rejects %s allowed-tools", (_label, allowedToolsLine) => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), "skill-audit-spec-"));
    fixtureRoots.push(fixtureRoot);
    const skillRoot = join(fixtureRoot, "fixture");
    mkdirSync(skillRoot);
    writeFileSync(
      join(skillRoot, "SKILL.md"),
      `---
name: fixture
description: Invalid allowed-tools fixture
${allowedToolsLine}
---
# Fixture
`,
    );

    const result = validateSkillSpec(skillRoot, "fixture");

    expect(result.findings).toContainEqual(
      expect.objectContaining({ id: "SPEC-20", severity: "medium" }),
    );
  });

  it("accepts metadata with only string values", () => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), "skill-audit-spec-"));
    fixtureRoots.push(fixtureRoot);
    const skillRoot = join(fixtureRoot, "fixture");
    mkdirSync(skillRoot);
    writeFileSync(
      join(skillRoot, "SKILL.md"),
      `---
name: fixture
description: Valid metadata fixture
metadata:
  author: example
  version: "1"
---
# Fixture
`,
    );

    const result = validateSkillSpec(skillRoot, "fixture");

    expect(result.findings).not.toContainEqual(
      expect.objectContaining({ id: "SPEC-19" }),
    );
  });

  it("rejects list-shaped metadata", () => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), "skill-audit-spec-"));
    fixtureRoots.push(fixtureRoot);
    const skillRoot = join(fixtureRoot, "fixture");
    mkdirSync(skillRoot);
    writeFileSync(
      join(skillRoot, "SKILL.md"),
      `---
name: fixture
description: Invalid metadata fixture
metadata:
  - author
  - example
---
# Fixture
`,
    );

    const result = validateSkillSpec(skillRoot, "fixture");

    expect(result.findings).toContainEqual(
      expect.objectContaining({ id: "SPEC-19", severity: "medium" }),
    );
  });

  it("rejects null metadata", () => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), "skill-audit-spec-"));
    fixtureRoots.push(fixtureRoot);
    const skillRoot = join(fixtureRoot, "fixture");
    mkdirSync(skillRoot);
    writeFileSync(
      join(skillRoot, "SKILL.md"),
      `---
name: fixture
description: Invalid metadata fixture
metadata:
---
# Fixture
`,
    );

    const result = validateSkillSpec(skillRoot, "fixture");

    expect(result.findings).toContainEqual(
      expect.objectContaining({ id: "SPEC-19", severity: "medium" }),
    );
  });

  it("rejects metadata values that are not strings", () => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), "skill-audit-spec-"));
    fixtureRoots.push(fixtureRoot);
    const skillRoot = join(fixtureRoot, "fixture");
    mkdirSync(skillRoot);
    writeFileSync(
      join(skillRoot, "SKILL.md"),
      `---
name: fixture
description: Invalid metadata fixture
metadata:
  author: example
  version: 1
---
# Fixture
`,
    );

    const result = validateSkillSpec(skillRoot, "fixture");

    expect(result.findings).toContainEqual(
      expect.objectContaining({
        id: "SPEC-19",
        severity: "medium",
        message: "metadata must be a mapping of string keys to string values",
      }),
    );
  });
});
