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
    expect(result.findings).toContainEqual(
      expect.objectContaining({
        id: "SPEC-18",
        severity: "critical",
      }),
    );
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
    expect(result.findings).not.toContainEqual(
      expect.objectContaining({ id: "SPEC-18" }),
    );
  });
});
