import { describe, expect, it } from "vitest";
import { resolveSkillAuditCacheDir } from "./cache.js";

describe("skill-audit cache resolution", () => {
  it("prefers an explicit absolute cache directory", () => {
    expect(
      resolveSkillAuditCacheDir({
        env: { SKILL_AUDIT_CACHE_DIR: "/tmp/custom-skill-audit" },
        homeDirectory: "/Users/test",
        platform: "darwin",
      }),
    ).toBe("/tmp/custom-skill-audit");
  });

  it("rejects blank and relative explicit cache directories", () => {
    for (const configured of ["", "   ", "./repository-cache"]) {
      expect(() =>
        resolveSkillAuditCacheDir({
          env: { SKILL_AUDIT_CACHE_DIR: configured },
          homeDirectory: "/Users/test",
          platform: "darwin",
        }),
      ).toThrow(/must not be blank|must be an absolute path/);
    }
  });

  it("uses each platform user cache convention", () => {
    expect(
      resolveSkillAuditCacheDir({
        env: {},
        homeDirectory: "/Users/test",
        platform: "darwin",
      }),
    ).toBe("/Users/test/Library/Caches/skill-audit");
    expect(
      resolveSkillAuditCacheDir({
        env: { XDG_CACHE_HOME: "/var/cache/test" },
        homeDirectory: "/home/test",
        platform: "linux",
      }),
    ).toBe("/var/cache/test/skill-audit");
    expect(
      resolveSkillAuditCacheDir({
        env: {},
        homeDirectory: "/home/test",
        platform: "linux",
      }),
    ).toBe("/home/test/.cache/skill-audit");
    expect(
      resolveSkillAuditCacheDir({
        env: { LOCALAPPDATA: "C:\\Users\\test\\AppData\\Local" },
        homeDirectory: "C:\\Users\\test",
        platform: "win32",
      }),
    ).toBe("C:\\Users\\test\\AppData\\Local\\skill-audit");
  });
});
