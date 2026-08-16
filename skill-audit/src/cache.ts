import { homedir } from "node:os";
import { isAbsolute, join, posix, resolve, win32 } from "node:path";

interface CacheResolutionOptions {
  env?: NodeJS.ProcessEnv;
  homeDirectory?: string;
  platform?: NodeJS.Platform;
}

export function resolveSkillAuditCacheDir(
  options: CacheResolutionOptions = {},
): string {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const homeDirectory = options.homeDirectory ?? homedir();
  const configured = env.SKILL_AUDIT_CACHE_DIR;

  if (configured !== undefined) {
    if (configured.trim() === "") {
      throw new Error("SKILL_AUDIT_CACHE_DIR must not be blank");
    }
    const configuredIsAbsolute =
      platform === "win32"
        ? win32.isAbsolute(configured)
        : posix.isAbsolute(configured);
    if (!configuredIsAbsolute) {
      throw new Error("SKILL_AUDIT_CACHE_DIR must be an absolute path");
    }
    return platform === "win32"
      ? win32.normalize(configured)
      : resolve(configured);
  }

  if (platform === "darwin") {
    return join(homeDirectory, "Library", "Caches", "skill-audit");
  }
  if (platform === "win32") {
    const localAppData = env.LOCALAPPDATA;
    if (localAppData && win32.isAbsolute(localAppData)) {
      return win32.join(localAppData, "skill-audit");
    }
    return win32.join(homeDirectory, "AppData", "Local", "skill-audit");
  }

  const xdgCacheHome = env.XDG_CACHE_HOME;
  if (xdgCacheHome && isAbsolute(xdgCacheHome)) {
    return join(xdgCacheHome, "skill-audit");
  }
  return join(homeDirectory, ".cache", "skill-audit");
}
