#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = realpathSync(
  join(dirname(fileURLToPath(import.meta.url)), ".."),
);
const repositoryRoot = realpathSync(join(packageRoot, ".."));
const supportedFile = /\.(?:[cm]?[jt]s|tsx?|json|ya?ml)$/;
const excludedDirectories = [
  "skill-audit/coverage/",
  "skill-audit/dist/",
  "skill-audit/node_modules/",
];

function git(arguments_, options = {}) {
  return execFileSync("git", arguments_, {
    cwd: repositoryRoot,
    ...options,
  });
}

function nulSeparatedPaths(arguments_) {
  const output = git(arguments_);
  return output.toString("utf8").split("\0").filter(Boolean);
}

function resolveBase() {
  const configuredBase = process.env.FORMAT_BASE;
  if (configuredBase && !/^0{40}$/.test(configuredBase)) {
    if (!/^[0-9a-f]{40}$/.test(configuredBase)) {
      throw new TypeError("FORMAT_BASE must be a full lowercase commit SHA");
    }
    return configuredBase;
  }

  for (const candidate of ["origin/main", "HEAD^"]) {
    try {
      return git(["merge-base", "HEAD", candidate], {
        encoding: "utf8",
      }).trim();
    } catch {
      // Try the next local fallback.
    }
  }
  throw new Error("Could not determine a formatting comparison commit");
}

function changedFiles(base) {
  const paths = new Set([
    ...nulSeparatedPaths([
      "diff",
      "--name-only",
      "--diff-filter=ACMR",
      "-z",
      `${base}...HEAD`,
      "--",
    ]),
    ...nulSeparatedPaths([
      "diff",
      "--name-only",
      "--diff-filter=ACMR",
      "-z",
      "--",
    ]),
    ...nulSeparatedPaths([
      "diff",
      "--cached",
      "--name-only",
      "--diff-filter=ACMR",
      "-z",
      "--",
    ]),
    ...nulSeparatedPaths(["ls-files", "--others", "--exclude-standard", "-z"]),
  ]);

  return [...paths]
    .filter((path) => supportedFile.test(path))
    .filter(
      (path) =>
        !excludedDirectories.some((directory) => path.startsWith(directory)),
    )
    .filter((path) => existsSync(join(repositoryRoot, path)))
    .sort();
}

const files = changedFiles(resolveBase());
if (files.length === 0) {
  console.log(
    "No changed JavaScript, TypeScript, JSON, or YAML files to format-check.",
  );
} else {
  execFileSync(
    process.execPath,
    [
      join(packageRoot, "node_modules", "prettier", "bin", "prettier.cjs"),
      "--check",
      ...files,
    ],
    { cwd: repositoryRoot, stdio: "inherit" },
  );
}
