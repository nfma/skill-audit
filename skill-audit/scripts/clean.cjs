#!/usr/bin/env node

const { rmSync } = require("node:fs");
const { basename, dirname, resolve } = require("node:path");

const packageRoot = resolve(__dirname, "..");
const distPath = resolve(packageRoot, "dist");

if (dirname(distPath) !== packageRoot || basename(distPath) !== "dist") {
  throw new Error("Refusing to clean an unexpected build directory");
}

rmSync(distPath, { recursive: true, force: true });
