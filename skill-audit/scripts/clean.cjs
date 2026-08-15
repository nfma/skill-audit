#!/usr/bin/env node

const { rmSync } = require("node:fs");
const { resolve } = require("node:path");

const distPath = resolve(__dirname, "..", "dist");

rmSync(distPath, { recursive: true, force: true });
