#!/usr/bin/env node

import { isDirectExecution } from "./direct-execution.js";
import { runCli } from "./index.js";

if (isDirectExecution(import.meta.url, process.argv[1])) {
  await runCli();
}
