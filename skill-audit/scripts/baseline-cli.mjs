import { realpathSync } from "node:fs";
import { resolve } from "node:path";

function parseBaselineArguments(argv, rootOption) {
  const values = new Map();
  let writeBaseline = false;
  const valueOptions = new Set(["--report", "--baseline", rootOption]);

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--write-baseline") {
      writeBaseline = true;
      continue;
    }
    if (!valueOptions.has(argument)) {
      throw new Error(`Unknown argument: ${argument}`);
    }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for ${argument}`);
    }
    values.set(argument, value);
    index += 1;
  }

  for (const required of valueOptions) {
    if (!values.has(required)) {
      throw new Error(`Missing required argument: ${required}`);
    }
  }

  return {
    baselinePath: resolve(values.get("--baseline")),
    reportPath: resolve(values.get("--report")),
    root: realpathSync(values.get(rootOption)),
    writeBaseline,
  };
}

export { parseBaselineArguments };
