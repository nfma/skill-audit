import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const { buildMock } = vi.hoisted(() => ({ buildMock: vi.fn() }));

vi.mock("esbuild", () => ({ build: buildMock }));

import { buildRelease } from "../scripts/build-release.js";
import { PACKAGE_VERSION } from "./generated/release-data.js";
import { RELEASE_MAX_BYTES } from "./release-assets.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  buildMock.mockReset();
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

async function expectBuildGuard(
  content: string | Uint8Array,
  message: string,
  imports: Array<{ external: boolean; path: string }> = [],
): Promise<void> {
  const root = mkdtempSync(join(tmpdir(), "skill-audit-build-guard-"));
  temporaryDirectories.push(root);
  const packageRoot = join(root, "skill-audit");
  const outputDirectory = join(root, "release");
  mkdirSync(packageRoot);

  buildMock.mockImplementationOnce(async (options: { outfile?: string }) => {
    if (!options.outfile) {
      throw new Error("test build did not receive an outfile");
    }
    writeFileSync(options.outfile, content);
    return {
      metafile: {
        outputs: {
          [options.outfile]: { imports },
        },
      },
    };
  });

  await expect(
    buildRelease({
      packageRoot,
      outputDirectory,
      releaseTag: `v${PACKAGE_VERSION}`,
      sourceCommit: "a".repeat(40),
    }),
  ).rejects.toThrow(message);
}

describe("release build guards", () => {
  it("rejects unresolved package imports", async () => {
    await expectBuildGuard(
      "#!/usr/bin/env node\n",
      "unresolved package imports: fixture-package",
      [{ external: true, path: "fixture-package" }],
    );
  });

  it("rejects missing and duplicate shebangs", async () => {
    await expectBuildGuard("console.log('fixture');\n", "missing the required");
    await expectBuildGuard(
      "#!/usr/bin/env node\n#!/usr/bin/env node\n",
      "more than one shebang",
    );
  });

  it("rejects executables above the release size ceiling", async () => {
    const shebang = Buffer.from("#!/usr/bin/env node\n", "utf8");
    const oversized = Buffer.concat([
      shebang,
      Buffer.alloc(RELEASE_MAX_BYTES + 1 - shebang.byteLength, 0x20),
    ]);
    await expectBuildGuard(oversized, "maximum is");
  });
});
