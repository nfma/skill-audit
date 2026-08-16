import { defaultExclude, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      exclude: ["src/**/*.test.ts"],
      include: [
        "src/**/*.ts",
        "scripts/build-release.ts",
        "scripts/generate-release-data.ts",
        "scripts/verify-release.ts",
      ],
      provider: "v8",
      reporter: ["text", "lcov"],
    },
    exclude: [...defaultExclude, "dist/**"],
  },
});
