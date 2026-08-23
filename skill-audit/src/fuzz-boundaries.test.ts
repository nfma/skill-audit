import { join, resolve } from "path";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { isWithinRoot } from "./discover.js";
import { canonicalizeJson } from "./release-assets.js";
import { parseMetadataList } from "./security.js";

const portableSegment = fc.string({
  unit: fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz0123456789-_"),
  minLength: 1,
  maxLength: 24,
});

describe("fuzzed security boundaries", () => {
  it("accepts descendants and rejects sibling-prefix paths", () => {
    fc.assert(
      fc.property(
        fc.array(portableSegment, { minLength: 1, maxLength: 8 }),
        portableSegment,
        (segments, sibling) => {
          const root = resolve("/", "skill-audit-fuzz-root");
          expect(isWithinRoot(root, join(root, ...segments))).toBe(true);
          expect(
            isWithinRoot(root, resolve(root, "..", `sibling-${sibling}`)),
          ).toBe(false);
        },
      ),
      { numRuns: 500 },
    );
  });

  it("normalizes arbitrary metadata lists without empty entries", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 4096 }), (value) => {
        const parsed = parseMetadataList(value);
        if (parsed === undefined) {
          expect(value.split(",").every((item) => item.trim() === "")).toBe(
            true,
          );
          return;
        }

        expect(parsed.length).toBeGreaterThan(0);
        expect(
          parsed.every((item) => item.length > 0 && item === item.trim()),
        ).toBe(true);
      }),
      { numRuns: 500 },
    );
  });

  it("canonicalizes arbitrary JSON values deterministically", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        const first = canonicalizeJson(value);
        const second = canonicalizeJson(JSON.parse(first));
        expect(second).toBe(first);
        expect(JSON.parse(first)).toEqual(JSON.parse(JSON.stringify(value)));
      }),
      { numRuns: 500 },
    );
  });
});
