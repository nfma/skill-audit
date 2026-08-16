import { existsSync, readFileSync, writeFileSync } from "fs";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs")>();
  return {
    ...actual,
    existsSync: vi.fn(() => false),
    mkdirSync: vi.fn(),
    readFileSync: vi.fn(() => {
      throw new Error("intel tests must not read the developer's filesystem");
    }),
    writeFileSync: vi.fn(),
  };
});

import {
  type AdvisoryRecord,
  fetchEPSS,
  fetchKEV,
  fetchNVD,
  isCacheStale,
  mergeByAlias,
  prioritizeRecords,
  queryGHSA,
  queryOSV,
  saveToCache,
} from "./intel.js";

function advisory(
  id: string,
  source: AdvisoryRecord["source"],
  aliases: string[] = [],
  epss?: number,
): AdvisoryRecord {
  return { id, aliases, source, epss, references: [] };
}

function streamingJsonResponse(signal: AbortSignal): Response {
  let bodyController: ReadableStreamDefaultController<Uint8Array>;
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      bodyController = controller;
      controller.enqueue(new TextEncoder().encode('{"vulnerabilities":['));
    },
  });

  signal.addEventListener(
    "abort",
    () => {
      bodyController.error(signal.reason);
    },
    { once: true },
  );

  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

describe("streaming feed cancellation", () => {
  it("aborts response-body parsing when the caller cancels after headers arrive", async () => {
    const caller = new AbortController();
    let requestSignal: AbortSignal | undefined;
    const fetchMock = vi.fn(
      (_url: string | URL | Request, init?: RequestInit) => {
        requestSignal = init?.signal ?? undefined;
        return Promise.resolve(streamingJsonResponse(requestSignal!));
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const request = fetchKEV(caller.signal);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    caller.abort(new Error("cancelled while streaming"));

    await expect(request).resolves.toEqual([]);
    expect(requestSignal?.aborted).toBe(true);
    expect(consoleSpy).not.toHaveBeenCalled();
  });

  it("keeps the per-attempt timeout active while the response body streams", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn(
      (_url: string | URL | Request, init?: RequestInit) => {
        return Promise.resolve(
          streamingJsonResponse(init?.signal as AbortSignal),
        );
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    vi.spyOn(console, "error").mockImplementation(() => {});

    const request = fetchKEV(undefined, 10);
    await vi.runAllTimersAsync();

    await expect(request).resolves.toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});

describe("cache source boundaries", () => {
  it("rejects cache source names that could escape the feed directory", () => {
    expect(() => isCacheStale("../../outside")).toThrow(
      "Unsupported cache source",
    );
    expect(() => saveToCache("../../outside", [])).toThrow(
      "Unsupported cache source",
    );
  });

  it("reports fresh, stale, and malformed cache metadata", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-16T12:00:00Z"));
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValueOnce(
      JSON.stringify({
        source: "kev",
        fetchedAt: "2026-08-16T00:00:00Z",
        recordCount: 1,
      }),
    );

    expect(isCacheStale("KEV")).toEqual({
      stale: false,
      age: 0.5,
      warn: false,
    });

    vi.mocked(readFileSync).mockReturnValueOnce(
      JSON.stringify({
        source: "kev",
        fetchedAt: "2026-08-10T12:00:00Z",
        recordCount: 1,
      }),
    );
    expect(isCacheStale("kev")).toEqual({
      stale: true,
      age: 6,
      warn: true,
    });

    vi.mocked(readFileSync).mockImplementationOnce(() => {
      throw new Error("malformed cache metadata");
    });
    expect(isCacheStale("kev")).toEqual({ stale: true, warn: false });
  });

  it("writes records and cache metadata for supported sources", () => {
    vi.mocked(existsSync).mockReturnValue(true);
    const record = advisory("CVE-2026-0001", "KEV", ["GHSA-fixture"]);

    saveToCache("KEV", [record]);

    expect(writeFileSync).toHaveBeenCalledTimes(2);
    expect(vi.mocked(writeFileSync).mock.calls[0]?.[1]).toBe(
      JSON.stringify(record),
    );
    expect(
      JSON.parse(String(vi.mocked(writeFileSync).mock.calls[1]?.[1])),
    ).toMatchObject({ source: "kev", recordCount: 1 });
  });
});

describe("advisory aggregation", () => {
  it("indexes records by normalized ids and aliases", () => {
    const first = advisory("CVE-2026-0001", "OSV", ["ghsa-fixture"]);
    const second = advisory("GHSA-FIXTURE", "GHSA", ["cve-2026-0001"]);
    const merged = mergeByAlias([first, second]);

    expect(merged.get("CVE-2026-0001")).toEqual([first, second]);
    expect(merged.get("GHSA-FIXTURE")).toEqual([first, second]);
  });

  it("prioritizes sources and then descending EPSS scores", () => {
    const records = [
      advisory("EPSS-low", "EPSS", [], 0.1),
      advisory("KEV", "KEV"),
      advisory("EPSS-high", "EPSS", [], 0.9),
      advisory("NVD", "NVD"),
      advisory("GHSA", "GHSA"),
      advisory("OSV", "OSV"),
      advisory("SONATYPE", "SONATYPE"),
    ];

    expect(prioritizeRecords(records).map((record) => record.id)).toEqual([
      "OSV",
      "GHSA",
      "NVD",
      "KEV",
      "EPSS-high",
      "EPSS-low",
      "SONATYPE",
    ]);
    expect(records[0]?.id).toBe("EPSS-low");
  });
});

describe("advisory response normalization", () => {
  it("normalizes OSV and authenticated GHSA responses", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          vulns: [
            {
              id: "OSV-2026-1",
              aliases: ["CVE-2026-0001"],
              severity: [{ type: "CVSS_V3", score: "7.5" }],
              published: "2026-08-01",
              modified: "2026-08-02",
              summary: "OSV fixture",
              references: [{ type: "WEB", url: "https://osv.dev/v/fixture" }],
            },
          ],
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          data: {
            securityVulnerabilities: {
              nodes: [
                {
                  advisory: {
                    ghsaId: "GHSA-fixture",
                    summary: "GHSA fixture",
                    severity: "HIGH",
                    publishedAt: "2026-08-03",
                    identifiers: [{ type: "CVE", value: "CVE-2026-0001" }],
                  },
                  severity: "HIGH",
                  vulnerableVersionRange: "< 2.0.0",
                },
              ],
            },
          },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubEnv("GITHUB_TOKEN", "fixture-token");

    await expect(queryOSV("npm", "fixture-package")).resolves.toEqual([
      expect.objectContaining({
        id: "OSV-2026-1",
        aliases: ["CVE-2026-0001"],
        severity: "CVSS_V3",
        references: ["https://osv.dev/v/fixture"],
      }),
    ]);
    await expect(queryGHSA("npm", "fixture-package")).resolves.toEqual([
      expect.objectContaining({
        id: "GHSA-fixture",
        aliases: ["CVE-2026-0001"],
        severity: "HIGH",
      }),
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1]?.[1]).toMatchObject({
      headers: expect.objectContaining({
        Authorization: "Bearer fixture-token",
      }),
    });
  });

  it("normalizes successful KEV, EPSS, and NVD feeds", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          vulnerabilities: [
            {
              cveID: "CVE-2026-0002",
              dateAdded: "2026-08-04",
              shortDescription: "KEV fixture",
              reference: "https://www.cisa.gov/fixture",
            },
          ],
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          status: "OK",
          total: 1,
          limit: 500,
          data: [
            {
              cve: "CVE-2026-0002",
              epss: "0.75",
              percentile: "0.95",
              date: "2026-08-05",
            },
          ],
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          resultsPerPage: 1,
          startIndex: 0,
          totalResults: 1,
          format: "NVD_CVE",
          version: "2.0",
          vulnerabilities: [
            {
              cve: {
                id: "CVE-2026-0002",
                published: "2026-08-04",
                lastModified: "2026-08-05",
                vulnerabilityStatus: "Analyzed",
                descriptions: [{ lang: "en", value: "NVD fixture" }],
                metrics: {
                  cvssMetricV31: [
                    {
                      cvssData: {
                        version: "3.1",
                        vectorString: "CVSS:3.1/AV:N/AC:L",
                        baseScore: 9.8,
                        baseSeverity: "CRITICAL",
                      },
                    },
                  ],
                },
                weaknesses: [
                  { description: [{ lang: "en", value: "CWE-79" }] },
                ],
                references: [{ url: "https://nvd.nist.gov/vuln/fixture" }],
              },
            },
          ],
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubEnv("NVD_API_KEY", "fixture-key");

    await expect(fetchKEV()).resolves.toEqual([
      expect.objectContaining({
        id: "CVE-2026-0002",
        kev: true,
        references: ["https://www.cisa.gov/fixture"],
      }),
    ]);
    await expect(fetchEPSS()).resolves.toEqual([
      expect.objectContaining({ id: "CVE-2026-0002", epss: 0.75 }),
    ]);
    await expect(fetchNVD()).resolves.toEqual([
      expect.objectContaining({
        id: "CVE-2026-0002",
        cvss: 9.8,
        cvssVector: "CVSS:3.1/AV:N/AC:L",
        cwe: ["CWE-79"],
        summary: "NVD fixture",
        references: ["https://nvd.nist.gov/vuln/fixture"],
      }),
    ]);
    expect(fetchMock.mock.calls[2]?.[1]).toMatchObject({
      headers: expect.objectContaining({ apiKey: "fixture-key" }),
    });
  });
});
