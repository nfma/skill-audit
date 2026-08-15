import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("fs", async importOriginal => {
  const actual = await importOriginal<typeof import("fs")>();
  return {
    ...actual,
    mkdirSync: vi.fn(),
    writeFileSync: vi.fn(),
  };
});

import { fetchKEV, isCacheStale, saveToCache } from "./intel.js";

function streamingJsonResponse(signal: AbortSignal): Response {
  let bodyController: ReadableStreamDefaultController<Uint8Array>;
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      bodyController = controller;
      controller.enqueue(new TextEncoder().encode('{"vulnerabilities":['));
    },
  });

  signal.addEventListener("abort", () => {
    bodyController.error(signal.reason);
  }, { once: true });

  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("streaming feed cancellation", () => {
  it("aborts response-body parsing when the caller cancels after headers arrive", async () => {
    const caller = new AbortController();
    let requestSignal: AbortSignal | undefined;
    const fetchMock = vi.fn((_url: string | URL | Request, init?: RequestInit) => {
      requestSignal = init?.signal ?? undefined;
      return Promise.resolve(streamingJsonResponse(requestSignal!));
    });
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
    const fetchMock = vi.fn((_url: string | URL | Request, init?: RequestInit) => {
      return Promise.resolve(streamingJsonResponse(init?.signal as AbortSignal));
    });
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
    expect(() => isCacheStale("../../outside")).toThrow("Unsupported cache source");
    expect(() => saveToCache("../../outside", [])).toThrow("Unsupported cache source");
  });
});
