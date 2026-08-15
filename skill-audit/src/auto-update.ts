/**
 * Auto-update intelligence feeds for skill-audit
 *
 * This module provides explicit updating of vulnerability intelligence
 * feeds (KEV, EPSS, NVD).
 * 
 * Features:
 * - Awaitable refresh with caller cancellation
 * - Graceful degradation (use stale cache if fetch fails)
 * - Verbose mode for transparency
 */

import { isCacheStale, fetchKEV, fetchEPSS, fetchNVD, saveToCache } from "./intel.js";

export interface AutoUpdateOptions {
  /** Enable verbose logging (default: false) */
  verbose?: boolean;
  /** Timeout in ms before giving up on fetch (default: 5000) */
  timeout?: number;
  /** Delay before starting update in ms (default: 100) */
  delay?: number;
  /** Abort an in-progress delay or feed request */
  signal?: AbortSignal;
}

const DEFAULT_OPTIONS = {
  verbose: false,
  timeout: 5000,
  delay: 100
};

type ResolvedAutoUpdateOptions = typeof DEFAULT_OPTIONS & Pick<AutoUpdateOptions, "signal">;

/**
 * Log message if verbose mode is enabled
 */
function log(verbose: boolean, ...args: unknown[]): void {
  if (verbose) {
    console.log("[auto-update]", ...args);
  }
}

/**
 * Update intelligence feeds if stale.
 * 
 * @param options - Configuration options
 * @returns Promise that resolves after every stale feed has completed or degraded gracefully
 */
export async function ensureIntelFeedsFresh(options: AutoUpdateOptions = {}): Promise<void> {
  const opts: ResolvedAutoUpdateOptions = { ...DEFAULT_OPTIONS, ...options };

  await waitForDelay(opts.delay, opts.signal);
  await updateFeeds(opts);
}

/**
 * Internal function that performs the actual update
 */
async function updateFeeds(opts: ResolvedAutoUpdateOptions): Promise<void> {
  const sources = ["kev", "epss", "nvd"] as const;

  for (const source of sources) {
    throwIfAborted(opts.signal);

    const staleInfo = isCacheStale(source);
    const stale = staleInfo?.stale ?? false;

    if (stale) {
      log(opts.verbose, `Cache stale for ${source}, fetching...`);
      
      const controller = new AbortController();
      const forwardAbort = () => controller.abort(opts.signal?.reason);
      opts.signal?.addEventListener("abort", forwardAbort, { once: true });
      if (opts.signal?.aborted) forwardAbort();
      const timeoutId = setTimeout(
        () => controller.abort(new Error(`Timeout after ${opts.timeout}ms`)),
        opts.timeout
      );

      try {
        const records = await (source === "kev"
          ? fetchKEV(controller.signal)
          : source === "epss" 
            ? fetchEPSS(controller.signal)
            : fetchNVD(controller.signal));

        throwIfAborted(opts.signal);
        throwIfAborted(controller.signal);

        if (records && records.length > 0) {
          saveToCache(source, records);
          log(opts.verbose, `Updated ${source}: ${records.length} records`);
        }
      } catch (error) {
        throwIfAborted(opts.signal);

        // Graceful degradation: use stale cache with warning
        const age = staleInfo?.age?.toFixed(1) ?? "unknown";
        log(opts.verbose, `Failed to update ${source}, using stale cache (${age} days old):`, 
          error instanceof Error ? error.message : "Unknown error");
        // Don't throw - continue with stale cache
      } finally {
        clearTimeout(timeoutId);
        opts.signal?.removeEventListener("abort", forwardAbort);
      }
    } else {
      log(opts.verbose, `Cache fresh for ${source}`);
    }
  }
}

function waitForDelay(delay: number, signal?: AbortSignal): Promise<void> {
  throwIfAborted(signal);
  if (delay <= 0) return Promise.resolve();

  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, delay);
    const onAbort = () => {
      clearTimeout(timeoutId);
      signal?.removeEventListener("abort", onAbort);
      reject(abortReason(signal));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw abortReason(signal);
}

function abortReason(signal?: AbortSignal): Error {
  return signal?.reason instanceof Error ? signal.reason : new Error("Feed refresh aborted");
}

/**
 * Check if feeds need update without actually updating
 * Useful for showing status to users
 */
export function getFeedStatus(): Array<{
  source: string;
  stale: boolean;
  age?: number;
  warn: boolean;
}> {
  const sources = ["kev", "epss", "nvd"] as const;
  return sources.map(source => {
    const info = isCacheStale(source);
    return {
      source,
      stale: info?.stale ?? true,
      age: info?.age,
      warn: info?.warn ?? false
    };
  });
}
