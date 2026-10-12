/**
 * Race `start(signal)` against a REF'd timer, so the returned promise always settles and the event loop
 * stays alive while it is pending. A bare `await fetch()` whose socket left the loop without settling made
 * Node drain the loop and exit 13 ("unsettled top-level await") — see test/exit13.test.ts.
 * Note: AbortSignal.timeout() uses an UNREF'd timer, so it does not give this guarantee.
 */
export function withDeadline<T>(start: (signal: AbortSignal) => Promise<T>, ms: number, what: string): Promise<T> {
  const ac = new AbortController();
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      ac.abort();
      reject(new Error(`${what}: no result after ${ms} ms`));
    }, ms);
    start(ac.signal).then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}
