// INTERNAL capability, deliberately NOT re-exported from core/index: only runFlow (flow.ts) imports it.
// A WeakMap (not a method or Symbol-keyed property) so nothing reachable from a WalkthroughCore instance, its
// prototype, or the package entry leads to the flow-policy screenshot path, which does not use replay.allowHosts.
import type { Evidence } from "./types.js";

export const flowScreenshot = new WeakMap<object, (id: string, url: string) => Promise<Evidence>>();
