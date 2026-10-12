import type { Sandbox } from "./sandbox.js";
import type { Judgement } from "./checks.js";
import type { Check, CheckAction, ObserveSpec, Walkthrough } from "./types.js";

/**
 * Pluggable seams. evaluate_check only talks to the verifier registry; action/observe sources are the
 * execution seam the host agent (or the demo agent) uses — the core itself no longer executes checks. New
 * sources (e.g. `connector:<name>` for read-only environment connectors) and verifier types can be
 * registered without touching them.
 */
export interface SourceContext { walkthrough: Walkthrough; sandbox: Sandbox }

/** Result of running an action source; `evidenceText` is stored as sha256 `response` evidence. */
export interface ActionOutcome {
  status?: number;
  exitCode?: number;
  body: string;
  evidenceText: string;
  repro: string;
}

export interface ActionSource<A extends CheckAction = CheckAction> {
  type: A["type"];
  run(action: A, ctx: SourceContext): Promise<ActionOutcome>;
}

/** Observation source (logs today; connectors later): snapshot before the action, collect the delta after. */
export interface ObserveSource<O extends ObserveSpec = ObserveSpec> {
  source: O["source"];
  snapshot(spec: O, ctx: SourceContext): Promise<unknown>;
  collect(spec: O, ctx: SourceContext, before: unknown): Promise<{ label: string; text: string; evidenceType: "logs" | "response" }>;
}

export interface ObservedData { status?: number; exitCode?: number; body: string; logs: string }

/** Verifier types: `rule` ships in v1; `script`, `playwright`, `computer-use` are reserved slots. */
export type VerifierType = "rule" | "script" | "playwright" | "computer-use" | (string & {});
/** Judges a check over the raw texts of its verified evidence. */
export interface Verifier { type: VerifierType; verify(check: Check, evidenceTexts: string[]): Promise<Judgement> }

export class Registry {
  private actions = new Map<string, ActionSource>();
  private observers = new Map<string, ObserveSource>();
  private verifiers = new Map<string, Verifier>();

  registerAction<A extends CheckAction>(src: ActionSource<A>): this { this.actions.set(src.type, src as unknown as ActionSource); return this; }
  registerObserver<O extends ObserveSpec>(src: ObserveSource<O>): this { this.observers.set(src.source, src as unknown as ObserveSource); return this; }
  registerVerifier(v: Verifier): this { this.verifiers.set(v.type, v); return this; }

  action(type: string): ActionSource {
    const a = this.actions.get(type);
    if (!a) throw new Error(`no action source registered for "${type}"`);
    return a;
  }
  observer(source: string): ObserveSource {
    const o = this.observers.get(source);
    if (!o) throw new Error(`no observe source registered for "${source}"`);
    return o;
  }
  verifier(type: string): Verifier {
    const v = this.verifiers.get(type);
    if (!v) throw new Error(`verifier "${type}" is not available yet`);
    return v;
  }
  has(kind: "action" | "observer" | "verifier", key: string): boolean {
    return (kind === "action" ? this.actions : kind === "observer" ? this.observers : this.verifiers).has(key);
  }
}
