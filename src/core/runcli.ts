/**
 * run_cli: a thin, read-only, whitelisted CLI executor (design doc §PR #6).
 *  - argv only, spawned as spawn(binary, args) with shell disabled; no string is ever handed to a shell.
 *  - each connector allows a fixed set of subcommand prefixes; credential flags and shell syntax are rejected.
 *  - each subcommand also has a flag ALLOWLIST (`args`); unlisted flags (e.g. --endpoint, --insecure) are rejected.
 *  - mongosh never takes agent argv: only fixed query templates (find / aggregate / countDocuments) that we render.
 *  - every call appends one hash-chained line to commands.jsonl (redacted argv, exit code, output sha256, cli
 *    name+version+profile name). Credentials are never logged: they stay in the CLI's own local login state.
 */
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";

export class CliRejectedError extends Error {
  constructor(message: string) { super(message); this.name = "CliRejectedError"; }
}

export interface ConnectorConfig {
  name: string;
  /** Executable name or absolute path. */
  binary: string;
  kind?: "cli" | "mongo";
  /** Allowed subcommand prefixes (argv after the binary). Ignored for kind=mongo. */
  allow?: string[][];
  /**
   * Per-subcommand flag ALLOWLIST, keyed by the subcommand prefix joined with a space (e.g. "sls GetLogs").
   * After the subcommand, argv must be `<flag> <value>` or `<flag>=<value>` pairs whose flag is listed here
   * (exact, case-sensitive). Anything else, including global flags such as --endpoint/--insecure, is rejected.
   * A subcommand with no entry accepts no extra arguments.
   */
  args?: Record<string, string[]>;
  /** Values accepted for `--region` (only if the subcommand allowlists it). Default: none, the profile's region is used. */
  regions?: string[];
  /** Extra denied flags (matched as `--flag` or `--flag=…`). Defence in depth only; the allowlist is what decides. */
  denyArgs?: string[];
  /** Name of the CLI's own local profile to use (`--profile <name>`); the name is logged, never its secrets. */
  profile?: string;
  /** mongo: connection string WITHOUT credentials (use the shell's own auth / a read-only user). */
  uri?: string;
  versionArgs?: string[];
  /**
   * Values accepted for `-n` (name server address). The agent may only pick one of these; if it omits `-n` and the
   * list is non-empty, the first entry is appended by us. Default: none, so any `-n` is rejected (no pivot to other hosts).
   */
  namesrvs?: string[];
  /** Message-body capping for subcommands that print message bodies: bodies are redacted, then cut to `maxChars`. */
  messageBody?: { subcommands: string[]; maxChars: number };
  /** Append `--profile <profile>` to argv (default true). False for CLIs without a profile flag; the name is still logged. */
  appendProfile?: boolean;
  /** Host env var names passed to the CLI in addition to the sandbox defaults. */
  passEnv?: string[];
}

export const PRESET_CONNECTORS: ConnectorConfig[] = [
  {
    name: "aliyun", binary: "aliyun",
    allow: [
      ["sls", "GetLogs"], ["sls", "GetHistograms"], ["sls", "ListLogStores"], ["sls", "ListProject"],
      ["cms", "DescribeAlertLogList"], ["cms", "DescribeMetricList"], ["cms", "DescribeMetricLast"], ["cms", "DescribeAlertHistoryList"],
    ],
    args: {
      "sls GetLogs": ["--project", "--logstore", "--from", "--to", "--query", "--topic", "--line", "--offset", "--reverse"],
      "sls GetHistograms": ["--project", "--logstore", "--from", "--to", "--query", "--topic"],
      "sls ListLogStores": ["--project", "--logstoreName", "--offset", "--size"],
      "sls ListProject": ["--projectName", "--offset", "--size"],
      "cms DescribeAlertLogList": ["--StartTime", "--EndTime", "--Namespace", "--MetricName", "--GroupId", "--RuleName", "--Level", "--PageNumber", "--PageSize"],
      "cms DescribeMetricList": ["--Namespace", "--MetricName", "--Dimensions", "--StartTime", "--EndTime", "--Period", "--Length", "--NextToken"],
      "cms DescribeMetricLast": ["--Namespace", "--MetricName", "--Dimensions", "--Period", "--Length", "--NextToken"],
      "cms DescribeAlertHistoryList": ["--StartTime", "--EndTime", "--RuleName", "--GroupId", "--State", "--Status", "--Page", "--PageSize"],
    },
  },
  {
    name: "mqadmin", binary: "mqadmin",
    // Query-only subcommands (names as in `mqadmin help`). Write/admin ones (updateTopic, deleteTopic, sendMessage,
    // resetOffsetByTime, updateSubGroup, wipeWritePerm, …) are simply absent and therefore rejected.
    allow: [["clusterList"], ["topicList"], ["topicStatus"], ["topicRoute"], ["topicClusterList"], ["consumerProgress"], ["consumerStatus"],
      ["queryMsgById"], ["queryMsgByKey"], ["queryMsgByUniqueKey"], ["brokerStatus"]],
    args: {
      clusterList: ["-n"], topicList: ["-n"], topicStatus: ["-n", "-t"], topicRoute: ["-n", "-t"], topicClusterList: ["-n", "-t"],
      consumerProgress: ["-n", "-g"], consumerStatus: ["-n", "-g", "-i"], queryMsgById: ["-n", "-i"],
      queryMsgByKey: ["-n", "-t", "-k"], queryMsgByUniqueKey: ["-n", "-i", "-t"], brokerStatus: ["-n", "-b", "-c"],
    },
    namesrvs: [], // set in config: the fixed name server address(es) the agent may query
    messageBody: { subcommands: ["queryMsgById", "queryMsgByKey", "queryMsgByUniqueKey"], maxChars: 2048 },
    appendProfile: false,
  },
  { name: "mongosh", binary: "mongosh", kind: "mongo" },
];

const CRED_FLAGS = ["--access-key-id", "--access-key-secret", "--sts-token", "--ram-role-arn", "--private-key", "--password", "-p", "--username", "-u",
  "--apiKey", "--token", "--secret", "--accessKey", "--secretKey", "--profile", "--eval", "-e", "--file", "-f", "--shell", "--nodb", "--config"];
const SHELLISH = /[;&|`<>$\n\r]|\$\(/;

export interface MongoTemplate {
  name: "find" | "aggregate" | "countDocuments";
  db: string; collection: string;
  filter?: Record<string, unknown>; projection?: Record<string, unknown>; sort?: Record<string, unknown>;
  limit?: number; pipeline?: Record<string, unknown>[];
}

export const AGG_STAGES = ["$match", "$project", "$group", "$sort", "$limit", "$skip", "$count", "$unwind", "$addFields", "$set", "$unset", "$lookup", "$sortByCount", "$replaceRoot"];
/** Operators that write ($out/$merge) or run server-side JS ($where/$function/$accumulator) — rejected at any depth. */
export const MONGO_FORBIDDEN = ["$out", "$merge", "$where", "$function", "$accumulator"];
const NAME = /^[A-Za-z0-9_][\w.-]{0,119}$/;

function scanForbidden(v: unknown, at: string): void {
  if (Array.isArray(v)) v.forEach((x, i) => scanForbidden(x, `${at}[${i}]`));
  else if (v && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) {
      if (MONGO_FORBIDDEN.includes(k)) throw new CliRejectedError(`${k} is not allowed (${at})`);
      scanForbidden(x, `${at}.${k}`);
    }
  }
}

/** Render a fixed mongosh query template into argv. Only data is substituted, as JSON string literals. */
export function mongoArgv(c: ConnectorConfig, t: MongoTemplate): string[] {
  if (!t || !["find", "aggregate", "countDocuments"].includes(t.name)) throw new CliRejectedError(`mongo template must be find|aggregate|countDocuments, got ${t?.name}`);
  if (!NAME.test(t.db ?? "") || !NAME.test(t.collection ?? "")) throw new CliRejectedError("invalid db/collection name");
  for (const [k, v] of Object.entries({ filter: t.filter, projection: t.projection, sort: t.sort })) {
    if (v !== undefined && (typeof v !== "object" || v === null || Array.isArray(v))) throw new CliRejectedError(`${k} must be an object`);
  }
  scanForbidden({ filter: t.filter, projection: t.projection, sort: t.sort, pipeline: t.pipeline }, "template");
  const limit = Math.min(Math.max(1, Math.trunc(t.limit ?? 100)), 1000);
  const lit = (v: unknown) => `EJSON.parse(${JSON.stringify(JSON.stringify(v ?? {}))})`;
  const coll = `db.getSiblingDB(${JSON.stringify(t.db)}).getCollection(${JSON.stringify(t.collection)})`;
  let expr: string;
  if (t.name === "aggregate") {
    if (!Array.isArray(t.pipeline)) throw new CliRejectedError("aggregate needs a pipeline array");
    for (const st of t.pipeline) {
      const keys = st && typeof st === "object" ? Object.keys(st) : [];
      if (keys.length !== 1 || !AGG_STAGES.includes(keys[0])) throw new CliRejectedError(`aggregate stage not allowed: ${keys.join(",") || JSON.stringify(st)}`);
    }
    expr = `${coll}.aggregate(${lit([...t.pipeline, { $limit: limit }])}).toArray()`;
  } else if (t.name === "countDocuments") {
    expr = `${coll}.countDocuments(${lit(t.filter)})`;
  } else {
    expr = `${coll}.find(${lit(t.filter)}, ${lit(t.projection)}).sort(${lit(t.sort)}).limit(${limit}).toArray()`;
  }
  if (c.uri && /\/\/[^/@]*@/.test(c.uri)) throw new CliRejectedError("connector uri must not embed credentials");
  return [...(c.uri ? [c.uri] : []), "--quiet", "--norc", "--eval", `print(EJSON.stringify(${expr}))`];
}

/** Validate agent argv for a cli connector and return the final argv (profile appended by us). */
export function cliArgv(c: ConnectorConfig, argv: string[]): string[] {
  if (!Array.isArray(argv) || argv.some((a) => typeof a !== "string")) throw new CliRejectedError("argv must be an array of strings");
  for (const a of argv) {
    if (SHELLISH.test(a)) throw new CliRejectedError(`argument contains shell syntax: ${JSON.stringify(a)}`);
    const flag = a.split("=")[0];
    if ([...CRED_FLAGS, ...(c.denyArgs ?? [])].includes(flag)) throw new CliRejectedError(`flag not allowed: ${flag}`);
  }
  const prefix = (c.allow ?? []).filter((p) => p.length <= argv.length && p.every((x, i) => argv[i] === x)).sort((a, b) => b.length - a.length)[0];
  if (!prefix) throw new CliRejectedError(`${c.name}: subcommand not in whitelist: ${argv.slice(0, 2).join(" ")}`);
  const allowed = c.args?.[prefix.join(" ")] ?? [];
  const rest = argv.slice(prefix.length);
  let sawNamesrv = false;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const eq = a.startsWith("-") ? a.indexOf("=") : -1;
    const flag = eq > 0 ? a.slice(0, eq) : a;
    if (!allowed.includes(flag)) throw new CliRejectedError(`${c.name} ${prefix.join(" ")}: argument not in allowlist: ${JSON.stringify(flag)}`);
    let value: string;
    if (eq > 0) value = a.slice(eq + 1);
    else {
      if (i + 1 >= rest.length) throw new CliRejectedError(`${c.name}: ${flag} needs a value`);
      value = rest[++i];
    }
    if (/^--?[A-Za-z]/.test(value)) throw new CliRejectedError(`${c.name}: ${flag} value looks like a flag: ${JSON.stringify(value)}`);
    if (flag === "--region" && !(c.regions ?? []).includes(value)) throw new CliRejectedError(`${c.name}: region not in allowlist: ${JSON.stringify(value)}`);
    if (c.namesrvs && flag === "-n") {
      if (!c.namesrvs.includes(value)) throw new CliRejectedError(`${c.name}: -n name server not in allowlist: ${JSON.stringify(value)}`);
      sawNamesrv = true;
    }
  }
  let out = argv;
  if (c.namesrvs && !sawNamesrv && c.namesrvs.length && allowed.includes("-n")) out = [...out, "-n", c.namesrvs[0]];
  return c.profile && c.appendProfile !== false ? [...out, "--profile", c.profile] : out;
}

export interface CommandLogEntry {
  seq: number; ts: string; walkthroughId: string; checkId?: string;
  connector: string; cli: { name: string; version: string; profile?: string };
  argv: string[]; cwd: string; exitCode: number; outputSha256: string; evidenceId: string;
  executedBy: "core"; prev: string; hash: string;
}

export const GENESIS = "0".repeat(64);
const entryHash = (e: Omit<CommandLogEntry, "hash">) => createHash("sha256").update(JSON.stringify(e)).digest("hex");

/** Append one entry; caller holds the walkthrough lock. Returns the new entry (with its hash). */
export function appendCommandLog(file: string, e: Omit<CommandLogEntry, "seq" | "prev" | "hash">): CommandLogEntry {
  return appendLogEntry(file, e as unknown as Record<string, unknown>) as unknown as CommandLogEntry;
}

/** Any hash-chained entry (run_cli calls, plan_append records). Same chain, same verification. */
export function appendLogEntry(file: string, e: Record<string, unknown>): { seq: number; hash: string; prev: string } & Record<string, unknown> {
  const lines = existsSync(file) ? readFileSync(file, "utf8").split("\n").filter(Boolean) : [];
  const last = lines.length ? (JSON.parse(lines[lines.length - 1]) as CommandLogEntry) : undefined;
  const base = { seq: lines.length + 1, ...e, prev: last?.hash ?? GENESIS };
  const full = { ...base, hash: entryHash(base as never) };
  appendFileSync(file, `${JSON.stringify(full)}\n`, { flag: "a" });
  return full;
}

/** Recompute the chain. `head` (stored in walkthrough.json) also catches truncation of the tail. */
export function verifyCommandLog(file: string, head?: { seq: number; hash: string }): { ok: boolean; entries: number; error?: string } {
  const lines = existsSync(file) ? readFileSync(file, "utf8").split("\n").filter(Boolean) : [];
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    let e: CommandLogEntry;
    try { e = JSON.parse(lines[i]); } catch { return { ok: false, entries: i, error: `line ${i + 1}: not JSON` }; }
    const { hash, ...rest } = e;
    if (e.seq !== i + 1) return { ok: false, entries: i, error: `line ${i + 1}: seq ${e.seq} out of order` };
    if (e.prev !== prev) return { ok: false, entries: i, error: `line ${i + 1}: prev hash mismatch` };
    if (entryHash(rest) !== hash) return { ok: false, entries: i, error: `line ${i + 1}: hash mismatch (entry modified)` };
    prev = hash;
  }
  if (head && (head.seq !== lines.length || head.hash !== prev)) return { ok: false, entries: lines.length, error: `head mismatch: expected seq ${head.seq}, log has ${lines.length} (truncated or replaced)` };
  return { ok: true, entries: lines.length };
}

/** Env vars that would redirect or re-credential a cloud CLI (endpoint, region, keys). Never passed to run_cli children. */
export const CLI_ENV_DENY = /^(ALIBABA_CLOUD_|ALICLOUD_|ALIYUN_|ACS_|NAMESRV_ADDR$|ROCKETMQ_)/i;

/**
 * Cap message bodies in query output: each `Message Body:` value (up to the next blank line) is passed through
 * `redact` FIRST (so a secret is never cut in half and partially kept), then cut to `maxChars`.
 */
export function capMessageBodies(output: string, maxChars: number, redact: (s: string) => string): string {
  return output.replace(/(Message Body:[ \t]*)([\s\S]*?)(?=\r?\n\s*\r?\n|$)/g, (_m, head: string, body: string) => {
    const r = redact(body);
    return r.length <= maxChars ? head + r : `${head}${r.slice(0, maxChars)}…[truncated ${r.length - maxChars} chars]`;
  });
}
