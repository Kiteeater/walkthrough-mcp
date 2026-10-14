// Mock `aliyun` CLI for `npm run demo` and the tests: answers `aliyun sls get-logs` / `get-logs-v2` like the real CLI,
// which prints the response body as JSON. Logs are objects whose values are all strings, with the reserved fields
// __time__ (unix seconds), __source__ and __topic__. get-logs returns the bare array; get-logs-v2 returns
// { meta: { progress: "Complete" | "Incomplete", count, … }, data: [ … ] } (SLS OpenAPI 2020-12-30).
// Only the read subcommand the demo uses is implemented; anything else exits 1 like an unknown API would.
// The query supports the plain search form the demo sends: `key: value and key: value` (exact matches).
import { chmodSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** cfg: { logs?: Record<string, string>[]; progress?: string | null } stored next to the binary; default: a few app/infra lines, no infra errors. */
export function writeMockAliyun(bin, cfg = {}) {
  const p = join(bin, "aliyun");
  writeFileSync(join(bin, "aliyun-cfg.json"), JSON.stringify(cfg));
  writeFileSync(p, `#!/usr/bin/env node
const fs=require("fs"),path=require("path");
const a=process.argv.slice(2);
if(a[0]==="--version"||a[0]==="version"){console.log("3.0.277-mock");process.exit(0)}
const cfg=JSON.parse(fs.readFileSync(path.join(__dirname,"aliyun-cfg.json"),"utf8"));
const opt=(f)=>{const i=a.indexOf(f);if(i>=0)return a[i+1];const e=a.find((x)=>x.startsWith(f+"="));return e?e.slice(f.length+1):undefined};
const v2=a[1]==="get-logs-v2";
if(a[0]!=="sls"||(a[1]!=="get-logs"&&!v2)){console.error("ERROR: mock supports only 'sls get-logs' and 'sls get-logs-v2'");process.exit(1)}
for(const f of ["--project","--logstore","--from","--to"]) if(!opt(f)){console.error("ERROR: "+f+" is required");process.exit(1)}
const from=Number(opt("--from")),to=Number(opt("--to"));
if(!(from<to)){console.error("ERROR: InvalidTimeRange: Request time range is invalid.");process.exit(1)}
const t=(d)=>String(from+d);
const logs=cfg.logs||[
  {__time__:t(1),__source__:"10.0.0.21",__topic__:"",layer:"infra",component:"slb",level:"INFO",message:"health check ok"},
  {__time__:t(2),__source__:"10.0.0.22",__topic__:"",layer:"infra",component:"ecs",level:"INFO",message:"cpu 23%, mem 41%"},
  {__time__:t(3),__source__:"10.0.0.31",__topic__:"",layer:"app",component:"orders",level:"ERROR",message:"GET /api/orders/ord-3/total 500"},
  {__time__:t(4),__source__:"10.0.0.23",__topic__:"",layer:"infra",component:"rds",level:"WARN",message:"slow query 210ms"},
];
const q=(opt("--query")||"*").trim();
const terms=q==="*"?[]:q.split(/\\s+and\\s+/i).map((x)=>{const m=/^(\\w+)\\s*:\\s*(\\S+)$/.exec(x.trim());if(!m){console.error("ERROR: InvalidQueryString: Query string is invalid.");process.exit(1)}return m});
const out=logs.filter((l)=>Number(l.__time__)>=from&&Number(l.__time__)<to&&terms.every((m)=>l[m[1]]===m[2]));
if(!v2){console.log(JSON.stringify(out,null,"\\t"));process.exit(0)}
// get-logs-v2: {meta, data}. cfg.progress: string (default "Complete"), or null to omit meta.progress entirely.
const meta={count:out.length,processedRows:logs.length,elapsedMillisecond:7,hasSQL:false,whereQuery:q,aggQuery:"",keys:out.length?Object.keys(out[0]).filter((k)=>!k.startsWith("__")):[]};
if(cfg.progress!==null) meta.progress=cfg.progress===undefined?"Complete":cfg.progress;
console.log(JSON.stringify({meta,data:out},null,"\\t"));
`);
  chmodSync(p, 0o755);
  return p;
}
