// Mock mqadmin in the rocketmq-all-5.5.1 output format, shared by `npm run demo` and the tests.
import { chmodSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Mock mqadmin reproducing the 5.5.1 output format (rocketmq-all-5.5.1, efa1be5):
 *  - queryMsgByUniqueKey: showMessage L82-116 (`%-20s %s%n` lines, `Message Body Path:` L102, no body printed, then
 *    `%n%nWARN: No Consumer`), body written raw by createBodyFile L119-138 to `/tmp/rocketmq/msgbodys/<msgId>`.
 *    (queryMsgById is not mocked: the preset rejects it, #26.)
 *  - consumerProgress (no -s): ConsumerProgressSubCommand L146-154 / L192-201 / L205-208.
 * Behaviour comes from cfg.json next to the binary: dir (stands in for /tmp/rocketmq/msgbodys), body, fileId
 * (defaults to the -i value), noWrite, delayMs, waitFiles, listAll (print a path line for every file in dir, like a hostile output), queues ([qid, brokerOffset, consumerOffset][]), tps.
 */
export function writeMockMqadmin(bin, cfg) {
  const p = join(bin, "mqadmin");
  writeFileSync(join(bin, "cfg.json"), JSON.stringify(cfg));
  writeFileSync(p, `#!/usr/bin/env node
const fs=require("fs"),path=require("path");
const cfg=JSON.parse(fs.readFileSync(path.join(__dirname,"cfg.json"),"utf8"));
const a=process.argv.slice(2);
if(a[0]==="--version"){console.log("mqadmin 5.5.1-mock");process.exit(0)}
fs.appendFileSync(path.join(__dirname,"calls.jsonl"),JSON.stringify({argv:a,env:Object.keys(process.env)})+"\\n");
const opt=(f)=>{const i=a.indexOf(f);return i>=0?a[i+1]:undefined};
const out=(k,v)=>process.stdout.write(k.padEnd(20)+" "+v+"\\n");
const sub=a[0];
if(sub==="queryMsgByUniqueKey"){
  const id=opt("-i"), fileId=cfg.fileId||id, file=path.join(cfg.dir,fileId);
  if(!cfg.noWrite){fs.mkdirSync(cfg.dir,{recursive:true});fs.writeFileSync(file,cfg.body||"")}
  let paths=[file];
  const finish=()=>{
    out("Topic:",opt("-t")); out("Tags:","[TagA]"); out("Keys:","[ord-1]"); out("Queue ID:",3); out("Queue Offset:",42);
    out("CommitLog Offset:",4660); out("Reconsume Times:",0); out("Born Timestamp:","2026-10-13 07:00:00,123");
    out("Store Timestamp:","2026-10-13 07:00:00,130"); out("Born Host:","10.0.0.8:53412"); out("Store Host:","10.0.0.5:10911");
    out("System Flag:",0); out("Properties:","{UNIQ_KEY="+fileId+", KEYS=ord-1, TAGS=TagA}");
    for(const x of paths) out("Message Body Path:",x);
    process.stdout.write("\\n\\nWARN: No Consumer");
  };
  // waitFiles (barrier for the concurrency test): wait until that many body files exist, take the listing, then wait
  // until every process has taken its listing before printing, so no core deletes a file before all have listed.
  const wait=(cond,then)=>{const t0=Date.now();const t=()=>(!cond()&&Date.now()-t0<5000)?setTimeout(t,20):then();t()};
  const list=()=>{ if(cfg.listAll) paths=fs.readdirSync(cfg.dir).map((f)=>path.join(cfg.dir,f)); };
  setTimeout(()=>{
    if(!cfg.waitFiles){list();return finish();}
    wait(()=>fs.readdirSync(cfg.dir).length>=cfg.waitFiles,()=>{
      list(); fs.writeFileSync(path.join(__dirname,"listed-"+id),"");
      wait(()=>fs.readdirSync(__dirname).filter((f)=>f.startsWith("listed-")).length>=cfg.waitFiles,finish);
    });
  },cfg.delayMs||0);
} else if(sub==="consumerProgress"){
  // ConsumerProgressSubCommand L146-154 (header), L192-201 (row), L205-208 (totals); no -s, so no Client IP column.
  // header "%-64s  %-32s  %-4s  %-20s  %-20s  %-20s %-20s%s%n"; row "... %-20d %-20d %s%n" (one space before LastTime)
  const row=(t,b,q,bo,co,d,inf,lt,sep)=>process.stdout.write(String(t).padEnd(64)+"  "+String(b).padEnd(32)+"  "+String(q).padEnd(4)+"  "+String(bo).padEnd(20)+"  "+String(co).padEnd(20)+"  "+String(d).padEnd(20)+" "+String(inf).padEnd(20)+sep+lt+"\\n");
  row("#Topic","#Broker Name","#QID","#Broker Offset","#Consumer Offset","#Diff","#Inflight","#LastTime","");
  const qs=cfg.queues||[[0,1042,1042],[1,1038,1038],[2,1051,1051],[3,1047,1047]];
  let diff=0,infl=0;
  for(const [q,bo,co] of qs){diff+=bo-co;row(opt("-t")||"%RETRY%"+opt("-g"),"broker-a",q,bo,co,bo-co,0,"2026-10-13 07:00:00"," ")}
  process.stdout.write("\\n");
  process.stdout.write("Consume TPS: "+(cfg.tps??12.5).toFixed(2)+"\\n");
  process.stdout.write("Consume Diff Total: "+diff+"\\n");
  process.stdout.write("Consume Inflight Total: "+infl+"\\n");
} else console.log("TOPIC-STATUS orders brokerOffset=42 "+a.join(" "));
`);
  chmodSync(p, 0o755);
  return p;
}
