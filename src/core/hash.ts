// sha256File moved verbatim from walkthrough.ts (leaf module: node built-ins only), so ops/ can import it without a cycle.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

export const sha256File = (p: string) => createHash("sha256").update(readFileSync(p)).digest("hex");
