const SECRET_NAME = /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)/i;
export const MASK = "[REDACTED]";

/** Collect values of env vars whose names look secret. Values are kept only in memory. */
export function secretValues(env: NodeJS.ProcessEnv = process.env): string[] {
  const out = new Set<string>();
  for (const [name, value] of Object.entries(env)) {
    if (value && value.length >= 4 && SECRET_NAME.test(name)) out.add(value);
  }
  // Longest first so overlapping secrets are fully masked.
  return [...out].sort((a, b) => b.length - a.length);
}

export class Redactor {
  constructor(private readonly secrets: string[]) {}
  static fromEnv(env: NodeJS.ProcessEnv = process.env): Redactor {
    return new Redactor(secretValues(env));
  }
  text(input: string): string {
    let s = input;
    for (const v of this.secrets) s = s.split(v).join(MASK);
    return s;
  }
  /** Deep-redact any JSON-serialisable value. */
  value<T>(input: T): T {
    return JSON.parse(this.text(JSON.stringify(input))) as T;
  }
}
