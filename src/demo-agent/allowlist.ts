// Replay allowlist for the demo runners: the service under test (+ Prometheus when configured).

/**
 * Loopback exceptions for a local demo. `localhost` gets the same treatment as `127.0.0.1`: it is the same local
 * service, but the IP policy judges the address `localhost` resolves to, which is loopback and therefore denied unless
 * listed. Node may resolve it to 127.0.0.1 or ::1 (resolver order), so both exact loopback hosts are listed.
 */
export function loopbackCidrs(urls: URL[]): string[] {
  const cidrs = new Set<string>();
  for (const u of urls) {
    if (u.hostname === "127.0.0.1") cidrs.add("127.0.0.1/32");
    if (u.hostname === "localhost") { cidrs.add("127.0.0.1/32"); cidrs.add("::1/128"); }
  }
  return [...cidrs];
}
