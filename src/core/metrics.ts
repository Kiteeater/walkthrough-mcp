/**
 * Read-only metrics adapter interface.
 * TODO(PR 2): Prometheus HTTP API implementation (`/api/v1/query`), with the
 * endpoint and credentials read from env vars only. Not wired into v1 evidence.
 */
export interface MetricsSample { metric: Record<string, string>; value: number; at: string }

export interface MetricsAdapter {
  readonly kind: string;
  /** Run an instant query. Must not mutate the backend. */
  query(expr: string, at?: Date): Promise<MetricsSample[]>;
}

export class NotImplementedMetricsAdapter implements MetricsAdapter {
  readonly kind = "none";
  async query(): Promise<MetricsSample[]> {
    throw new Error("metrics adapter not implemented in v1 (planned for PR 2)");
  }
}
