/** A claim backed by evidence ids: the shared shape of root-cause steps, ruled-out and inconclusive hypotheses. */
export interface Cite {
  claim: string;
  evidence_ids: string[];
}
