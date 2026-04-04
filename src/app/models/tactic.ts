export interface Tactic {
  id: string;         // STIX id
  attackId: string;   // e.g. "TA0001"
  name: string;
  shortname: string;  // x_mitre_shortname, matches kill_chain_phases
  description: string;
  url: string;
  order: number;      // position in matrix tactic_refs
}
