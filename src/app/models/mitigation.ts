export interface Mitigation {
  id: string;       // STIX id
  attackId: string; // e.g. "M1031"
  name: string;
  description: string;
  url: string;
}

export interface MitigationRelationship {
  mitigation: Mitigation;
  description: string; // how the mitigation addresses the technique
}
