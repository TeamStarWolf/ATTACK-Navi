// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
export interface ProcedureExample {
  sourceId: string;    // STIX id of the group or software
  sourceName: string;
  attackId: string;    // e.g. G0016 or S0002
  sourceType: 'group' | 'tool' | 'malware';
  description: string; // relationship description from STIX
}
