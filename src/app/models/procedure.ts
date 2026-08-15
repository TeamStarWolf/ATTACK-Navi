// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
export interface ProcedureExample {
  sourceId: string;    // STIX id of the group, software, or campaign
  sourceName: string;
  attackId: string;    // e.g. G0016, S0002, or C0015
  sourceType: 'group' | 'tool' | 'malware' | 'campaign';
  description: string; // relationship description from STIX
}
