// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
export interface ThreatGroup {
  id: string;        // STIX id (intrusion-set--xxx)
  attackId: string;  // e.g. G0001
  name: string;
  description: string;
  url: string;
  aliases: string[];
}
