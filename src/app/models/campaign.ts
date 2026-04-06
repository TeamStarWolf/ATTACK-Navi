// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
export interface Campaign {
  id: string;
  attackId: string;
  name: string;
  description: string;
  url: string;
  aliases: string[];
  firstSeen: string;  // ISO date string or empty
  lastSeen: string;   // ISO date string or empty
  attributedGroupIds: string[]; // STIX IDs of attributed intrusion-sets
}
