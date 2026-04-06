// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
export interface AttackSoftware {
  id: string;          // STIX id (tool-- or malware--)
  attackId: string;    // e.g. "S0001"
  name: string;
  description: string;
  url: string;
  type: 'tool' | 'malware';
  platforms: string[];
  aliases: string[];
}
