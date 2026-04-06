// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
export interface MitreDataSource {
  id: string;
  name: string;
  description: string;
  collectionLayers: string[];
}

export interface MitreDataComponent {
  id: string;
  name: string;
  dataSourceRef: string; // STIX id of parent MitreDataSource
  dataSourceName: string;
}
