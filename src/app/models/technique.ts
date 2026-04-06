// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
export interface Technique {
  id: string;               // STIX id
  attackId: string;         // e.g. "T1190" or "T1055.011"
  name: string;
  description: string;
  url: string;
  tacticShortnames: string[];
  isSubtechnique: boolean;
  parentId: string | null;  // STIX id of parent technique
  subtechniques: Technique[];
  mitigationCount: number;
  platforms: string[];
  // Enrichment fields from STIX
  dataSources: string[];          // x_mitre_data_sources
  detectionText: string;          // x_mitre_detection
  defenseBypassed: string[];      // x_mitre_defense_bypassed
  permissionsRequired: string[];  // x_mitre_permissions_required
  effectivePermissions: string[];  // x_mitre_effective_permissions
  systemRequirements: string[];    // x_mitre_system_requirements
  impactType: string[];            // x_mitre_impact_type
  remoteSupport: boolean;          // x_mitre_remote_support
  capecIds: string[];              // CAPEC IDs from external_references
}
