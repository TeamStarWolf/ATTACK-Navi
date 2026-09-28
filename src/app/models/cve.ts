// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
export interface NvdCveItem {
  id: string;                    // CVE-2023-12345
  description: string;
  cvssScore: number | null;
  cvssVector: string | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'UNKNOWN';
  cwes: string[];                // ['CWE-78', 'CWE-89']
  cpes: string[];                // affected product CPE strings
  published: string;             // ISO date
  lastModified: string;
  references: { url: string; tags: string[] }[];
  // Enriched
  mappedAttackIds: string[];     // ['T1190', 'T1059'] — corrected CWE->ATT&CK mapping (anchor-first)
  /** Confidence tiers for mappedAttackIds: high = exploitation-nature anchor, low = CAPEC-derived. */
  mappedAttackTiers?: { high: string[]; low: string[] };
  isKev: boolean;
  kevDateAdded?: string;
  kevDueDate?: string;
  kevVendorProject?: string;
  kevProduct?: string;
  kevKnownRansomware?: boolean;
  epssScore?: number | null;
  epssPercentile?: number | null;
}

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string; // 'Known' | 'Unknown'
  notes: string;
  cwes?: string;
}
