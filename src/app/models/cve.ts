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
  /** Free-text fields: present in the live feed, left out of the bundled snapshot (no view reads them). */
  shortDescription?: string;
  requiredAction?: string;
  dueDate: string;
  knownRansomwareCampaignUse: string; // 'Known' | 'Unknown'
  notes?: string;
  /** The live feed sends an array; older copies sent a comma-separated string. */
  cwes?: string | string[];
}

/**
 * What an SSVC evaluation may conclude from KEV membership (plan E1.3).
 *
 * "Not in the catalogue" means "not known to be exploited" only when a catalogue is on
 * hand. When neither the live feed nor the bundled snapshot loaded, exploitation is
 * unknown and SSVC blocks the decision instead of falling through to 'track'.
 */
export interface KevContext {
  /** A KEV catalogue (live, or the bundled snapshot) is on hand. */
  available: boolean;
  /** YYYY-MM-DD of the bundled snapshot when that is the catalogue on hand; null for the live feed. */
  snapshotDate: string | null;
}

/** No KEV catalogue on hand: exploitation is unknown for any CVE not already flagged in KEV. */
export const KEV_UNAVAILABLE: KevContext = { available: false, snapshotDate: null };

/** The live KEV feed is loaded. */
export const KEV_LIVE: KevContext = { available: true, snapshotDate: null };

/** The bundled KEV snapshot of `date` is the catalogue on hand. */
export function kevSnapshot(date: string): KevContext {
  return { available: true, snapshotDate: date };
}
