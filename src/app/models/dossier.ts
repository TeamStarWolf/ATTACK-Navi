// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { SsvcResult } from '../services/ssvc.service';

/**
 * A single CVE assembled across every framework the app knows about.
 *
 * Two ways to obtain one, and the difference is visible to the reader:
 *
 *   asset  a pre-generated file under assets/data/dossiers/. Produced offline by
 *          cve-dossier, so it can carry things the browser cannot reach — published
 *          reporting, Exploit-DB rows, full CWE mitigation text.
 *   live   composed in the browser from the services already loaded. Available for any
 *          CVE on demand, but limited to what those services expose.
 */
export type DossierSource = 'asset' | 'live';

/**
 * How strongly a technique is tied to this CVE.
 *
 *   exploitation / primary-impact / secondary-impact
 *       CTID maps these to THIS CVE and types each one.
 *   weakness-class
 *       derived from the CVE's CWEs via CAPEC. Describes how that class of weakness is
 *       attacked in general — not a claim about this CVE.
 */
export type DossierTier = 'exploitation' | 'primary-impact' | 'secondary-impact' | 'weakness-class';

export interface DossierTechnique {
  id: string;
  name: string;
  tier: DossierTier;
  tactics: string[];
  /** Set when the mapped id was retired and ATT&CK names a replacement. */
  supersedes?: string;
  /** Set when the id exists in no current release and has no replacement. */
  unresolved?: boolean;
  /** CTID's analyst note explaining the mapping, when there is one. */
  comment?: string;
}

export interface DossierNamed {
  id: string;
  name: string;
  url?: string;
  detail?: string;
}

export interface DossierControl {
  control: string;
  name: string;
  family?: string;
  techniques: string[];
}

export interface DossierCountermeasure {
  id: string;
  name: string;
  tactic: string;
  /**
   * The digital artifact the countermeasure operates on — the telemetry you must be
   * collecting for it to work. Only D3FEND's offensive-to-defensive mapping carries
   * this, so it is present on generated assets and absent when composed live: the
   * in-app D3FEND service exposes a definition, which is not the same thing.
   */
  artifact?: string;
  /** D3FEND's prose definition of the countermeasure. */
  definition?: string;
  techniques: string[];
}

export interface DossierDetection {
  techniqueId: string;
  techniqueName: string;
  notes: string[];
  dataComponents: string[];
  sigmaRuleCount: number;
  atomicTestCount: number;
  /** Runnable hunt queries, asset-only. */
  queries: { platform: string; title: string; query: string; dataSource?: string }[];
}

export interface DossierExploits {
  hasPoc: boolean;
  pocUrl?: string;
  exploitDb: { id: string; title: string; url: string; date?: string }[];
  publicPocs: { repo: string; url: string; stars?: number }[];
  advisories: { id: string; url: string; severity?: string }[];
  exploitTaggedRefs: string[];
}

export interface DossierArticle {
  title: string;
  url: string;
  source: string;
  date?: string;
  tier?: 'research' | 'press' | 'other';
}

export interface CveDossier {
  cveId: string;
  generated: string;
  source: DossierSource;

  description: string;
  published?: string;
  cvssScore: number | null;
  cvssVector: string | null;
  severity: string;
  epss: number | null;
  epssPercentile: number | null;
  isKev: boolean;
  kevDateAdded?: string;
  kevDueDate?: string;
  kevRansomware?: boolean;
  kevVendorProject?: string;
  kevProduct?: string;

  ssvc: SsvcResult | null;

  cwes: DossierNamed[];
  capecs: DossierNamed[];
  techniques: DossierTechnique[];
  mitigations: DossierNamed[];
  countermeasures: DossierCountermeasure[];
  engage: DossierNamed[];
  controls: DossierControl[];
  detection: DossierDetection[];
  exploits: DossierExploits;
  articles: DossierArticle[];

  /** Everything the assembly could not establish. Shown, never swallowed. */
  warnings: string[];
  /** Which ATT&CK release the techniques were resolved against. */
  attackVersion?: string;
}

/** Ordering and labels for the technique tiers. */
export const TIER_ORDER: DossierTier[] = [
  'exploitation',
  'primary-impact',
  'secondary-impact',
  'weakness-class',
];

export const TIER_LABEL: Readonly<Record<DossierTier, string>> = {
  exploitation: 'Exploitation',
  'primary-impact': 'Primary impact',
  'secondary-impact': 'Secondary impact',
  'weakness-class': 'Weakness-class signals',
};

export const TIER_BLURB: Readonly<Record<DossierTier, string>> = {
  exploitation: 'How this CVE is exploited. Mapped to this CVE by CTID.',
  'primary-impact': 'What exploiting it gains the adversary directly. Mapped to this CVE by CTID.',
  'secondary-impact': 'What adversaries have been observed doing afterwards. Mapped to this CVE by CTID.',
  'weakness-class':
    'Derived from this CVE’s weaknesses via CAPEC. Describes how that class of ' +
    'weakness is attacked in general — not a claim about this CVE.',
};
