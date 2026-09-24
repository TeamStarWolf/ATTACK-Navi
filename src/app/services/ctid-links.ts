// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

/**
 * Links into CTID's Mappings Explorer.
 *
 * The site is served from ctid.mitre.org/mappings. The
 * center-for-threat-informed-defense.github.io/mappings-explorer host answers on its
 * root but 404s on every deeper path, so links built on it appear to work — the root
 * loads — while every specific page fails. Attribution links across the app pointed at
 * that root, which is why a control link only ever reached the generic site.
 *
 * Framework slugs and dataset names here differ from the ones used in the raw data
 * repository (the data lives under `nist_800_53/.../nist_800_53-rev5` but the site
 * publishes it as `nist/.../nist-rev5`), so both are kept side by side and each was
 * checked against the live site rather than inferred.
 */

export const CTID_BASE = 'https://ctid.mitre.org/mappings';

export interface CtidDataset {
  /** Slug in the site URL, which is not always the slug in the data repository. */
  slug: string;
  /** ATT&CK version the mapping was published against. */
  attackVersion: string;
  /** Dataset segment in the site URL. */
  dataset: string;
  /** Whether the site publishes a page per capability id. */
  perControl: boolean;
}

/**
 * Verified against the live site. `perControl` is false where only the dataset page
 * resolves — linking a control there would 404, so the dataset page is used instead.
 */
export const CTID_DATASETS: Readonly<Record<string, CtidDataset>> = {
  m365: { slug: 'm365', attackVersion: '16.1', dataset: 'm365-07.18.2025', perControl: true },
  cri: { slug: 'cri_profile', attackVersion: '16.1', dataset: 'cri_profile-v2.1', perControl: true },
  nist: { slug: 'nist', attackVersion: '16.1', dataset: 'nist-rev5', perControl: false },
  csaCcm: { slug: 'csa_ccm', attackVersion: '17.1', dataset: 'csa_ccm-4.1', perControl: false },
  aws: { slug: 'aws', attackVersion: '16.1', dataset: 'aws-12.12.2024', perControl: false },
  azure: { slug: 'azure', attackVersion: '16.1', dataset: 'azure-04.26.2025', perControl: false },
  gcp: { slug: 'gcp', attackVersion: '16.1', dataset: 'gcp-03.06.2025', perControl: false },
  kev: { slug: 'kev', attackVersion: '16.1', dataset: 'kev-07.28.2025', perControl: false },
  veris: { slug: 'veris', attackVersion: '', dataset: '', perControl: false },
};

/** The dataset page for a framework, or its section page when there is no dataset. */
export function ctidDatasetUrl(key: keyof typeof CTID_DATASETS | string): string {
  const d = CTID_DATASETS[key];
  if (!d) return `${CTID_BASE}/`;
  if (!d.attackVersion || !d.dataset) return `${CTID_BASE}/external/${d.slug}/`;
  return `${CTID_BASE}/external/${d.slug}/attack-${d.attackVersion}/domain-enterprise/${d.dataset}/`;
}

/**
 * The page for one capability, falling back to the dataset page when the framework has
 * no per-control pages. Returning a working broader link beats returning a 404.
 */
export function ctidControlUrl(
  key: keyof typeof CTID_DATASETS | string,
  controlId: string,
): string {
  const d = CTID_DATASETS[key];
  if (!d?.perControl || !controlId) return ctidDatasetUrl(key);
  return ctidDatasetUrl(key) + encodeURIComponent(controlId) + '/';
}
