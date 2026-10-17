// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The 'Reference depth' lens (heat=unified): how much DEFENSIVE reference
// material the world has mapped to a technique. It is a Known-rung number
// (plan 4.1): it says nothing about what is deployed in your estate.
//
// Inputs are defensive reference sources only. Threat-side signals (groups,
// software, campaigns, KEV) are deliberately NOT inputs: they describe how
// much adversaries care, which the Threat lenses (Frequency, Selected
// adversaries, Intelligence, KEV, Threat-weighted mapping gap) show. Adding a
// group that uses a technique must never change its Reference depth, so the
// input type below has no field a threat signal could flow through.

/** Per-technique counts of each defensive reference source. */
export interface ReferenceDepthInputs {
  /** ATT&CK mitigations mapped to the technique. */
  mitigations: number;
  /** Detection content available: Sigma rules plus CAR analytics. */
  detectionContent: number;
  /** CTID control-framework mappings (NIST 800-53, CRI, CIS, CSA CCM, M365). */
  controls: number;
  /** D3FEND countermeasures. */
  d3fend: number;
  /** Atomic Red Team tests. */
  atomic: number;
}

/**
 * Weight and saturation point of each input. The relative weights are the
 * ones the composite used before the threat-intel and KEV terms left it
 * (mitigations 15, detection content 20, controls 15, D3FEND 10, Atomic 10);
 * the sum is rescaled to 0-100 so the lens's colour thresholds keep their
 * meaning.
 */
export const REFERENCE_DEPTH_TERMS: Readonly<Record<keyof ReferenceDepthInputs, { weight: number; saturatesAt: number }>> = {
  mitigations: { weight: 15, saturatesAt: 4 },
  detectionContent: { weight: 20, saturatesAt: 5 },
  controls: { weight: 15, saturatesAt: 4 },
  d3fend: { weight: 10, saturatesAt: 2 },
  atomic: { weight: 10, saturatesAt: 3 },
};

const TOTAL_WEIGHT = Object.values(REFERENCE_DEPTH_TERMS).reduce((sum, t) => sum + t.weight, 0);

/** Reference depth, 0-100 (integer). 0 = no defensive reference mapped; 100 = every source saturated. */
export function referenceDepthScore(inputs: ReferenceDepthInputs): number {
  let raw = 0;
  for (const key of Object.keys(REFERENCE_DEPTH_TERMS) as Array<keyof ReferenceDepthInputs>) {
    const { weight, saturatesAt } = REFERENCE_DEPTH_TERMS[key];
    const count = Number.isFinite(inputs[key]) ? Math.max(0, inputs[key]) : 0;
    raw += Math.min(count / saturatesAt, 1) * weight;
  }
  return Math.round((raw * 100) / TOTAL_WEIGHT);
}

// ─── Reference depth bands (replace the old Detect letter grades) ──────────
//
// The Detect panels used to grade techniques 'Excellent', 'Good', 'Poor' and
// so on from reference-content counts (CAR, Atomic, D3FEND, Engage). Those
// counts are Known-rung: they say how much content the world has mapped, not
// how well you detect. Plan 4.1 allows 'mapped', 'available' and 'reference
// depth' for Known data and bans letter grades, so the panels show a
// reference-depth band instead, with the same neutral words as the Reference
// depth legend.

export type ReferenceDepthBand = 'none' | 'thin' | 'some' | 'deep' | 'deepest';

/** Display words for each band. 'none' is a fact about the reference data, never 'safe' or 'at risk'. */
export const REFERENCE_DEPTH_BAND_LABELS: Readonly<Record<ReferenceDepthBand, string>> = {
  none: 'None mapped',
  thin: 'Thin',
  some: 'Some',
  deep: 'Deep',
  deepest: 'Deepest',
};

/** Bands in ascending order. */
export const REFERENCE_DEPTH_BANDS: readonly ReferenceDepthBand[] = ['none', 'thin', 'some', 'deep', 'deepest'];

/**
 * The band a reference-content count falls in. `floors` are the lowest counts
 * for thin, some, deep and deepest (ascending); anything below the first floor
 * (including 0, negatives and non-finite values) is 'none'.
 */
export function referenceDepthBand(
  count: number,
  floors: readonly [thin: number, some: number, deep: number, deepest: number],
): ReferenceDepthBand {
  const n = Number.isFinite(count) ? count : 0;
  if (n >= floors[3]) return 'deepest';
  if (n >= floors[2]) return 'deep';
  if (n >= floors[1]) return 'some';
  if (n >= floors[0]) return 'thin';
  return 'none';
}
