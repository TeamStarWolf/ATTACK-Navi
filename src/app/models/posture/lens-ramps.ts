// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The four registry-hosted lenses P2-14 adds or re-derives (Phase 2 design §3
// P2-14, §6): Proven, Covered (self-attested or range), Status and Controls.
// Each has a projection (`project`, §2.5) and ONE colour function (`color`)
// that the technique cell, the minimap (MatrixComponent.getCellColor) and the
// legend all call, so the hex copies the status and controls lenses held in
// heatmap-modes.ts, technique-cell, the minimap and the legend are gone.
//
// Ramps. Every ramp is ordinal: its fills run from the theme's surface (the
// Posture lens's 'none') toward one hue of the posture ramp (posture-ramp.ts),
// mixed in sRGB, so luminance rises with the stop. Covered, Status and
// Controls run toward the Covered blue (plan 4.1: the Covered ordinal ramp);
// Proven runs toward the Proven teal, and its stale stop IS the Posture lens's
// stale fill. Neighbouring stops differ by at least 1.2:1 in both themes, for
// normal vision and under protanopia, deuteranopia and tritanopia
// (status-lens-guard.spec.ts), so the colorblind-safe setting does not change them.
//
// The D16 breadth guard (§6) reaches all four through PostureService: Covered
// and Controls read the guarded CoveredMarks of PostureState, Status reads
// PostureService.implViewFor. A partial cell (a broad mitigation only) also
// carries bucket 'partial', so the cell draws the Posture lens's dashed
// outline and the partial stop never depends on hue alone.
//
// Words. Every Proven word is composed from PROVEN and every Covered word
// names its qualifier (posture-vocabulary.ts, §2.4). Stops whose words are
// Covered or Proven words are flagged `ownerWords`: the legend renders them
// only under PostureService.ownerWords (§1.3).
//
// Runtime imports stay cycle-free: heatmap-modes.ts imports this file, and
// this file imports only types from it.
import type { Technique } from '../technique';
import type { LensCell, LensContext } from '../heatmap-modes';
import type { ImplStatus } from '../../services/implementation.service';
import type { PostureBucket } from './posture.types';
import { hexContrast, mixHex } from '../cvd';
import { POSTURE_SURFACE, STALE_MIX, type PostureTheme, postureFill } from './posture-ramp';
import { PROVEN, scenarioOutcomeLabel } from './posture-vocabulary';

/** One stop of a P2-14 lens ramp: its key (the cell's implStop or score), mix toward the hue, and words. */
interface RampSpec {
  readonly key: string;
  /** 1 = the surface, 0 = the full hue. */
  readonly mix: number;
  readonly label: string;
  /** The label is a Covered or Proven word: render it only under ownerWords (§1.3). */
  readonly ownerWords: boolean;
  /** The cell draws the dashed partial outline on this stop. */
  readonly partial?: boolean;
  /** The cell draws the check mark on this stop. */
  readonly check?: boolean;
}

/** One legend entry of a registry-hosted lens (the shape PostureLegendStop also has). */
export interface LensLegendStop {
  readonly key: string;
  readonly fill: string;
  /** Black or white, whichever reads better on the fill. */
  readonly text: string;
  readonly patternClass: string | null;
  readonly check: boolean;
  readonly label: string;
  /** The label is a Covered or Proven word (§1.3). */
  readonly ownerWords: boolean;
}

function fillOf(hue: 'covered' | 'proven', mix: number, theme: PostureTheme): string {
  if (mix >= 1) return POSTURE_SURFACE[theme];
  // Proven at 0.5 is the Posture lens's own stale fill (posture-ramp.ts STALE_MIX), by the same mix.
  return mix <= 0 ? postureFill(hue, theme) : mixHex(postureFill(hue, theme), POSTURE_SURFACE[theme], mix);
}

/** Black or white, whichever reads better on the fill (the cell decides with tinycolor the same way). */
function readableOn(fill: string): string {
  return hexContrast(fill, '#000000') >= hexContrast(fill, '#ffffff') ? '#000000' : '#ffffff';
}

function legendOf(hue: 'covered' | 'proven', specs: readonly RampSpec[], theme: PostureTheme): LensLegendStop[] {
  return specs.map(s => {
    const fill = fillOf(hue, s.mix, theme);
    return {
      key: s.key, fill, text: readableOn(fill), patternClass: s.partial ? 'posture-partial' : null,
      check: !!s.check, label: s.label, ownerWords: s.ownerWords,
    };
  });
}

function fillFor(hue: 'covered' | 'proven', specs: readonly RampSpec[], key: string, theme: PostureTheme): string {
  const spec = specs.find(s => s.key === key) ?? specs[0];
  return fillOf(hue, spec.mix, theme);
}

// ─── Status (heat=status): the guarded best mitigation status (R1) ──────────

/** The status lens's stops, in ordinal (legend) order; 'partial' sits between in progress and implemented (§10.4 item 14). */
export const STATUS_STOPS = ['none', 'not-started', 'planned', 'in-progress', 'partial', 'implemented'] as const;
export type StatusStop = (typeof STATUS_STOPS)[number];

const STATUS_SPECS: readonly RampSpec[] = [
  { key: 'none', mix: 1, label: 'none', ownerWords: false },
  { key: 'not-started', mix: 0.77, label: 'not started', ownerWords: false },
  { key: 'planned', mix: 0.57, label: 'planned', ownerWords: false },
  { key: 'in-progress', mix: 0.39, label: 'in progress', ownerWords: false },
  { key: 'partial', mix: 0.2, label: 'implemented, partial via a broad mitigation', ownerWords: false, partial: true },
  { key: 'implemented', mix: 0, label: 'implemented', ownerWords: false },
];

/** The status stop of a guarded implementation view: implemented through broad mitigations only is 'partial'. */
export function statusStop(view: { readonly status: ImplStatus | null; readonly partialVia: string | null }): StatusStop {
  if (view.status === 'implemented' && view.partialVia) return 'partial';
  return view.status ?? 'none';
}

/** The words of one status cell: 'implemented, partial via M1038', 'in progress', 'none'. */
export function statusStopLabel(stop: StatusStop, partialVia: string | null = null): string {
  if (stop === 'partial' && partialVia) return `implemented, partial via ${partialVia}`;
  return STATUS_SPECS.find(s => s.key === stop)!.label;
}

/** heat=status projection: the stop of PostureService.implViewFor(t), scored by its ordinal rank. */
export function statusProject(ctx: Pick<LensContext, 'implView'>, t: Technique): LensCell {
  const view = ctx.implView(t);
  const stop = statusStop(view);
  return {
    score: STATUS_STOPS.indexOf(stop), implStop: stop, bucket: stop === 'partial' ? 'partial' : 'none',
    subStates: [], proofScope: null, label: `Status: ${statusStopLabel(stop, view.partialVia)}`,
  };
}

/** heat=status colour: the stop's fill on the Covered ordinal ramp. */
export function statusColor(cell: LensCell, ctx: Pick<LensContext, 'theme' | 'colorblindSafe'>): string {
  return fillFor('covered', STATUS_SPECS, cell.implStop ?? 'none', ctx.theme);
}

/** The fill of a status stop (the coverage lens's implementation dot uses it too). */
export function statusStopFill(stop: StatusStop, theme: PostureTheme): string {
  return fillFor('covered', STATUS_SPECS, stop, theme);
}

export function statusLegendStops(theme: PostureTheme): LensLegendStop[] {
  return legendOf('covered', STATUS_SPECS, theme);
}

// ─── Controls (heat=controls): the guarded control marks (R1) ──────────────

export const CONTROL_STOPS = ['none', 'planned', 'partial', 'covered'] as const;
export type ControlStop = (typeof CONTROL_STOPS)[number];

const CONTROL_SPECS: readonly RampSpec[] = [
  { key: 'none', mix: 1, label: 'none', ownerWords: false },
  { key: 'planned', mix: 0.62, label: 'planned', ownerWords: false },
  { key: 'partial', mix: 0.3, label: 'Covered (self-attested), partial via a broad mitigation', ownerWords: true, partial: true },
  { key: 'covered', mix: 0, label: 'Covered (self-attested)', ownerWords: true },
];

/**
 * The controls stop of a technique from its CoveredMarks: a full control mark
 * is 'covered', a partial one (the control lists a mitigation broader than the
 * D16 threshold) 'partial', a planned one 'planned'.
 */
export function controlStop(marks: readonly { readonly basis: string; readonly strength: string }[]): ControlStop {
  let best: ControlStop = 'none';
  for (const m of marks) {
    if (m.basis !== 'control-implemented') continue;
    const stop: ControlStop = m.strength === 'full' ? 'covered' : m.strength === 'partial' ? 'partial' : 'planned';
    if (CONTROL_STOPS.indexOf(stop) > CONTROL_STOPS.indexOf(best)) best = stop;
  }
  return best;
}

/** heat=controls projection over PostureState.covered (control marks only). */
export function controlsProject(ctx: Pick<LensContext, 'posture'>, t: Technique): LensCell {
  const s = ctx.posture(t);
  const stop = controlStop(s.covered);
  const via = stop === 'partial'
    ? [...new Set(s.covered.filter(m => m.basis === 'control-implemented' && m.strength === 'partial' && m.via).map(m => m.via!))].sort()
    : [];
  const label = stop === 'partial' && via.length > 0
    ? `Covered (self-attested, partial via ${via.join(', ')})`
    : CONTROL_SPECS.find(c => c.key === stop)!.label;
  return {
    score: CONTROL_STOPS.indexOf(stop), implStop: stop, bucket: stop === 'partial' ? 'partial' : 'none',
    subStates: [], proofScope: null, label: `Controls: ${label}`,
  };
}

export function controlsColor(cell: LensCell, ctx: Pick<LensContext, 'theme' | 'colorblindSafe'>): string {
  return fillFor('covered', CONTROL_SPECS, cell.implStop ?? 'none', ctx.theme);
}

export function controlsLegendStops(theme: PostureTheme): LensLegendStop[] {
  return legendOf('covered', CONTROL_SPECS, theme);
}

// ─── Covered (self-attested or range): score 2 full / 1 partial / 0 ────────

const COVERED_SPECS: readonly RampSpec[] = [
  { key: '0', mix: 1, label: 'none', ownerWords: false },
  { key: '1', mix: 0.4, label: `${scenarioOutcomeLabel('covered')}, partial`, ownerWords: true, partial: true },
  { key: '2', mix: 0, label: scenarioOutcomeLabel('covered'), ownerWords: true },
];

/**
 * heat=covered projection: 2 when a full CoveredMark stands (self-attested or
 * range, not contradicted by a later failed run), 1 when only partial marks do
 * (D16), else 0. Planned marks score 0. Proof does not score here: the lens
 * shows the Covered rung on its own.
 */
export function coveredProject(ctx: Pick<LensContext, 'posture'>, t: Technique): LensCell {
  const s = ctx.posture(t);
  const contradicted = s.subStates.includes('contradicted');
  const full = !contradicted && s.covered.some(m => m.strength === 'full');
  const partial = !full && s.covered.some(m => m.strength === 'partial');
  const score = full ? 2 : partial ? 1 : 0;
  const bucket: PostureBucket = full ? 'covered' : partial ? 'partial' : 'none';
  return { score, bucket, subStates: s.subStates, proofScope: null, label: coveredLabel(bucket, s.covered) };
}

function coveredLabel(bucket: PostureBucket, marks: readonly { readonly strength: string; readonly via?: string }[]): string {
  if (bucket === 'covered') return scenarioOutcomeLabel('covered');
  if (bucket !== 'partial') return 'None';
  const via = [...new Set(marks.filter(m => m.strength === 'partial' && m.via).map(m => m.via!))].sort();
  return via.length > 0 ? `Covered (self-attested or range), partial via ${via.join(', ')}` : COVERED_SPECS[1].label;
}

export function coveredColor(cell: LensCell, ctx: Pick<LensContext, 'theme' | 'colorblindSafe'>): string {
  return fillFor('covered', COVERED_SPECS, String(cell.score), ctx.theme);
}

export function coveredLegendStops(theme: PostureTheme): LensLegendStop[] {
  return legendOf('covered', COVERED_SPECS, theme);
}

// ─── Proven: score 3 production / 2 range or own run / 1 stale / 0 ─────────

const PROVEN_SPECS: readonly RampSpec[] = [
  { key: '0', mix: 1, label: 'no recorded detection', ownerWords: false },
  { key: '1', mix: STALE_MIX, label: `${PROVEN} (stale)`, ownerWords: true, check: true },
  { key: '2', mix: 0.25, label: `${PROVEN} in range or your run`, ownerWords: true, check: true },
  { key: '3', mix: 0, label: `${PROVEN} in production`, ownerWords: true, check: true },
];

/**
 * heat=proven projection (plan:680): a fresh production proof scores 3, a
 * fresh range or own-run proof 2, a proof past its D10 window 1, no proof 0.
 * The cell keeps the bucket (proven or stale, for the check mark) and the
 * best proof's scope (for the 'lab' badge on range proof).
 */
export function provenProject(ctx: Pick<LensContext, 'posture'>, t: Technique): LensCell {
  const s = ctx.posture(t);
  if (s.bucket !== 'proven' && s.bucket !== 'stale') {
    return { score: 0, bucket: 'none', subStates: s.subStates, proofScope: null, label: PROVEN_SPECS[0].label };
  }
  const score = s.bucket === 'stale' ? 1 : s.proofScope === 'production' ? 3 : 2;
  const scope = s.proofScope === 'production' ? ' in production' : s.proofScope === 'range' ? ' in range' : s.proofScope === 'own-run' ? ' (your run)' : '';
  return {
    score, bucket: s.bucket, subStates: s.subStates, proofScope: s.proofScope,
    label: PROVEN + scope + (s.bucket === 'stale' ? ' (stale)' : ''),
  };
}

export function provenColor(cell: LensCell, ctx: Pick<LensContext, 'theme' | 'colorblindSafe'>): string {
  return fillFor('proven', PROVEN_SPECS, String(cell.score), ctx.theme);
}

export function provenLegendStops(theme: PostureTheme): LensLegendStop[] {
  return legendOf('proven', PROVEN_SPECS, theme);
}

/** True when a Proven cell shows the 'lab' text badge: its best proof was recorded in the range (E2.5 asserts it). */
export function provenLabBadge(cell: Pick<LensCell, 'score' | 'proofScope'>): boolean {
  return cell.score > 0 && cell.proofScope === 'range';
}

/** A registry ramp (HEATMAP_MODES ramp.stops) from a legend: the dark fills the minimap and the snapshot paint. */
export function rampStopsOf(legend: (theme: PostureTheme) => readonly LensLegendStop[]): { color: string; label: string }[] {
  return legend('dark').map(s => ({ color: s.fill, label: s.label }));
}
