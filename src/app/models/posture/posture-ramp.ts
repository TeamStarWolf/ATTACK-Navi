// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The Posture lens's ordinal, CVD-safe ramp (Phase 2 design §3 P2-13, plan
// 4.1) as theme tokens, and the lens's projection and colour functions (§2.5).
//
// One fill per bucket and theme:
//   none    = the theme's surface (the matrix panel, --bg-elevated)
//   known   = a neutral blue-grey
//   partial = the Known fill; the cell adds a dashed blue outline (D16, §6)
//   covered = blue
//   proven  = teal; the cell adds a check mark
//   stale   = the proven teal mixed 50% toward the surface; the check mark
//             stays and the label says 'stale' (D10, §7)
// and three patterns the cell draws on top of the fill, so they never depend
// on hue alone:
//   contradicted     = a vermilion hatched outline
//   not-reproducible = a grey cross-hatch
//   n/a              = the existing LENS_NA_COLOR hatch (heatmap-modes.ts),
//                      painted by the lensUnavailable path before any lens
//                      colour; the Posture lens has data in every domain.
//
// The ramp is ordinal under protanopia, deuteranopia and tritanopia in both
// themes: contrast from the surface rises none < known < covered < proven with
// at least 1.3:1 between neighbours (posture-ramp.cvd.spec.ts). It is safe by
// default, so the colorblind-safe setting does not change it.
//
// Runtime imports stay cycle-free: heatmap-modes.ts imports this file, and
// this file imports only types from it.
import type { Technique } from '../technique';
import type { LensCell, LensContext, LensRampStop } from '../heatmap-modes';
import type { PostureBucket, PostureState, PostureSubState, ProofScope } from './posture.types';
import { hexContrast, mixHex } from '../cvd';
import { PROVEN, postureBadge, scenarioOutcomeLabel } from './posture-vocabulary';

export type PostureTheme = 'dark' | 'light';

/** The surface the matrix cells sit on (--bg-elevated in each theme). 'none' is this colour. */
export const POSTURE_SURFACE: Readonly<Record<PostureTheme, string>> = {
  dark: '#18181b',
  light: '#ffffff',
};

/** The three ordinal hues per theme; every other stop is derived from these and the surface. */
const BASE: Readonly<Record<PostureTheme, { known: string; covered: string; proven: string }>> = {
  dark: { known: '#3d4b5c', covered: '#2f6fd0', proven: '#2ec4a6' },
  light: { known: '#c3ccd6', covered: '#5b8fe0', proven: '#0b7a68' },
};

/** How far stale moves the proven hue toward the surface (§7). */
export const STALE_MIX = 0.5;

/** A stop's fill and the text colour drawn on it (whichever of black and white reads better). */
export interface PostureStopToken {
  readonly fill: string;
  readonly text: string;
}

function token(fill: string): PostureStopToken {
  return { fill, text: hexContrast(fill, '#000000') >= hexContrast(fill, '#ffffff') ? '#000000' : '#ffffff' };
}

function themeTokens(theme: PostureTheme): Readonly<Record<PostureBucket, PostureStopToken>> {
  const surface = POSTURE_SURFACE[theme];
  const b = BASE[theme];
  return {
    none: token(surface),
    known: token(b.known),
    partial: token(b.known),
    covered: token(b.covered),
    proven: token(b.proven),
    stale: token(mixHex(b.proven, surface, STALE_MIX)),
  };
}

/** The posture ramp as theme tokens: one fill and text colour per bucket and theme. */
export const POSTURE_TOKENS: Readonly<Record<PostureTheme, Readonly<Record<PostureBucket, PostureStopToken>>>> = {
  dark: themeTokens('dark'),
  light: themeTokens('light'),
};

/** Every bucket, in ramp (legend) order. */
export const POSTURE_BUCKETS: readonly PostureBucket[] = ['none', 'known', 'partial', 'covered', 'proven', 'stale'];

/** The four ordinal stops the CVD guarantee is about. */
export const POSTURE_ORDINAL_STOPS: readonly PostureBucket[] = ['none', 'known', 'covered', 'proven'];

/** A cell's ordinal score: higher is a higher rung; stale ranks below fresh proof. */
export const POSTURE_SCORE: Readonly<Record<PostureBucket, number>> = {
  none: 0, known: 1, partial: 2, covered: 3, stale: 4, proven: 5,
};

/** The pattern classes that tell sub-states apart without hue (asserted distinct by the CVD spec). */
export const POSTURE_PATTERN_CLASS = {
  partial: 'posture-partial',
  contradicted: 'posture-contradicted',
  'not-reproducible': 'posture-not-reproducible',
} as const;

export type PosturePattern = keyof typeof POSTURE_PATTERN_CLASS;

/** One technique's cell on the Posture lens (P2-13): the one new technique-cell input. */
export interface PostureCellVM {
  readonly bucket: PostureBucket;
  readonly subStates: readonly PostureSubState[];
  readonly proofScope: ProofScope | null;
  /** postureCellLabel(state, windows), or the lens's own cell words (P2-14): for aria-label and tooltip. */
  readonly label: string;
  /** The lens's score when it is not the Posture score (P2-14: Proven, Covered, Status, Controls). */
  readonly score?: number;
  /** The lens's categorical stop (P2-14: Status, Controls). */
  readonly implStop?: string;
}

/**
 * The words of the contradicted sub-state, one phrase for the legend stop and
 * for a contradicted cell's aria-label and tooltip (RP-F decision 11).
 */
export const CONTRADICTED_WORDS = 'contradicted by a later failed run';

/**
 * The lenses whose cell words name the contradicted sub-state. Paints implies
 * speaks (RP-F decision 17): every lens whose projection carries the
 * sub-states, so posturePatterns draws the contradicted hatch (Posture, Covered,
 * Proven), says so in its aria-label and tooltip; Status draws no hatch but its
 * stop comes from the same implementation marks, so it says so too (RP-F
 * decision 11). Controls keeps its own words: its projection drops sub-states.
 * posture-ramp.spec asserts the invariant over every posture-cell lens.
 */
export const CONTRADICTED_SPOKEN_LENSES: ReadonlySet<string> = new Set(['posture', 'covered', 'proven', 'status']);

/**
 * The words of one posture-cell lens cell, for its aria-label and tooltip
 * (§7 Decay, Rendering). On the Posture lens (no `lens`, or `lens.words`
 * absent) they are postureBadge(state), except that a stale cell names its
 * proof age and the decay window it passed, as "Proven (your run), stale (120
 * days; window 90)". `windows` are the D10 windows the state was derived with
 * (PostureService.decayDays). A stale state with no scope or age (never
 * produced by derivePosture) falls back to the badge. Another posture-cell
 * lens passes its own cell words as `lens.words` (P2-14).
 *
 * A contradicted state (a later failed run outranks the full marks or the
 * proof) adds ', contradicted by a later failed run' on the lenses in
 * CONTRADICTED_SPOKEN_LENSES, the way a stale cell names its age (RP-F
 * decisions 11 and 17): "Known: mapped, contradicted by a later failed run".
 */
export function postureCellLabel(
  s: Pick<PostureState, 'bucket' | 'qualifiers' | 'proofScope' | 'proofAge' | 'covered' | 'subStates'>,
  windows: Readonly<Record<ProofScope, number>>,
  lens: { readonly value: string; readonly words?: string } = { value: 'posture' },
): string {
  const words = lens.words ?? postureStateWords(s, windows);
  return CONTRADICTED_SPOKEN_LENSES.has(lens.value) && s.subStates.includes('contradicted')
    ? `${words}, ${CONTRADICTED_WORDS}`
    : words;
}

/** The Posture lens's own words for a state: the badge, or the stale age and window. */
function postureStateWords(
  s: Pick<PostureState, 'bucket' | 'qualifiers' | 'proofScope' | 'proofAge' | 'covered'>,
  windows: Readonly<Record<ProofScope, number>>,
): string {
  if (s.bucket !== 'stale' || s.proofScope === null || s.proofAge === null) return postureBadge(s);
  return `${postureBadge({ ...s, bucket: 'proven' })}, stale (${s.proofAge} days; window ${windows[s.proofScope]})`;
}

/** The fill of a bucket in a theme. */
export function postureFill(bucket: PostureBucket, theme: PostureTheme): string {
  return POSTURE_TOKENS[theme][bucket].fill;
}

/** The patterns a cell draws on top of its fill. */
export function posturePatterns(cell: Pick<PostureCellVM, 'bucket' | 'subStates'>): PosturePattern[] {
  const out: PosturePattern[] = [];
  if (cell.bucket === 'partial') out.push('partial');
  if (cell.subStates.includes('contradicted')) out.push('contradicted');
  if (cell.subStates.includes('not-reproducible')) out.push('not-reproducible');
  return out;
}

/** True when the cell shows the check mark: a recorded detection, fresh or stale. */
export function postureHasCheck(bucket: PostureBucket): boolean {
  return bucket === 'proven' || bucket === 'stale';
}

/** The Posture lens's projection (§2.5 `project`): the technique's own posture state. */
export function postureProject(ctx: Pick<LensContext, 'posture'>, t: Technique): LensCell {
  const s = ctx.posture(t);
  return { score: POSTURE_SCORE[s.bucket], bucket: s.bucket, subStates: s.subStates, proofScope: s.proofScope };
}

/**
 * The Posture lens's colour (§2.5 `color`): the bucket's fill in the theme.
 * `colorblindSafe` is deliberately unused: the ramp is CVD-safe by default.
 */
export function postureColor(cell: LensCell, ctx: Pick<LensContext, 'theme' | 'colorblindSafe'>): string {
  return postureFill(cell.bucket ?? 'none', ctx.theme);
}

/** The LensCell a technique cell rebuilds from its PostureCellVM input (null: no state yet, 'none'). */
export function postureLensCell(vm: PostureCellVM | null): LensCell {
  if (!vm) return { score: 0, bucket: 'none', subStates: [], proofScope: null };
  return {
    score: vm.score ?? POSTURE_SCORE[vm.bucket], bucket: vm.bucket, subStates: vm.subStates, proofScope: vm.proofScope,
    ...(vm.implStop !== undefined ? { implStop: vm.implStop } : {}),
  };
}

/**
 * The words of each stop. Every rung word comes from the vocabulary module
 * (§2.4): the Covered words carry their qualifier, the Proven word is PROVEN.
 * Surfaces render these only under hasOwnerWords() (§1.3).
 */
export function postureStopLabel(key: PostureBucket | PosturePattern): string {
  switch (key) {
    case 'none': return scenarioOutcomeLabel('none');
    case 'known': return scenarioOutcomeLabel('known');
    case 'partial': return `${scenarioOutcomeLabel('covered')}, partial`;
    case 'covered': return scenarioOutcomeLabel('covered');
    case 'proven': return PROVEN;
    case 'stale': return `${PROVEN} (stale)`;
    case 'contradicted': return CONTRADICTED_WORDS;
    default: return 'not reproducible';
  }
}

/** One legend entry: a fill, the pattern class it shows (if any) and its words. */
export interface PostureLegendStop {
  readonly key: PostureBucket | PosturePattern;
  readonly fill: string;
  /** The text (and check mark) colour on that fill. */
  readonly text: string;
  readonly patternClass: string | null;
  readonly check: boolean;
  readonly label: string;
}

/** The legend's posture stops in a theme: the six buckets, then the two sub-state patterns. */
export function postureLegendStops(theme: PostureTheme): PostureLegendStop[] {
  const buckets = POSTURE_BUCKETS.map((b): PostureLegendStop => ({
    key: b,
    fill: postureFill(b, theme),
    text: POSTURE_TOKENS[theme][b].text,
    patternClass: b === 'partial' ? POSTURE_PATTERN_CLASS.partial : null,
    check: postureHasCheck(b),
    label: postureStopLabel(b),
  }));
  const patterns = (['contradicted', 'not-reproducible'] as const).map((p): PostureLegendStop => ({
    key: p,
    fill: postureFill('known', theme),
    text: POSTURE_TOKENS[theme].known.text,
    patternClass: POSTURE_PATTERN_CLASS[p],
    check: false,
    label: postureStopLabel(p),
  }));
  return [...buckets, ...patterns];
}

/**
 * The registry's ramp stops (HEATMAP_MODES 'posture'.ramp): the six bucket
 * fills of the dark theme, which is what the minimap and the lens snapshot
 * paint (ThemeService starts dark).
 */
export function postureRampStops(): LensRampStop[] {
  return POSTURE_BUCKETS.map(b => ({ color: postureFill(b, 'dark'), label: postureStopLabel(b) }));
}
