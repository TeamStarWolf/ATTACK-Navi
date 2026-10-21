// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The LensRegistry seam (Phase 2 design §2.5, §3 P2-13). A registry-hosted
// lens carries its own `project` and `color` on its HEATMAP_MODES entry, so
// the technique cell, the minimap (MatrixComponent.getCellColor) and the
// legend all call ONE colour function for it instead of holding three hex
// copies. A lens without them is a legacy lens: the matrix switchboard scores
// it and each surface keeps its own branch, byte for byte as before (the
// frozen-hash guard in lens-snapshots.spec.ts proves the 31 remaining legacy
// lenses unchanged). Registry-hosted today: posture (P2-13); status and
// controls, re-derived through PostureService, and proven and covered (P2-14).
import type { Technique } from './technique';
import type { LensCell, LensContext, LensDefinition } from './heatmap-modes';

/** A lens id (HeatmapMode), as a LensDefinition carries it. */
export type LensMode = LensDefinition['value'];

/** A registry-hosted lens: one that projects and colours itself. */
export type RegistryLens = LensDefinition & Required<Pick<LensDefinition, 'project' | 'color'>>;

/** True when `def` projects and colours itself (both functions present). */
export function isRegistryLens(def: LensDefinition | undefined | null): def is RegistryLens {
  return !!def && typeof def.project === 'function' && typeof def.color === 'function';
}

/** One technique's cell on a registry lens. Throws for a legacy lens, which has no projection. */
export function registryCell(def: LensDefinition, ctx: LensContext, t: Technique): LensCell {
  if (!def.project) throw new Error(`lens '${def.value}' is not registry-hosted (no project)`);
  return def.project(ctx, t);
}

/** The colour of a projected cell on a registry lens. Throws for a legacy lens, which has no colour function. */
export function registryColor(def: LensDefinition, cell: LensCell, ctx: Pick<LensContext, 'theme' | 'colorblindSafe'>): string {
  if (!def.color) throw new Error(`lens '${def.value}' is not registry-hosted (no color)`);
  return def.color(cell, ctx);
}

/**
 * The lenses whose menu label is itself a rung word (the Proven and Covered
 * lenses). Their names may render only when PostureService.ownerWords() is
 * true (§1.3; design §10.4 item 14: rung words never appear for an empty user).
 * One rule for every surface that names a lens: the heatmap-mode picker
 * (MatrixControlsComponent), the View button and the legend (lensOnScreen),
 * the matrix page's fallback for a heat= link, and the settings sentence.
 */
export const OWNER_WORD_LENSES: ReadonlySet<string> = new Set(['proven', 'covered']);

/** Whether `def`'s name may render: always, unless it is an owner-word lens and no owner data exists. */
export function lensNameVisible(def: Pick<LensDefinition, 'value'>, ownerWords: boolean): boolean {
  return ownerWords || !OWNER_WORD_LENSES.has(def.value);
}

/**
 * The lens to put on screen for `mode`: `mode` itself, or `fallback` (the
 * default lens) while its name may not render. A link with heat=covered or
 * heat=proven, opened with no owner data, shows the default lens instead.
 */
export function lensOnScreen(mode: LensMode, ownerWords: boolean, fallback: LensMode): LensMode {
  return lensNameVisible({ value: mode }, ownerWords) ? mode : fallback;
}

/**
 * Registry lenses whose every number is the owner's Covered or Proven data
 * (Posture, Proven, Covered). With no owner words they are titled
 * NO_OWNER_DATA_LINE instead of their question (§1.3): the Posture question
 * names Covered. Status and Controls keep the question: a planned status is
 * data of yours, and their words are not rung words.
 */
export const OWNER_DATA_LENSES: ReadonlySet<string> = new Set(['posture', 'proven', 'covered']);

/** What an owner-data lens says in place of its question while no owner data exists. */
export const NO_OWNER_DATA_LINE = 'No data of yours recorded';

/** The line a lens is titled with: its question, or NO_OWNER_DATA_LINE on an owner-data lens with no owner words. */
export function lensQuestion(def: Pick<LensDefinition, 'value' | 'question'>, ownerWords: boolean): string {
  return ownerWords || !OWNER_DATA_LENSES.has(def.value) ? def.question : NO_OWNER_DATA_LINE;
}
