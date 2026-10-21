// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The LensRegistry seam (Phase 2 design §2.5, §3 P2-13). A registry-hosted
// lens carries its own `project` and `color` on its HEATMAP_MODES entry, so
// the technique cell, the minimap (MatrixComponent.getCellColor) and the
// legend all call ONE colour function for it instead of holding three hex
// copies. A lens without them is a legacy lens: the matrix switchboard scores
// it and each surface keeps its own branch, byte for byte as before (the
// frozen-hash guard in lens-snapshots.spec.ts proves the 33 legacy lenses
// unchanged).
import type { Technique } from './technique';
import type { LensCell, LensContext, LensDefinition } from './heatmap-modes';

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
