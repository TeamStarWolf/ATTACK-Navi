// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf - MIT License
import { AttackDomain } from '../services/data.service';

/**
 * ATTACK-Navi's own internal layer model — the format a user's uploaded MITRE
 * ATT&CK Navigator layer is converted INTO and saved as.
 *
 * It is a faithful superset of the official Navigator layer format: every rich
 * per-technique field (score, color, comment, enabled, metadata[], links[]) and
 * every layer-level field (gradient, legendItems, metadata[], links, filters,
 * domain) is preserved so nothing the analyst put in the source layer is lost on
 * round-trip. The one deliberate simplification is that Navigator's cosmetic
 * `{ divider: true }` metadata/link separators are dropped — only real
 * name/value and label/url entries are kept.
 */

/** A Navigator metadata entry — a {name, value} pair shown in the tooltip. */
export interface UserLayerMetadataEntry {
  name: string;
  value: string;
}

/** A Navigator link entry — a {label, url} pair. */
export interface UserLayerLink {
  label: string;
  url: string;
}

/** One converted technique row, preserving all of Navigator's per-technique data. */
export interface UserLayerTechnique {
  techniqueID: string;
  /** Tactic shortname the row is scoped to (blank = applies to every tactic). */
  tactic: string;
  /** Numeric score, or null when the source left it unscored. */
  score: number | null;
  /** Explicit cell color the analyst set, or '' when none (score/gradient wins). */
  color: string;
  comment: string;
  enabled: boolean;
  metadata: UserLayerMetadataEntry[];
  links: UserLayerLink[];
  showSubtechniques: boolean;
}

/** The score→color gradient (Navigator interpolates cell fills across it). */
export interface UserLayerGradient {
  colors: string[];
  minValue: number;
  maxValue: number;
}

/** A manual legend swatch carried by the layer. */
export interface UserLayerLegendItem {
  label: string;
  color: string;
}

/**
 * A fully converted, persistable ATTACK-Navi layer. `id`/`importedAt`/
 * `sourceFormat` are ATTACK-Navi bookkeeping; everything else mirrors the
 * source Navigator layer.
 */
export interface AttackNaviLayer {
  /** Stable local id (persistence key). */
  id: string;
  name: string;
  description: string;
  /** Normalized internal domain the layer targets. */
  domain: AttackDomain;
  /** The original Navigator `domain` string (e.g. 'enterprise-attack'). */
  navigatorDomain: string;
  attackVersion: string;
  navigatorVersion: string;
  layerVersion: string;
  filters: { platforms: string[] };
  gradient: UserLayerGradient;
  legendItems: UserLayerLegendItem[];
  /** Layer-level metadata (name/value pairs). */
  metadata: UserLayerMetadataEntry[];
  /** Layer-level links. */
  links: UserLayerLink[];
  techniques: UserLayerTechnique[];
  /** ISO timestamp of when this layer was imported into ATTACK-Navi. */
  importedAt: string;
  /** Detected source format, e.g. 'navigator-4.5' or 'navigator-3.x'. */
  sourceFormat: string;
}

/** Lightweight metadata for the saved-layers list UI (no technique payload). */
export interface AttackNaviLayerMeta {
  id: string;
  name: string;
  description: string;
  domain: AttackDomain;
  techniqueCount: number;
  importedAt: string;
  sourceFormat: string;
}

/** Outcome of converting a raw Navigator layer, with any non-fatal warnings. */
export interface LayerConversionResult {
  layer: AttackNaviLayer;
  warnings: string[];
}

export function toLayerMeta(layer: AttackNaviLayer): AttackNaviLayerMeta {
  return {
    id: layer.id,
    name: layer.name,
    description: layer.description,
    domain: layer.domain,
    techniqueCount: layer.techniques.length,
    importedAt: layer.importedAt,
    sourceFormat: layer.sourceFormat,
  };
}
