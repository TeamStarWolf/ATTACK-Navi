// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

/**
 * Colorblind-safe heatmap palettes, applied app-wide when the
 * "Colorblind-safe heatmaps" setting is enabled.
 *
 * Sequential ramps use viridis (Stéfan van der Walt & Nathaniel Smith,
 * matplotlib): luminance rises monotonically, so magnitude stays readable
 * under deuteranopia/protanopia/tritanopia and in grayscale.
 * Categorical states use Okabe & Ito's palette (Color Universal Design,
 * 2008) — the standard CVD-safe categorical set.
 */

/** Sequential low→high ramp for all relative (count/ratio) heatmap modes. */
export const SAFE_SEQ: [string, string, string, string] =
  ['#3b528b', '#21918c', '#5ec962', '#fde725'];

/** 5-stop coverage scale (0 mitigations → 4+), viridis dark→bright. */
export const SAFE_COVERAGE: string[] =
  ['#440154', '#3b528b', '#21918c', '#5ec962', '#fde725'];

/** Implementation status → Okabe-Ito categorical colors. */
export const SAFE_STATUS: Record<string, string> = {
  'implemented': '#009e73',  // bluish green
  'in-progress': '#e69f00',  // orange
  'planned': '#56b4e9',      // sky blue
  'not-started': '#d55e00',  // vermillion
  'none': '#6b7280',         // neutral gray
};

/** Security-control state → Okabe-Ito categorical colors. */
export const SAFE_CONTROLS: Record<string, string> = {
  'covered': '#009e73',
  'planned': '#56b4e9',
  'none': '#1c2b30',
};
