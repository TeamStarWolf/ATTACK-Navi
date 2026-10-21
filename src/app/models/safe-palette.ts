// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

/**
 * Colorblind-safe heatmap palettes, applied app-wide when the
 * "Colorblind-safe heatmaps" setting is enabled.
 *
 * Sequential ramps use viridis (Stéfan van der Walt & Nathaniel Smith,
 * matplotlib): luminance rises monotonically, so magnitude stays readable
 * under deuteranopia/protanopia/tritanopia and in grayscale.
 * The status, controls, covered, proven and posture lenses are CVD-safe by
 * design (models/posture/lens-ramps.ts, posture-ramp.ts) and have no entry here.
 */

/** Sequential low→high ramp for all relative (count/ratio) heatmap modes. */
export const SAFE_SEQ: [string, string, string, string] =
  ['#3b528b', '#21918c', '#5ec962', '#fde725'];

/** 5-stop coverage scale (0 mitigations → 4+), viridis dark→bright. */
export const SAFE_COVERAGE: string[] =
  ['#440154', '#3b528b', '#21918c', '#5ec962', '#fde725'];

