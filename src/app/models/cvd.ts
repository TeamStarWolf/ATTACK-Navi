// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Colour-vision-deficiency simulation (Phase 2 design §3 P2-13, R13): the
// Machado, Oliveira and Fernandes (2009) matrices at severity 1.0, applied in
// linear sRGB. Pure functions, no DOM: the posture ramp's CVD spec uses them to
// show that the ramp stays ordinal for protanopia, deuteranopia and
// tritanopia in both themes.
//
// Reference: G. M. Machado, M. M. Oliveira, L. A. F. Fernandes, "A
// Physiologically-based Model for Simulation of Color Vision Deficiency",
// IEEE TVCG 15(6), 2009, Table 1 (severity 1.0).

export type CvdKind = 'protanopia' | 'deuteranopia' | 'tritanopia';

export const CVD_KINDS: readonly CvdKind[] = ['protanopia', 'deuteranopia', 'tritanopia'];

type Row = readonly [number, number, number];
export type Matrix3 = readonly [Row, Row, Row];

/** Machado 2009, severity 1.0, rows applied to linear [r, g, b]. */
export const MACHADO_2009: Readonly<Record<CvdKind, Matrix3>> = {
  protanopia: [
    [0.152286, 1.052583, -0.204868],
    [0.114503, 0.786281, 0.099216],
    [-0.003882, -0.048116, 1.051998],
  ],
  deuteranopia: [
    [0.367322, 0.860646, -0.227968],
    [0.280085, 0.672501, 0.047413],
    [-0.01182, 0.04294, 0.968881],
  ],
  tritanopia: [
    [1.255528, -0.076749, -0.178779],
    [-0.078411, 0.930809, 0.147602],
    [0.004733, 0.691367, 0.3039],
  ],
};

export type Rgb = readonly [number, number, number];

/** '#rrggbb' (or '#rgb') to 0-255 channels. */
export function hexToRgb(hex: string): Rgb {
  const h = hex.replace('#', '');
  const full = h.length === 3 ? h.split('').map(c => c + c).join('') : h;
  if (!/^[0-9a-fA-F]{6}$/.test(full)) throw new Error(`not a hex colour: ${hex}`);
  return [parseInt(full.slice(0, 2), 16), parseInt(full.slice(2, 4), 16), parseInt(full.slice(4, 6), 16)];
}

/** 0-255 channels to lowercase '#rrggbb' (rounded, clamped). */
export function rgbToHex(rgb: Rgb): string {
  return '#' + rgb.map(v => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, '0')).join('');
}

/** sRGB channel (0-255) to linear light (0-1). */
export function toLinear(v: number): number {
  const s = v / 255;
  return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
}

/** Linear light (0-1, clamped) to an sRGB channel (0-255, unrounded). */
export function fromLinear(v: number): number {
  const c = Math.max(0, Math.min(1, v));
  const s = c <= 0.0031308 ? c * 12.92 : 1.055 * Math.pow(c, 1 / 2.4) - 0.055;
  return s * 255;
}

/** The colour as a viewer with `kind` sees it, as '#rrggbb'. */
export function simulateCvd(hex: string, kind: CvdKind): string {
  const lin = hexToRgb(hex).map(toLinear);
  const m = MACHADO_2009[kind];
  const out = m.map(row => fromLinear(row[0] * lin[0] + row[1] * lin[1] + row[2] * lin[2])) as unknown as Rgb;
  return rgbToHex(out);
}

/** WCAG 2.x relative luminance of a hex colour. */
export function relativeLuminance(hex: string): number {
  const [r, g, b] = hexToRgb(hex).map(toLinear);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** WCAG 2.x contrast ratio of two hex colours (1 to 21). */
export function hexContrast(a: string, b: string): number {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/** Mix `hex` toward `toward` by `t` (0 = hex, 1 = toward), in sRGB, rounded. */
export function mixHex(hex: string, toward: string, t: number): string {
  const a = hexToRgb(hex);
  const b = hexToRgb(toward);
  return rgbToHex([0, 1, 2].map(i => a[i] + (b[i] - a[i]) * t) as unknown as Rgb);
}
