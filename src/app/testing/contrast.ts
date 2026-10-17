// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// WCAG 2.x contrast helpers for specs (plan E1.5 and section 6.7, "token
// contrast unit test"). They read colours the browser has already computed,
// so a spec measures what the theme really renders, not what a stylesheet says.

export type Rgba = [r: number, g: number, b: number, a: number];

/** Parses a computed colour: 'rgb(1, 2, 3)', 'rgba(1, 2, 3, 0.5)' or 'rgb(1 2 3 / 50%)'. */
export function parseColor(css: string): Rgba {
  const m = css.match(/rgba?\(([^)]+)\)/);
  if (!m) throw new Error(`not an rgb() colour: ${css}`);
  const parts = m[1].split(/[\s,/]+/).filter(Boolean);
  const alpha = parts[3] === undefined ? 1 : parts[3].endsWith('%') ? parseFloat(parts[3]) / 100 : Number(parts[3]);
  return [Number(parts[0]), Number(parts[1]), Number(parts[2]), alpha];
}

/** Source-over compositing of `top` on `bottom`. */
export function over(top: Rgba, bottom: Rgba): Rgba {
  const a = top[3] + bottom[3] * (1 - top[3]);
  if (a === 0) return [0, 0, 0, 0];
  const ch = (i: number) => (top[i] * top[3] + bottom[i] * bottom[3] * (1 - top[3])) / a;
  return [ch(0), ch(1), ch(2), a];
}

function luminance([r, g, b]: Rgba): number {
  const lin = (v: number) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

/** WCAG contrast ratio of two opaque colours (1 to 21). */
export function contrastRatio(a: Rgba, b: Rgba): number {
  const la = luminance(a);
  const lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/**
 * The colour an element's text is drawn on: its own and its ancestors'
 * background colours composited down to the first opaque one (white below
 * that). Background images are not considered.
 */
export function effectiveBackground(el: Element): Rgba {
  const layers: Rgba[] = [];
  for (let n: Element | null = el; n; n = n.parentElement) {
    const bg = parseColor(getComputedStyle(n).backgroundColor);
    if (bg[3] > 0) layers.push(bg);
    if (bg[3] >= 1) break;
  }
  return layers.reduceRight<Rgba>((below, layer) => over(layer, below), [255, 255, 255, 1]);
}

/** Contrast of an element's own text against what it is drawn on. */
export function textContrast(el: Element): number {
  const bg = effectiveBackground(el);
  return contrastRatio(over(parseColor(getComputedStyle(el).color), bg), bg);
}
