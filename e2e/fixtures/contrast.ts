// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// A strict text-contrast scan for the e2e contrast spec (plan E1.5: "text
// >= 4.5:1 in both themes on 10 routes").
//
// axe's color-contrast rule applies 3:1 to large text and skips any node whose
// background it cannot resolve, so it is run next to this scan, not instead of
// it. The scan visits every rendered element that has its own text and
// compares its colour (with opacity) to the background colours it is drawn on,
// composited up the ancestor chain to the first opaque one. It skips what WCAG
// exempts or what has no meaningful text colour: disabled and aria-hidden
// content, visually hidden text, nodes over a background image (gradients),
// and text made only of emoji, which renders in its own colours.
import type { Page } from '@playwright/test';

export interface LowContrastNode {
  /** Short CSS path of the element (tag.class, up to four levels). */
  path: string;
  text: string;
  color: string;
  background: string;
  ratio: number;
}

export interface ScanOptions {
  /** Minimum ratio; the plan sets 4.5:1 for all text. */
  min?: number;
  /** Selector of the subtree(s) to scan; the whole body when omitted. */
  root?: string;
}

/** Text nodes under the minimum contrast, as rendered in the page right now. */
export async function lowContrastText(page: Page, options: ScanOptions = {}): Promise<LowContrastNode[]> {
  return page.evaluate(({ min, root }) => {
    type Rgba = number[];
    const parse = (c: string): Rgba | null => {
      const m = c.match(/rgba?\(([^)]+)\)/);
      if (!m) return null;
      const p = m[1].split(/[\s,/]+/).filter(Boolean);
      const a = p[3] === undefined ? 1 : p[3].endsWith('%') ? parseFloat(p[3]) / 100 : Number(p[3]);
      return [Number(p[0]), Number(p[1]), Number(p[2]), a];
    };
    const over = (t: Rgba, b: Rgba): Rgba => {
      const a = t[3] + b[3] * (1 - t[3]);
      if (a === 0) return [0, 0, 0, 0];
      return [0, 1, 2].map(i => (t[i] * t[3] + b[i] * b[3] * (1 - t[3])) / a).concat([a]);
    };
    const lum = (c: Rgba) => {
      const f = (v: number) => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]);
    };
    const ratio = (a: Rgba, b: Rgba) => {
      const x = lum(a);
      const y = lum(b);
      return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
    };
    const path = (e: Element) => {
      const parts: string[] = [];
      for (let n: Element | null = e, k = 0; n && n !== document.body && k < 4; n = n.parentElement, k++) {
        const cls = (typeof n.className === 'string' ? n.className : '')
          .trim()
          .split(/\s+/)
          .filter(c => c && !c.startsWith('ng-'))
          .slice(0, 2)
          .join('.');
        parts.unshift(n.tagName.toLowerCase() + (cls ? '.' + cls : ''));
      }
      return parts.join(' > ');
    };
    const emojiOnly = /^[\p{Extended_Pictographic}\p{Emoji_Modifier}‍️⃣\s]+$/u;

    const roots = root ? Array.from(document.querySelectorAll(root)) : [document.body];
    const elements = new Set<Element>();
    for (const r of roots) {
      elements.add(r);
      r.querySelectorAll('*').forEach(e => elements.add(e));
    }

    const out: Array<{ path: string; text: string; color: string; background: string; ratio: number }> = [];
    for (const el of elements) {
      if (['SCRIPT', 'STYLE', 'TITLE', 'OPTION', 'NOSCRIPT'].includes(el.tagName)) continue;
      const own = Array.from(el.childNodes)
        .filter(n => n.nodeType === Node.TEXT_NODE && n.textContent!.trim())
        .map(n => n.textContent!.trim())
        .join(' ');
      if (!own || emojiOnly.test(own)) continue;
      const box = el.getBoundingClientRect();
      if (box.width < 1 || box.height < 1) continue;
      const cs = getComputedStyle(el);
      if (cs.visibility !== 'visible') continue;
      if ((el as HTMLButtonElement).disabled || el.closest('[disabled], [aria-disabled="true"], [aria-hidden="true"], .sr-only, .visually-hidden')) continue;
      if (cs.clip === 'rect(0px, 0px, 0px, 0px)' || cs.clipPath === 'inset(50%)') continue;

      let opacity = 1;
      let imageBehind = false;
      const layers: Rgba[] = [];
      for (let n: Element | null = el; n; n = n.parentElement) {
        const s = getComputedStyle(n);
        opacity *= Number(s.opacity);
        if (s.backgroundImage && s.backgroundImage !== 'none') {
          imageBehind = true;
          break;
        }
        const bg = parse(s.backgroundColor);
        if (bg && bg[3] > 0) {
          layers.push(bg);
          if (bg[3] >= 1) break;
        }
      }
      if (imageBehind || opacity < 0.1) continue;
      const background = layers.reduceRight<Rgba>((below, layer) => over(layer, below), [255, 255, 255, 1]);
      const fg = parse(cs.color);
      if (!fg) continue;
      const r = ratio(over([fg[0], fg[1], fg[2], fg[3] * opacity], background), background);
      if (r < min) {
        out.push({
          path: path(el),
          text: own.slice(0, 40),
          color: cs.color,
          background: `rgb(${background.slice(0, 3).map(Math.round).join(' ')})`,
          ratio: Math.round(r * 100) / 100,
        });
      }
    }
    return out;
  }, { min: options.min ?? 4.5, root: options.root ?? null });
}

/** Wait for finite CSS animations (fade-ins, slide-ups) to finish, so colours are final. */
export async function settleAnimations(page: Page): Promise<void> {
  await page.evaluate(() =>
    Promise.all(
      document
        .getAnimations()
        .filter(a => a.effect?.getComputedTiming().iterations !== Infinity)
        .map(a => a.finished.catch(() => undefined)),
    ),
  );
}
