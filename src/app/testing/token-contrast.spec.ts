// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Token contrast (plan E1.5 and section 6.7): every text-colour token reads at
// 4.5:1 or better on every surface token, in both themes. The global
// stylesheet (src/styles.scss with its tokens) is loaded in the Karma run, so
// the colours here are the ones the browser computes for :root (dark) and
// body.light-mode (light). The four light-mode leaks E1.5 fixed (onboarding
// titles, palette match highlight, KEV numbers, score chips) now draw from
// these tokens, so this spec is the floor they stand on; the e2e contrast spec
// measures the rendered leaks themselves.
import tinycolor from 'tinycolor2';
import { Rgba, contrastRatio, over, parseColor, textContrast } from './contrast';
import { hexToRgb } from '../models/cvd';
import { POSTURE_BUCKETS, POSTURE_TOKENS } from '../models/posture/posture-ramp';

const TEXT_TOKENS = [
  '--text-main',
  '--text-primary',
  '--text-secondary',
  '--text-muted',
  '--text-faint',
  '--accent',
  '--accent-blue',
  '--accent-green',
  '--accent-red',
  '--accent-orange',
  '--accent-purple',
  '--accent-warm',
  '--success',
  '--danger',
] as const;

const SURFACE_TOKENS = ['--bg-base', '--bg-app', '--bg-elevated', '--bg-surface', '--bg-panel', '--bg-panel-strong'] as const;

const MIN = 4.5;

describe('theme token contrast (plan E1.5)', () => {
  let host: HTMLDivElement;

  beforeEach(() => {
    host = document.createElement('div');
    document.body.appendChild(host);
  });

  afterEach(() => {
    host.remove();
    document.body.classList.remove('light-mode');
  });

  /** The computed colour of a token, resolved in the current theme. */
  function token(name: string, prop: 'color' | 'backgroundColor' = 'color'): Rgba {
    const probe = document.createElement('span');
    probe.style[prop] = `var(${name})`;
    host.appendChild(probe);
    const value = parseColor(getComputedStyle(probe)[prop]);
    probe.remove();
    return value;
  }

  /** A surface composited on the page base, as a panel is drawn on the app. */
  function surface(name: string): Rgba {
    const base = over(token('--bg-base', 'backgroundColor'), [255, 255, 255, 1]);
    return over(token(name, 'backgroundColor'), base);
  }

  for (const theme of ['dark', 'light'] as const) {
    it(`every text token is >= ${MIN}:1 on every surface token in the ${theme} theme`, () => {
      document.body.classList.toggle('light-mode', theme === 'light');
      const failures: string[] = [];
      for (const s of SURFACE_TOKENS) {
        const bg = surface(s);
        for (const t of TEXT_TOKENS) {
          const ratio = contrastRatio(over(token(t), bg), bg);
          if (ratio < MIN) failures.push(`${t} on ${s}: ${ratio.toFixed(2)}:1`);
        }
      }
      expect(failures).withContext(theme).toEqual([]);
    });
  }

  it('the light theme really re-points the tokens (the check above is not testing one theme twice)', () => {
    const dark = token('--text-main');
    document.body.classList.add('light-mode');
    const light = token('--text-main');
    expect(light).not.toEqual(dark);
  });

  it('measures a real element: theme text on a theme panel', () => {
    for (const light of [false, true]) {
      document.body.classList.toggle('light-mode', light);
      host.innerHTML = '<div style="background: var(--bg-panel-strong)"><span style="color: var(--text-faint)">x</span></div>';
      expect(textContrast(host.querySelector('span')!)).toBeGreaterThanOrEqual(MIN);
    }
  });
});

// P2-13: the Posture lens paints its cells from the posture ramp tokens, and
// the cell draws its id and name on them. Text on every stop reads at 4.5:1 or
// better in both themes, and the cell's own text rule (the better of black and
// white, technique-cell ngOnChanges) lands on the token's text colour.
describe('posture ramp text contrast (P2-13)', () => {
  const rgba = (hex: string): Rgba => [...hexToRgb(hex), 1] as Rgba;

  for (const theme of ['dark', 'light'] as const) {
    it(`text on every posture stop is >= ${MIN}:1 in the ${theme} theme`, () => {
      const failures: string[] = [];
      for (const b of POSTURE_BUCKETS) {
        const { fill, text } = POSTURE_TOKENS[theme][b];
        const ratio = contrastRatio(rgba(text), rgba(fill));
        if (ratio < MIN) failures.push(`${b} (${text} on ${fill}): ${ratio.toFixed(2)}:1`);
        expect(tinycolor.mostReadable(fill, ['#000000', '#ffffff']).toHexString()).withContext(`${theme} ${b}`).toBe(text);
      }
      expect(failures).withContext(theme).toEqual([]);
    });
  }
});
