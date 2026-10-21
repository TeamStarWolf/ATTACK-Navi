// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// [AC] CVD snapshot test (Phase 2 design §3 P2-13, R13). For protanopia,
// deuteranopia and tritanopia (Machado 2009, severity 1.0, cvd.ts), in each
// theme separately:
//   - the simulated contrast FROM THE THEME'S SURFACE is strictly increasing
//     none < known < covered < proven, where none is the surface itself (1:1);
//   - neighbouring stops differ by at least 1.3:1;
//   - the simulated hexes match src/app/testing/__snapshots__/posture-ramp-cvd.json;
// and partial, contradicted and not-reproducible are told apart by pattern
// (distinct CSS classes that draw distinct styles), never by hue alone.
//
// When the ramp changes on purpose, the failing expectation prints the new
// simulated hexes; review them against the two ordinal rules before updating
// the json by hand.
import { TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';

import CVD_SNAPSHOT from '../../testing/__snapshots__/posture-ramp-cvd.json';
import { CVD_KINDS, MACHADO_2009, hexContrast, simulateCvd } from '../cvd';
import type { Technique } from '../technique';
import { TechniqueCellComponent } from '../../components/technique-cell/technique-cell.component';
import { SettingsService } from '../../services/settings.service';
import {
  POSTURE_BUCKETS, POSTURE_ORDINAL_STOPS, POSTURE_PATTERN_CLASS, POSTURE_SURFACE, type PostureCellVM, type PostureTheme,
  postureFill, posturePatterns,
} from './posture-ramp';

type CvdSnapshot = Record<PostureTheme, Record<string, Record<string, string>>>;
const COMMITTED = CVD_SNAPSHOT as unknown as CvdSnapshot;
const THEMES: readonly PostureTheme[] = ['dark', 'light'];
const MIN_STEP = 1.3;

/** The simulated surface and every bucket fill for one theme and deficiency. */
function simulated(theme: PostureTheme, kind: (typeof CVD_KINDS)[number]): Record<string, string> {
  const out: Record<string, string> = { surface: simulateCvd(POSTURE_SURFACE[theme], kind) };
  for (const b of POSTURE_BUCKETS) out[b] = simulateCvd(postureFill(b, theme), kind);
  return out;
}

describe('cvd.ts: Machado 2009 simulation (pure)', () => {
  it('has the three severity-1.0 matrices, rows summing to 1 (white and greys stay neutral)', () => {
    expect(Object.keys(MACHADO_2009).sort()).toEqual(['deuteranopia', 'protanopia', 'tritanopia']);
    for (const kind of CVD_KINDS) {
      for (const row of MACHADO_2009[kind]) {
        expect(row[0] + row[1] + row[2]).withContext(kind).toBeCloseTo(1, 2);
      }
    }
    expect(MACHADO_2009.protanopia[0]).toEqual([0.152286, 1.052583, -0.204868]);
    expect(MACHADO_2009.deuteranopia[0]).toEqual([0.367322, 0.860646, -0.227968]);
    expect(MACHADO_2009.tritanopia[0]).toEqual([1.255528, -0.076749, -0.178779]);
  });

  it('keeps greys neutral and maps the primaries as the paper does (red and green collapse to yellows)', () => {
    for (const kind of CVD_KINDS) {
      for (const grey of ['#000000', '#808080', '#ffffff']) expect(simulateCvd(grey, kind)).withContext(kind).toBe(grey);
    }
    expect(simulateCvd('#ff0000', 'protanopia')).toBe('#6d5f00');
    expect(simulateCvd('#00ff00', 'protanopia')).toBe('#ffe500');
    expect(simulateCvd('#ff0000', 'deuteranopia')).toBe('#a39000');
    expect(simulateCvd('#00ff00', 'deuteranopia')).toBe('#efd63a');
    expect(simulateCvd('#0000ff', 'tritanopia')).toBe('#006b96');
    expect(simulateCvd('#00ff00', 'tritanopia')).toBe('#00f7d9');
  });
});

describe('[AC] posture ramp under colour-vision deficiency (P2-13, R13)', () => {
  for (const theme of THEMES) {
    for (const kind of CVD_KINDS) {
      describe(`${theme} theme, ${kind}`, () => {
        const sim = simulated(theme, kind);

        it('none is the surface (contrast 1:1)', () => {
          expect(postureFill('none', theme)).toBe(POSTURE_SURFACE[theme]);
          expect(hexContrast(sim['none'], sim['surface'])).toBe(1);
        });

        it('contrast from the surface rises strictly: none < known < covered < proven', () => {
          const c = POSTURE_ORDINAL_STOPS.map(b => hexContrast(sim[b], sim['surface']));
          for (let i = 1; i < c.length; i++) {
            expect(c[i]).withContext(`${POSTURE_ORDINAL_STOPS[i]} vs ${POSTURE_ORDINAL_STOPS[i - 1]}: ${c.map(x => x.toFixed(2)).join(' < ')}`)
              .toBeGreaterThan(c[i - 1]);
          }
        });

        it(`neighbouring stops differ by at least ${MIN_STEP}:1`, () => {
          for (let i = 1; i < POSTURE_ORDINAL_STOPS.length; i++) {
            const a = POSTURE_ORDINAL_STOPS[i - 1];
            const b = POSTURE_ORDINAL_STOPS[i];
            expect(hexContrast(sim[a], sim[b])).withContext(`${a} -> ${b}`).toBeGreaterThanOrEqual(MIN_STEP);
          }
        });

        it('matches the committed simulated hexes (posture-ramp-cvd.json)', () => {
          expect(sim).withContext(JSON.stringify(sim)).toEqual(COMMITTED[theme][kind]);
        });
      });
    }
  }

  it('the snapshot covers both themes and all three deficiencies, every bucket', () => {
    expect(Object.keys(COMMITTED).sort()).toEqual(['dark', 'light']);
    for (const theme of THEMES) {
      expect(Object.keys(COMMITTED[theme]).sort()).toEqual([...CVD_KINDS].sort());
      for (const kind of CVD_KINDS) {
        expect(Object.keys(COMMITTED[theme][kind]).sort()).toEqual(['surface', ...POSTURE_BUCKETS].sort());
      }
    }
  });
});

describe('[AC] partial, contradicted and not reproducible are told apart by pattern (P2-13)', () => {
  const vm = (bucket: PostureCellVM['bucket'], subStates: PostureCellVM['subStates']): PostureCellVM =>
    ({ bucket, subStates, proofScope: null, label: 'x' });

  it('each maps to its own CSS class', () => {
    const classes = Object.values(POSTURE_PATTERN_CLASS);
    expect(new Set(classes).size).toBe(3);
    expect(posturePatterns(vm('partial', ['partial']))).toEqual(['partial']);
    expect(posturePatterns(vm('known', ['contradicted']))).toEqual(['contradicted']);
    expect(posturePatterns(vm('known', ['not-reproducible']))).toEqual(['not-reproducible']);
    expect(posturePatterns(vm('covered', []))).toEqual([]);
  });

  it('partial shares the Known fill, so only its pattern sets it apart', () => {
    for (const theme of THEMES) expect(postureFill('partial', theme)).toBe(postureFill('known', theme));
  });

  it('the rendered cell draws a different style for each class', () => {
    const settings$ = new BehaviorSubject<unknown>({ colorblindSafe: false, cellDisplay: null });
    TestBed.configureTestingModule({
      imports: [TechniqueCellComponent],
      providers: [{ provide: SettingsService, useValue: { settings$, get current() { return settings$.value; }, getCoverageColors: () => ['#000000'] } }],
    });
    const tech = { id: 'attack-pattern--x', attackId: 'T1', name: 'X', isSubtechnique: false, mitigationCount: 1, platforms: [], tacticShortnames: [] } as unknown as Technique;
    const render = (cell: PostureCellVM) => {
      const f = TestBed.createComponent(TechniqueCellComponent);
      f.componentRef.setInput('technique', tech);
      f.componentRef.setInput('heatmapMode', 'posture');
      f.componentRef.setInput('posture', cell);
      f.detectChanges();
      document.body.appendChild(f.nativeElement);
      const el = (f.nativeElement as HTMLElement).querySelector('.cell') as HTMLElement;
      const style = {
        classes: [...el.classList].filter(c => c.startsWith('posture-')),
        before: getComputedStyle(el, '::before').borderTopStyle,
        afterImage: getComputedStyle(el, '::after').borderImageSource,
        background: getComputedStyle(el).backgroundImage,
      };
      f.nativeElement.remove();
      return style;
    };
    const partial = render(vm('partial', ['partial']));
    const contradicted = render(vm('known', ['contradicted']));
    const notReproducible = render(vm('known', ['not-reproducible']));
    expect(partial.classes).toEqual([POSTURE_PATTERN_CLASS.partial]);
    expect(contradicted.classes).toEqual([POSTURE_PATTERN_CLASS.contradicted]);
    expect(notReproducible.classes).toEqual([POSTURE_PATTERN_CLASS['not-reproducible']]);
    // partial: a dashed outline; contradicted: a hatched (gradient) frame; not reproducible: a cross-hatch fill.
    expect(partial.before).toBe('dashed');
    expect(contradicted.afterImage).toContain('repeating-linear-gradient');
    expect(notReproducible.background).toContain('repeating-linear-gradient');
    expect(partial.background).toBe('none');
    expect(contradicted.before).not.toBe('dashed');
    expect(notReproducible.afterImage).toBe('none');
  });
});
