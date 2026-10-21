// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { GapViewComponent } from './gap-view.component';
import { DataService } from '../../services/data.service';
import { FilterService } from '../../services/filter.service';
import type { Domain } from '../../models/domain';

/**
 * The words the fresh-profile e2e scan bans (e2e/fixtures/workspace/sample-org.json
 * honesty.forbiddenStrings), plus the Proven words the truth lint owns.
 */
const BANNED = ['covered', 'defended', 'low risk', 'protected', 'coverage score', 'proven', 'validated'];

describe('GapViewComponent', () => {
  let component: GapViewComponent;
  let fixture: ComponentFixture<GapViewComponent>;
  let domain$: BehaviorSubject<Domain | null>;

  beforeEach(() => {
    domain$ = new BehaviorSubject<Domain | null>(null);
    TestBed.configureTestingModule({
      imports: [GapViewComponent],
      providers: [
        { provide: DataService, useValue: { domain$ }},
        { provide: FilterService, useValue: {
            activeMitigationFilters$: new BehaviorSubject([]),
            heatmapMode$: new BehaviorSubject('coverage'),
            setActivePanel: jasmine.createSpy(),
            selectTechnique: jasmine.createSpy(),
        }},
      ],
    });
    fixture = TestBed.createComponent(GapViewComponent);
    component = fixture.componentInstance;
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  // P2-17 (R17, §10.4 item 16): the legacy Gap view is relabelled; its rule
  // (no mapped ATT&CK mitigation) and its .gap-overlay class are unchanged.
  describe('relabelled Unmapped techniques (P2-17)', () => {
    const tech = (id: string, attackId: string, mitigationCount: number) => ({
      id, attackId, name: `Name ${attackId}`, isSubtechnique: false, mitigationCount,
      tacticShortnames: ['execution'], platforms: ['Windows'],
    });
    const domainWith = (techniques: ReturnType<typeof tech>[]): Domain => ({
      tacticColumns: [{ tactic: { name: 'Execution' }, techniques }],
      groupsByTechnique: new Map(),
    }) as unknown as Domain;

    /** Every string a reader sees or hears in the panel. */
    const visibleStrings = (): string[] => {
      const root = fixture.nativeElement as HTMLElement;
      const out = [root.textContent ?? ''];
      for (const node of Array.from(root.querySelectorAll('*'))) {
        for (const attr of ['title', 'aria-label', 'placeholder', 'alt']) {
          const v = node.getAttribute(attr);
          if (v) out.push(v);
        }
      }
      return out;
    };
    const bannedHits = (): string[] => visibleStrings().filter(v =>
      BANNED.some(w => new RegExp(`\\b${w}\\b`, 'i').test(v)) || /(?<![\w-])grades?\b/i.test(v));

    it("titles the panel 'Unmapped techniques' and keeps the rule and the .gap-overlay class", () => {
      domain$.next(domainWith([tech('a', 'T1001', 0), tech('b', 'T1002', 3)]));
      fixture.detectChanges();
      component.show();
      fixture.detectChanges();
      const root = fixture.nativeElement as HTMLElement;
      expect(root.querySelector('.gap-overlay')).not.toBeNull();
      expect(root.querySelector('.gap-title')!.textContent!.trim()).toBe('Unmapped techniques');
      expect(root.textContent).not.toContain('Mitigation Gaps');
      expect(root.querySelector('.gap-subtitle')!.textContent!.trim()).toBe('1 technique with no mapped mitigations');
      expect([...root.querySelectorAll('.gap-id')].map(e => e.textContent!.trim())).toEqual(['T1001']);
    });

    it('contains no banned word, with techniques listed or with none', () => {
      domain$.next(domainWith([tech('a', 'T1001', 0)]));
      fixture.detectChanges();
      component.show();
      fixture.detectChanges();
      expect(bannedHits()).toEqual([]);
      domain$.next(domainWith([tech('b', 'T1002', 2)]));
      fixture.detectChanges();
      const empty = (fixture.nativeElement as HTMLElement).querySelector('.gap-empty')!;
      expect(empty.textContent!.trim()).toBe('Every technique has at least one ATT&CK mitigation mapped.');
      expect(bannedHits()).toEqual([]);
    });
  });
});
