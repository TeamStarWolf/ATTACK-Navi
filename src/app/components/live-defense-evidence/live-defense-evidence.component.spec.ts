// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { LiveDefenseEvidenceComponent } from './live-defense-evidence.component';
import { LiveDefenseService, type LiveDefenseEvidence } from '../../services/live-defense.service';
import { FilterService, type HeatmapMode } from '../../services/filter.service';
import type { Technique } from '../../models/technique';

const EV: LiveDefenseEvidence = {
  techniqueID: 'T1190', name: 'Exploit Public-Facing Application', rank: 1, score: 100, heat: 168.5,
  confidence: 'high', itemCount: 1215, ransomwareCount: 249,
  breakdown: { halfLifeDays: 180, ransomwareBonus: 0.5, asOf: '2026-10-16', itemsShown: 1 },
  brief: 'Sourced KEV brief for the panel.',
  items: [{
    cve: 'CVE-2026-59310', source: 'CISA KEV', url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-59310',
    dateAdded: '2026-08-18', knownRansomware: true, confidence: 'high', quote: 'VMware vCenter Path Traversal',
    cwes: ['CWE-22'], via: 'CWE-22', weight: 1.2,
  }],
};

const tech = (attackId: string): Technique => ({ attackId } as Technique);

describe('LiveDefenseEvidenceComponent', () => {
  let fixture: ComponentFixture<LiveDefenseEvidenceComponent>;
  const evidence = new Map<string, LiveDefenseEvidence>([['T1190', EV]]);
  let mode$: BehaviorSubject<HeatmapMode>;

  beforeEach(() => {
    mode$ = new BehaviorSubject<HeatmapMode>('live-defense');
    TestBed.configureTestingModule({
      imports: [LiveDefenseEvidenceComponent],
      providers: [
        {
          provide: LiveDefenseService,
          useValue: {
            loaded$: new BehaviorSubject(true),
            getEvidence: (id: string) => evidence.get(id) ?? null,
          },
        },
        { provide: FilterService, useValue: { heatmapMode$: mode$ } },
      ],
    });
    fixture = TestBed.createComponent(LiveDefenseEvidenceComponent);
  });

  it('renders nothing when no technique is selected (fail quiet)', () => {
    fixture.componentRef.setInput('technique', null);
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.ld')).toBeNull();
  });

  it('renders nothing for a technique the lens does not heat (fail quiet)', () => {
    fixture.componentRef.setInput('technique', tech('T1570'));
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.ld')).toBeNull();
  });

  it('renders the heat, brief, updated stamp and a sourced CVE for a heated technique', () => {
    fixture.componentRef.setInput('technique', tech('T1190'));
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('.ld-score')?.textContent).toContain('100');
    expect(el.querySelector('.ld-brief')?.textContent).toContain('Sourced KEV brief');
    expect(el.textContent).toContain('2026-10-16'); // updated stamp
    const cve = el.querySelector('.ld-cve') as HTMLAnchorElement;
    expect(cve.textContent).toContain('CVE-2026-59310');
    expect(cve.href).toContain('nvd.nist.gov/vuln/detail/CVE-2026-59310');
    expect(cve.getAttribute('aria-label')).toContain('opens in a new tab');
    expect(el.querySelector('.ld-ransom')).not.toBeNull();
  });

  it('renders nothing when the active lens is not Live Defense (does not change other drawers)', () => {
    mode$.next('kev');
    fixture.componentRef.setInput('technique', tech('T1190'));
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.ld')).toBeNull();
  });
});
