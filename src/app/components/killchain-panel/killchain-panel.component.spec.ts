// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { KillchainPanelComponent } from './killchain-panel.component';
import { DataService } from '../../services/data.service';

/** The least a Domain needs for the panel's per-tactic arithmetic. */
function domain(name: string, tactics: { id: string; attackId: string; name: string; covered: number; uncovered: number }[]): any {
  const groupsByTechnique = new Map<string, { id: string }[]>();
  const tacticColumns = tactics.map(t => {
    const techniques: any[] = [];
    for (let i = 0; i < t.covered; i++) {
      techniques.push({ id: `${t.id}-c${i}`, name: `${t.name} covered ${i}`, isSubtechnique: false, mitigationCount: 2, subtechniques: [{}] });
    }
    for (let i = 0; i < t.uncovered; i++) {
      const id = `${t.id}-u${i}`;
      techniques.push({ id, name: `${t.name} uncovered ${i}`, isSubtechnique: false, mitigationCount: 0, subtechniques: [] });
      groupsByTechnique.set(id, [{ id: 'G0001' }]);
    }
    return { tactic: { id: t.id, attackId: t.attackId, name: t.name, shortname: t.id }, techniques };
  });
  return { name, tacticColumns, groupsByTechnique };
}

const ENTERPRISE = domain('Enterprise ATT&CK', [
  { id: 'recon', attackId: 'TA0043', name: 'Reconnaissance', covered: 1, uncovered: 3 },
  { id: 'exec', attackId: 'TA0002', name: 'Execution', covered: 3, uncovered: 1 },
  { id: 'stealth', attackId: 'TA0005', name: 'Stealth', covered: 2, uncovered: 2 },
]);
const ICS = domain('ICS ATT&CK', [
  { id: 'inhibit', attackId: 'TA0107', name: 'Inhibit Response Function', covered: 0, uncovered: 2 },
  { id: 'impair', attackId: 'TA0106', name: 'Impair Process Control', covered: 1, uncovered: 1 },
]);

describe('KillchainPanelComponent', () => {
  let component: KillchainPanelComponent;
  let fixture: ComponentFixture<KillchainPanelComponent>;
  let domain$: BehaviorSubject<any>;

  beforeEach(() => {
    domain$ = new BehaviorSubject<any>(null);
    TestBed.configureTestingModule({
      imports: [KillchainPanelComponent],
      providers: [
        {
          provide: DataService,
          useValue: {
            domain$,
            getGroupsForTechnique: (id: string) => domain$.value?.groupsByTechnique.get(id) ?? [],
          },
        },
      ],
    });
    fixture = TestBed.createComponent(KillchainPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  const subtitle = () => fixture.nativeElement.querySelector('.header-subtitle')?.textContent ?? '';
  const cardNames = () =>
    [...fixture.nativeElement.querySelectorAll('.card-tactic-name')].map((el: Element) => el.textContent?.trim());

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  it('selectedTacticId starts null', () => {
    expect(component.selectedTacticId).toBeNull();
  });

  it('shows the spinner until a domain is loaded', () => {
    expect(fixture.nativeElement.querySelector('.loading-state')).toBeTruthy();
    expect(component.tacticStats).toEqual([]);
  });

  it('computes one card per tactic of the loaded domain and names that domain', () => {
    domain$.next(ENTERPRISE);
    fixture.detectChanges();

    expect(cardNames()).toEqual(['Reconnaissance', 'Execution', 'Stealth']);
    expect(subtitle()).toContain('Enterprise ATT&CK tactics');
    const exec = component.tacticStats[1];
    expect(exec.totalTechs).toBe(4);
    expect(exec.coveredTechs).toBe(3);
    expect(exec.coveragePct).toBe(75);
    expect(exec.subtechniqueCount).toBe(3);
    expect(exec.threatGroupCount).toBe(1);
    expect(exec.topUncoveredTech).toBe('Execution uncovered 0');
    expect(component.overallCoverage).toBe(50); // 6 of 12
  });

  it('recomputes when the domain is switched, instead of keeping the first domain forever', () => {
    domain$.next(ENTERPRISE);
    fixture.detectChanges();
    component.selectTactic(component.tacticStats[0]);
    expect(component.selectedTacticId).toBe('recon');

    // DataService emits null while the next bundle loads...
    domain$.next(null);
    fixture.detectChanges();
    expect(component.tacticStats).toEqual([]);
    expect(fixture.nativeElement.querySelector('.loading-state')).toBeTruthy();

    // ...then the new domain. Enterprise-only tactics must be gone, the caption must
    // not say Enterprise, and a selection from the old domain must not linger.
    domain$.next(ICS);
    fixture.detectChanges();
    expect(cardNames()).toEqual(['Inhibit Response Function', 'Impair Process Control']);
    expect(cardNames()).not.toContain('Reconnaissance');
    expect(subtitle()).toContain('ICS ATT&CK tactics');
    expect(subtitle()).not.toContain('Enterprise');
    expect(component.selectedTacticId).toBeNull();
    expect(component.totalTechniques).toBe(4);
    expect(component.overallCoverage).toBe(25);
  });

  it('keeps a selection that still exists in the new domain', () => {
    domain$.next(ENTERPRISE);
    fixture.detectChanges();
    component.selectTactic(component.tacticStats[1]);
    domain$.next(null);
    domain$.next(domain('Enterprise ATT&CK', [
      { id: 'exec', attackId: 'TA0002', name: 'Execution', covered: 1, uncovered: 0 },
    ]));
    fixture.detectChanges();
    expect(component.selectedTacticId).toBe('exec');
  });

  it('stops listening once destroyed', () => {
    fixture.destroy();
    expect(domain$.observed).toBe(false);
  });
});
