// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// P2-10 [AC]: changing the shared threat profile updates every denominator in one
// step (design §3 P2-10, S8). setSource moves the wizard total, the gap-analysis
// total, the ctem posture-card "threat-relevant techniques: N" line and
// ThreatProfile.parentTechniqueIds.size to the SAME number; the all-groups
// dashboard/actor denominators (§10.4 item 15) do not move. The reactive-seam half
// (the card recomputes on setSource) is proven in posture.service.spec; here we
// pin the equality across surfaces.
import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { HttpClient, provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { Domain } from '../models/domain';
import { AttackDomain, DataService } from '../services/data.service';
import { ThreatProfileService } from '../services/threat-profile.service';
import { GapAnalysisService } from '../services/gap-analysis.service';
import { SigmaService } from '../services/sigma.service';
import { ElasticService } from '../services/elastic.service';
import { SplunkContentService } from '../services/splunk-content.service';
import { M365DefenderService } from '../services/m365-defender.service';
import { AtomicService } from '../services/atomic.service';
import { CARService } from '../services/car.service';
import { AttackCveService } from '../services/attack-cve.service';
import { ExploitdbService } from '../services/exploitdb.service';
import { PostureCardComponent } from '../components/posture-card/posture-card.component';
import { AssessmentWizardComponent } from '../components/assessment-wizard/assessment-wizard.component';
import { THREAT_WEIGHT_PROVIDER, allGroupsWeight } from '../models/posture/threat-weight';
import { POSTURE_TODAY } from '../models/posture/posture-today';
import { resolveProfile } from '../models/threat-profile';
import { parseFixtureDomain, resetBrowserState, signalStubProviders } from './lens-harness';

const TODAY = new Date('2026-10-01T00:00:00.000Z');

describe('threat-profile denominators move in one step (P2-10 [AC])', () => {
  let domain: Domain;
  let threatProfile: ThreatProfileService;
  let gap: GapAnalysisService;

  /** Load a domain the way DataService publishes one (matches posture.service.spec). */
  function load(d: Domain, id: AttackDomain): void {
    const ds = TestBed.inject(DataService) as unknown as {
      attackDomain: AttackDomain; currentDomain$: { next(v: AttackDomain): void }; domainSubject: { next(v: Domain | null): void };
    };
    ds.attackDomain = id;
    ds.currentDomain$.next(id);
    ds.domainSubject.next(d);
  }

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      imports: [PostureCardComponent, AssessmentWizardComponent],
      providers: [
        provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]),
        ...signalStubProviders(),
        { provide: POSTURE_TODAY, useValue: signal(TODAY) },
        // The seam P2-10 wires: the shared profile is the threat-weight source.
        { provide: THREAT_WEIGHT_PROVIDER, useExisting: ThreatProfileService },
        // Gap-analysis detection stubs (the lens-harness stubs answer different method
        // names). These make generateReport() run; its denominator is the profile, not
        // detection counts, so returning 0/[] does not affect totalTechniques.
        ...[SigmaService, ElasticService, SplunkContentService].map(t => ({ provide: t, useValue: { getRuleCount: () => 0 } })),
        { provide: M365DefenderService, useValue: { getQueriesForTechnique: () => [] } },
        { provide: AtomicService, useValue: { getTestCount: () => 0 } },
        { provide: CARService, useValue: { getAnalytics: () => [] } },
        { provide: AttackCveService, useValue: { getKevCvesForTechnique: () => [] } },
        { provide: ExploitdbService, useValue: { getExploitCount: () => 0 } },
      ],
    });
    load(domain, 'enterprise');
    threatProfile = TestBed.inject(ThreatProfileService);
    gap = TestBed.inject(GapAnalysisService);
  });

  afterEach(() => resetBrowserState());

  /** The rendered ctem posture-card "threat-relevant techniques: N" line. */
  function cardThreatRelevant(): number {
    const f = TestBed.createComponent(PostureCardComponent);
    f.componentRef.setInput('scope', 'threat-relevant');
    f.detectChanges();
    const el = (f.nativeElement as HTMLElement).querySelector('[data-posture="threat-relevant"]');
    return Number((el?.textContent ?? '').trim());
  }
  /** The wizard's step-3 denominator getter. */
  function wizardTotal(): number {
    return TestBed.createComponent(AssessmentWizardComponent).componentInstance.totalTechniques;
  }
  /** The gap-analysis report's total-techniques denominator. */
  function gapTotal(): number {
    return gap.generateReport(domain, threatProfile.current).summary.totalTechniques;
  }

  it('wizard, gap, ctem threat-relevant line and parentTechniqueIds.size agree and move together', () => {
    // Group profiles: every parent in parentTechniqueIds is used by a selected group,
    // so it carries a threat weight and the card counts exactly that set. (A 'all'
    // profile would add group-less parents that carry no weight, so group profiles are
    // the clean cross-surface comparison.)
    const withTechs = domain.groups.filter(g => (domain.techniquesByGroup.get(g.id) ?? []).length > 0);
    expect(withTechs.length).withContext('fixture has >= 2 groups with techniques').toBeGreaterThanOrEqual(2);
    const [a, b] = withTechs;

    threatProfile.setSource({ kind: 'groups', ids: [a.id, b.id] });
    const n = threatProfile.current.parentTechniqueIds.size;
    expect(n).toBeGreaterThan(0);
    expect([wizardTotal(), gapTotal(), cardThreatRelevant()]).toEqual([n, n, n]);

    // A different profile: every surface moves to the new same number (0 for no groups).
    threatProfile.setSource({ kind: 'groups', ids: [] });
    expect(threatProfile.current.parentTechniqueIds.size).toBe(0);
    expect([wizardTotal(), gapTotal(), cardThreatRelevant()]).toEqual([0, 0, 0]);
  });

  it('the all-groups dashboard and actor denominators do NOT move with the profile (§10.4 item 15)', () => {
    const parents = domain.techniques.filter(t => !t.isSubtechnique);
    // dashboard criticalRisk "threat-relevant" = parents used by any ATT&CK group (R4 §3; dashboard-panel:261-266).
    const dashCount = () => parents.filter(t => allGroupsWeight(domain, t.id) > 0).length;
    // actor-profile per-actor total = techniquesByGroup(actor).length (R4 §3; actor-profile-panel:84).
    const actor = domain.groups[0];
    const actorTotal = () => (domain.techniquesByGroup.get(actor.id) ?? []).length;

    threatProfile.setSource({ kind: 'all' });
    const d1 = dashCount();
    const a1 = actorTotal();
    expect(d1).toBeGreaterThan(0);

    threatProfile.setSource({ kind: 'groups', ids: [] });
    expect(dashCount()).toBe(d1);     // all-groups count is profile-independent
    expect(actorTotal()).toBe(a1);
  });
});

// The measured Top-20 default on the real bundled Enterprise 19.2, recorded for the PR body.
describe('Top-20 default threat-relevant count on bundled Enterprise 19.2 (P2-10)', () => {
  let domain: Domain;
  beforeAll(async () => {
    const bundle = await (await fetch('assets/data/enterprise-attack.json')).json();
    TestBed.configureTestingModule({ providers: [{ provide: HttpClient, useValue: { get: () => of({}) } }] });
    domain = (TestBed.inject(DataService) as unknown as { parseBundle(b: unknown, n: string): Domain })
      .parseBundle(bundle, 'Enterprise ATT&CK');
    TestBed.resetTestingModule();   // release the injected DataService (cross-spec leak guard)
  }, 120_000);

  it('Top 20 groups by prevalence weight 167 parent techniques', () => {
    expect(resolveProfile({ kind: 'top-groups', n: 20 }, domain).parentTechniqueIds.size).toBe(167);
  });
});
