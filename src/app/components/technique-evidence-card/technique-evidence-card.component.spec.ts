// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// TechniqueEvidenceCardComponent (P2-18, E2.3-b): each block renders from a
// seeded PostureState; a fresh profile shows Known and Threat only, with no
// Covered or Proven words; "Why this colour" follows the lens on screen.
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { type EnvironmentProviders, type Provider, WritableSignal, signal } from '@angular/core';
import { provideRouter } from '@angular/router';
import { ValidationStatusPillComponent } from '../validation-status-pill/validation-status-pill.component';
import { ValidationService } from '../../services/validation.service';
import { BehaviorSubject, of } from 'rxjs';
import { TechniqueEvidenceCardComponent } from './technique-evidence-card.component';
import type { Technique } from '../../models/technique';
import type { Domain } from '../../models/domain';
import type { CoveredMark, PostureState, ProofRecord, RunSummary } from '../../models/posture/posture.types';
import { DEFAULT_POSTURE_RULES, derivePosture } from '../../models/posture/derive-posture';
import { POSTURE_TODAY } from '../../models/posture/posture-today';
import { heatmapModeDef } from '../../models/heatmap-modes';
import { DataService } from '../../services/data.service';
import { FilterService, type HeatmapMode } from '../../services/filter.service';
import { PostureService } from '../../services/posture.service';
import { EnrichmentService } from '../../services/enrichment.service';
import { MatrixControlService } from '../../services/matrix-control.service';
import { ThreatProfileService } from '../../services/threat-profile.service';
import { CveService } from '../../services/cve.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { SettingsService } from '../../services/settings.service';
import { TechniqueMarksService } from '../../services/technique-marks.service';
import { SourceRegistryService } from '../../services/source-registry.service';

const TECH = {
  id: 'attack-pattern--t1078', attackId: 'T1078', name: 'Valid Accounts', mitigationCount: 8,
  tacticShortnames: ['initial-access'], subtechniques: [], platforms: [], isSubtechnique: false,
} as unknown as Technique;
const OTHER = { ...TECH, id: 'attack-pattern--t1003', attackId: 'T1003', name: 'OS Credential Dumping' } as unknown as Technique;

const DOMAIN = {
  name: 'Enterprise ATT&CK', attackVersion: '19.2', techniques: [TECH, OTHER],
  groupsByTechnique: new Map([[TECH.id, [{}, {}, {}]], [OTHER.id, [{}, {}, {}, {}, {}, {}]]]),
  softwareByTechnique: new Map(), campaignsByTechnique: new Map(),
} as unknown as Domain;

const RANGE_PROOF: ProofRecord = {
  scope: 'range', detectionRef: 'wazuh:990003', outcome: 'alerted', date: '2026-06-01', source: 'lylat-range:CORNERIA-ROOT-01', runId: 'r-range',
};
const OWN_PROOF: ProofRecord = {
  scope: 'own-run', detectionRef: 'sigma:4688', outcome: 'blocked', date: '2026-10-20T10:00:00.000Z', source: 'manual', runId: 'r-own',
};
const PARTIAL: CoveredMark = { qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'partial', via: 'M1038', source: 'manual' };
const FULL_RANGE: CoveredMark = { qualifier: 'range', basis: 'range-detection-authored', strength: 'full', via: 'wazuh:990003', source: 'lylat-range:CORNERIA-ROOT-01', at: '2026-06-01' };

function state(over: Partial<PostureState> = {}): PostureState {
  return {
    ref: 'attack/enterprise/T1078@19.2', rung: 'known', bucket: 'known', qualifiers: [], subStates: [], covered: [], proof: [],
    proofScope: null, proofAge: null, knownSignals: 3, threatWeight: 1, exposureWeight: 0, excluded: false, runsWithoutProof: [], ...over,
  };
}

describe('TechniqueEvidenceCardComponent (P2-18)', () => {
  let fixture: ComponentFixture<TechniqueEvidenceCardComponent>;
  let heat: BehaviorSubject<HeatmapMode>;
  let confirm: jasmine.Spy;
  let kevLoaded: BehaviorSubject<boolean>;
  // The drawer's threat-profile line (RP-F decision 6): the shared notice replaces the label.
  let domainNotice: WritableSignal<string | null>;
  let profileLabel: string;
  let profileActors: string[];
  /** The profile's roll-up over sub-techniques (usedBy); null reads as the direct uses. */
  let profileRollup: string[] | null;
  beforeEach(() => {
    domainNotice = signal<string | null>(null);
    profileLabel = 'Top 20 groups by prevalence';
    profileActors = ['APT28', 'APT29'];
    profileRollup = null;
  });

  function render(s: PostureState, ownerWords: boolean, mode: HeatmapMode = 'frequency', extra: (Provider | EnvironmentProviders)[] = []): HTMLElement {
    heat = new BehaviorSubject<HeatmapMode>(mode);
    confirm = jasmine.createSpy('confirm').and.returnValue(true);
    kevLoaded = new BehaviorSubject(true);
    TestBed.configureTestingModule({
      imports: [TechniqueEvidenceCardComponent],
      providers: [
        {
          provide: PostureService,
          useValue: {
            stateFor: () => s, ownerWords: signal(ownerWords), decayDays: signal(DEFAULT_POSTURE_RULES.decayDays),
            implViewFor: () => ({ status: null, partialVia: null }),
          },
        },
        {
          provide: DataService,
          useValue: {
            domain$: new BehaviorSubject(DOMAIN), currentDomain$: new BehaviorSubject('enterprise'),
            getCurrentAttackDomain: () => 'enterprise', getCurrentDomain: () => DOMAIN,
          },
        },
        { provide: FilterService, useValue: { heatmapMode$: heat } },
        {
          provide: EnrichmentService,
          useValue: {
            referenceDefenseCounts: () => ({ mitigations: 8, sigma: 2, car: 1, controls: 0, d3fend: 0, atomic: 4 }),
            referenceDefenseSignals: () => ({ mitigation: true, detection: true, control: false, d3fend: false, atomic: true }),
          },
        },
        {
          provide: ThreatProfileService,
          useValue: { profile$: of({ label: profileLabel, usedBy: () => profileRollup ?? profileActors, usedByDirect: () => profileActors }), domainNotice },
        },
        {
          provide: CveService,
          useValue: { kevLoaded$: kevLoaded, kevTechScores$: of(new Map([['T1078', 2]])), isKev: (id: string) => id === 'CVE-2024-3400' },
        },
        { provide: AttackCveService, useValue: { loaded$: of(true), getCvesForTechnique: () => [{ cveId: 'CVE-2024-3400' }, { cveId: 'CVE-2019-0001' }] } },
        { provide: SettingsService, useValue: { settings$: of({}), getCoverageColors: () => ['#0', '#1', '#2', '#3', '#4'] } },
        { provide: TechniqueMarksService, useValue: { confirm } },
        { provide: POSTURE_TODAY, useValue: signal(new Date('2026-10-21T00:00:00.000Z')) },
        ...extra,
      ],
    });
    fixture = TestBed.createComponent(TechniqueEvidenceCardComponent);
    fixture.componentRef.setInput('technique', TECH);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  const text = (el: Element | null) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();
  const block = (el: HTMLElement, id: string) => el.querySelector(`[data-testid="${id}"]`);

  it('a fresh profile shows Known and Threat only: no covered, proven or defended strings', () => {
    const el = render(state(), false);
    expect(block(el, 'ev-proven')).toBeNull();
    expect(block(el, 'ev-covered')).toBeNull();
    expect(block(el, 'ev-known')).not.toBeNull();
    expect(block(el, 'ev-threat')).not.toBeNull();
    expect(text(el)).not.toMatch(/\bcovered\b|\bproven\b|\bdefended\b|\bvalidated\b/i);
    for (const attr of ['title', 'aria-label', 'placeholder', 'alt']) {
      for (const node of Array.from(el.querySelectorAll(`[${attr}]`))) {
        expect(node.getAttribute(attr)).not.toMatch(/\bcovered\b|\bproven\b|\bdefended\b/i);
      }
    }
  });

  it('a fresh profile on heat=covered explains the default lens instead (the name may not render)', () => {
    const el = render(state(), false, 'covered');
    expect(text(block(el, 'ev-why'))).toContain('Lens: Frequency');
    expect(text(el)).not.toMatch(/\bcovered\b/i);
  });

  it('Why this colour on a legacy lens: the domain score while the matrix has not scored it, then the matrix readout', () => {
    const el = render(state(), false, 'frequency');
    const freq = heatmapModeDef('frequency')!.formula;
    expect(text(block(el, 'ev-why'))).toBe(`Why this colour: score 3 of max 6: ${freq} Lens: Frequency`);

    heat.next('sigma');
    TestBed.inject(MatrixControlService).publishReadout({ techId: TECH.id, mode: 'sigma', score: 2, max: 9 });
    fixture.detectChanges();
    expect(text(block(el, 'ev-why'))).toContain(`Why this colour: score 2 of max 9: ${heatmapModeDef('sigma')!.formula}`);

    // A readout for another technique is not this cell's score.
    TestBed.inject(MatrixControlService).publishReadout({ techId: OTHER.id, mode: 'sigma', score: 7, max: 9 });
    fixture.detectChanges();
    expect(text(block(el, 'ev-why'))).toContain('not scored on the matrix in this session;');
  });

  // RP-F item 6: with the SigmaHQ layer down every cell scores 0 and the card read
  // 'score 0 of max 1', which looks like "no rules"; it says n/a and why instead.
  it('the Sigma lens reads n/a, not 0 of max 1, while the SigmaHQ coverage layer failed to load', () => {
    const el = render(state(), false, 'sigma');
    const sources = TestBed.inject(SourceRegistryService);
    sources.fail('sigmahq-coverage', 'network error');
    TestBed.inject(MatrixControlService).publishReadout({ techId: TECH.id, mode: 'sigma', score: 0, max: 1 });
    fixture.detectChanges();
    expect(text(block(el, 'ev-why'))).toContain('Why this colour: n/a: SigmaHQ coverage layer did not load (network error), so no count is known');
    expect(text(block(el, 'ev-why'))).not.toContain('of max');
    expect(text(block(el, 'ev-why'))).toContain('Lens: Sigma Rules');

    sources.succeed('sigmahq-coverage', 120);   // a later load: the matrix score is the answer again
    TestBed.inject(MatrixControlService).publishReadout({ techId: TECH.id, mode: 'sigma', score: 2, max: 9 });
    fixture.detectChanges();
    expect(text(block(el, 'ev-why'))).toContain(`Why this colour: score 2 of max 9: ${heatmapModeDef('sigma')!.formula}`);
  });

  it('a failed layer of another lens does not mark Sigma n/a, and Sigma n/a does not leak to other lenses', () => {
    const el = render(state(), false, 'frequency');
    TestBed.inject(SourceRegistryService).fail('sigmahq-coverage', 'network error');
    fixture.detectChanges();
    expect(text(block(el, 'ev-why'))).toContain('Why this colour: score 3 of max 6');
  });

  it('Why this colour on Posture, Proven and Covered reads the seeded PostureState', () => {
    const proven = state({ rung: 'proven', bucket: 'proven', proof: [OWN_PROOF], proofScope: 'own-run', proofAge: 1 });
    const el = render(proven, true, 'posture');
    expect(text(block(el, 'ev-why'))).toContain('Why this colour: Proven (your run) on 10/20/26 by manual; 1 rule fired');

    heat.next('proven');
    fixture.detectChanges();
    expect(text(block(el, 'ev-why'))).toContain('Why this colour: Proven (your run) on 10/20/26 by manual; 1 rule fired');

    heat.next('covered');
    fixture.detectChanges();
    // RP-F item 2: no covered mark, but the same card's Proven block lists the run,
    // so the line points there instead of saying nothing of yours reaches the technique.
    expect(text(block(el, 'ev-why'))).toContain('Why this colour: None: no covered (self-attested or range) mark; see the Proven block for its recorded result');
    expect(text(block(el, 'ev-why'))).not.toContain('nothing of yours reaches this technique');
    expect(text(block(el, 'ev-why'))).toContain('Lens: Covered (self-attested or range)');
    expect(block(el, 'ev-proven')!.querySelectorAll('[data-testid="ev-proof"]').length).toBe(1);
  });

  // RP-F decision 9: a run of yours with no named rule (untested; failed; passed with no rule)
  // is named on the card with its status and date, never as a rung; the Proven block stays proof-only.
  describe('runs without proof (RP-F decision 9)', () => {
    const UNTESTED: RunSummary = { runId: 'u1', status: 'untested', date: '2026-10-21T08:00:00.000Z', source: 'manual' };
    const FAILED: RunSummary = { runId: 'f1', status: 'failed', date: '2026-10-19T08:00:00.000Z', source: 'manual' };
    const T1069_NONE = state({ ref: 'attack/enterprise/T1069@19.2', rung: 'none', bucket: 'none', knownSignals: 0, runsWithoutProof: [UNTESTED] });
    const RUNG_WORDS = /\bcovered\b|\bproven\b|\bdefended\b|\bvalidated\b/i;

    it('an untested run on T1069 with no owner words: the None line names it, and no rung word reaches the card', () => {
      const el = render(T1069_NONE, false, 'posture');
      expect(text(block(el, 'ev-why'))).toContain(
        'Why this colour: None: no reference data mapped; 1 run of yours recorded, latest untested on 10/21/26; see Detection Validation');
      expect(text(block(el, 'ev-why'))).not.toContain('nothing of yours recorded');
      expect(text(block(el, 'ev-runs-without-proof'))).toBe('Runs without proof: untested on 10/21/26 (source manual); see Detection Validation');
      expect(block(el, 'ev-proven')).toBeNull();
      expect(text(el)).not.toMatch(RUNG_WORDS);
    });

    it('with owner words the Proven block stays proof-only and the line lists every run, newest first', () => {
      const el = render(state({ rung: 'none', bucket: 'none', knownSignals: 0, runsWithoutProof: [UNTESTED, FAILED] }), true, 'covered');
      expect(text(block(el, 'ev-proven')!.querySelector('.ev-empty'))).toBe('No recorded detection for this technique.');
      expect(block(el, 'ev-proven')!.querySelectorAll('[data-testid="ev-proof"]').length).toBe(0);
      expect(text(block(el, 'ev-runs-without-proof')))
        .toBe('Runs without proof: untested on 10/21/26 (source manual); failed on 10/19/26 (source manual); see Detection Validation');
      expect(text(block(el, 'ev-why'))).toContain('Why this colour: None: no covered (self-attested or range) mark; '
        + '2 runs of yours recorded, latest untested on 10/21/26; see Detection Validation');
      expect(text(block(el, 'ev-why'))).not.toContain('nothing of yours reaches this technique');
    });

    // RP-F decision 28: round 4's S12 T1018 shape. An untested run with one fired rule sat
    // beside the pill "UNTESTED 1 of 0 detection rules fired" while the Proven block said
    // "No recorded detection for this technique.".
    it('beside a run that fired a rule without proof, the Proven block and the Proven lens name the run and its status', () => {
      const fired: RunSummary = { ...UNTESTED, runId: 's12', date: '2026-10-15T15:00:00.000Z', rulesFired: 1 };
      const el = render(state({ rung: 'known', bucket: 'known', runsWithoutProof: [fired] }), true, 'proven');
      const line = 'No proof: 1 rule fired in your run on 10/15/26 (status untested); a run is proof only when its status is passed';
      expect(text(block(el, 'ev-proven')!.querySelector('[data-testid="ev-proven-empty"]'))).toBe(`${line}.`);
      expect(text(block(el, 'ev-why'))).toContain(`Why this colour: ${line}`);
      expect(text(el)).not.toContain('No recorded detection');
      expect(text(block(el, 'ev-runs-without-proof')))
        .toBe('Runs without proof: untested on 10/15/26 (source manual, 1 rule fired); see Detection Validation');
    });

    // RP-F decision 29: proof supersession is per rule, and only a later FAILED or
    // not-reproducible run of the SAME rule removes proof (the real T1518 shape, a later
    // untested run, stays Proven and is covered in lens-explain.spec.ts). The state is
    // derived by derivePosture, not built by hand, so it is one the app can produce.
    it('a later failed run of the same rule removes the pass: the why line names both runs; the card reads no rung from the pass', () => {
      const rule = OWN_PROOF.detectionRef;
      const passed: RunSummary = { runId: 'p1', status: 'passed', date: '2026-10-18T15:00:00.000Z', source: 'manual', rulesFired: 1, rules: [rule] };
      const failed: RunSummary = { runId: 'f2', status: 'failed', date: '2026-10-20T15:00:00.000Z', source: 'manual', rules: [rule] };
      const s = derivePosture(state().ref, {
        knownSignals: 3, covered: [], threatWeight: 1, exposureWeight: 0,
        proof: [{ ...OWN_PROOF, runId: 'p1', date: passed.date }],
        verdicts: [{ date: failed.date, failed: true, notReproducible: false, source: 'manual' }],
        runs: [failed, passed],
      }, DEFAULT_POSTURE_RULES, new Date('2026-10-21T00:00:00.000Z'));
      expect(s.rung).toBe('known');
      expect(s.proof.length).toBe(0);
      expect(s.supersededProof?.latest.runId).toBe('f2');
      const el = render(s, true, 'posture');
      expect(text(block(el, 'ev-why'))).toContain(
        'Why this colour: Known: mapped (3 of 5 reference families); contradicted: latest run of the rule failed on 10/20/26; an earlier run passed on 10/18/26; see Detection Validation');
      // RP-F decision 28 (round 4 repair, S27 T1059.001): the outranked pass fired a rule the pill
      // still shows, so the Proven block names it rather than "No recorded detection".
      expect(text(block(el, 'ev-proven')!.querySelector('[data-testid="ev-proven-empty"]')))
        .toBe('No proof: 1 rule fired in your run on 10/18/26 (status passed); a later run outranks it.');
      expect(text(el)).not.toContain('No recorded detection');
    });

    // RP-F decision 24 (round 4 repair, S22 T1497): an unreadable run date is sorted oldest AND
    // flagged where it is printed; round 4 read "Runs without proof: failed on yesterday (source manual)".
    it('a run whose date cannot be read is flagged in the runs line, never printed as a date', () => {
      const undated: RunSummary = { runId: 'y', status: 'failed', date: 'yesterday', source: 'manual' };
      const el = render(state({ rung: 'none', bucket: 'none', knownSignals: 0, runsWithoutProof: [undated] }), true, 'posture');
      expect(text(block(el, 'ev-runs-without-proof')))
        .toBe("Runs without proof: failed on 'yesterday' (unreadable date, sorted oldest) (source manual); see Detection Validation");
    });

    // RP-F decision 16a: the Covered block's empty line spoke of everything ("Nothing of yours
    // recorded for this technique.") beside a recorded run on 72 of 72 owner cards in round 3.
    it('the Covered block never says nothing of yours is recorded while the card lists a run', () => {
      const el = render(state({ rung: 'none', bucket: 'none', knownSignals: 0, runsWithoutProof: [UNTESTED, FAILED] }), true, 'covered');
      expect(block(el, 'ev-covered')).not.toBeNull();
      expect(block(el, 'ev-covered')!.querySelector('[data-testid="ev-covered-empty"]')).toBeNull();
      expect(text(el)).not.toMatch(/nothing of yours/i);
      expect(block(el, 'ev-runs-without-proof')).not.toBeNull();
    });

    it('the Covered block omits its empty line beside a Proven record too, and names marks only when nothing is listed', () => {
      const proven = render(state({ rung: 'proven', bucket: 'proven', proof: [OWN_PROOF], proofScope: 'own-run', proofAge: 1 }), true, 'posture');
      expect(block(proven, 'ev-covered')!.querySelector('[data-testid="ev-covered-empty"]')).toBeNull();
      expect(text(proven)).not.toMatch(/nothing of yours/i);
      TestBed.resetTestingModule();

      // Owner words from another technique; this one has no mark and no run: the line is about marks.
      const bare = render(state(), true, 'posture');
      expect(text(block(bare, 'ev-covered')!.querySelector('[data-testid="ev-covered-empty"]')))
        .toBe('No covered (self-attested or range) mark recorded.');
      expect(text(bare)).not.toMatch(/nothing of yours recorded for this technique/i);
    });

    // RP-F decision 16a: the card printed the UTC day of the ISO timestamp (date.slice(0, 10)),
    // "2026-10-22", while the drawer's Validation pill printed "10/21/26, 7:49 PM".
    it('a run recorded after 19:00 local time: the card and the Validation pill print the same day', () => {
      const late = new Date(2026, 9, 21, 19, 49).toISOString();   // 19:49 local on 21 October, whatever the zone
      const run: RunSummary = { runId: 'late', status: 'failed', date: late, source: 'manual' };
      const proof: ProofRecord = { ...OWN_PROOF, date: late, runId: 'late-proof' };
      const validation = {
        runs$: new BehaviorSubject([]),
        forTechnique: () => [{ id: 'late', runDate: late, status: 'failed', detectionsFired: [], detectionsExpected: ['sigma:4688'], outcomes: [] }],
        latestFor: () => ({ id: 'late', runDate: late, status: 'failed', detectionsFired: [], detectionsExpected: ['sigma:4688'], outcomes: [] }),
      };
      const el = render(state({
        rung: 'proven', bucket: 'proven', proof: [proof], proofScope: 'own-run', proofAge: 0, runsWithoutProof: [run],
      }), true, 'posture', [provideRouter([]), { provide: ValidationService, useValue: validation }]);
      const pill = TestBed.createComponent(ValidationStatusPillComponent);
      pill.componentInstance.attackId = 'T1078';
      pill.detectChanges();
      pill.componentInstance.ngOnChanges({});
      pill.detectChanges();
      const pillWhen = text((pill.nativeElement as HTMLElement).querySelector('.vsp-when'));
      expect(pillWhen).toMatch(/^last run 10\/21\/26, 7:49\sPM/);

      const day = '10/21/26';
      expect(text(block(el, 'ev-why'))).toContain(`Why this colour: Proven (your run) on ${day} by manual; 1 rule fired`);
      expect(text(block(el, 'ev-proven')!.querySelector('[data-testid="ev-proof"]'))).toContain(`Proven (your run) on ${day} by sigma:4688`);
      expect(text(block(el, 'ev-runs-without-proof'))).toBe(`Runs without proof: failed on ${day} (source manual); see Detection Validation`);
      expect(text(el)).not.toContain('2026-10-22');
      expect(text(el)).not.toContain('2026-10-21');
    });

    it('a technique with no runs renders no Runs without proof line: an empty user\'s card is unchanged', () => {
      const el = render(state({ rung: 'none', bucket: 'none', knownSignals: 0 }), false, 'posture');
      expect(block(el, 'ev-runs-without-proof')).toBeNull();
      expect(text(block(el, 'ev-why'))).toContain('Why this colour: None: no reference data mapped and nothing of yours recorded');
      expect(text(el)).not.toMatch(RUNG_WORDS);
    });
  });

  it('the Proven block lists each record: rule, date, source, outcome, lab badge and stale', () => {
    const s = state({
      rung: 'proven', bucket: 'proven', proof: [OWN_PROOF, RANGE_PROOF], proofScope: 'own-run', proofAge: 1, covered: [FULL_RANGE],
      qualifiers: ['range'],
    });
    const el = render(s, true, 'posture');
    const proven = block(el, 'ev-proven')!;
    expect(text(proven.querySelector('h3'))).toBe('Proven');
    const rows = Array.from(proven.querySelectorAll('[data-testid="ev-proof"]')).map(r => text(r));
    expect(rows.length).toBe(2);
    expect(rows[0]).toBe('Proven (your run) on 10/20/26 by sigma:4688 (blocked) source manual');
    // 142 days old on the 90-day range window: stale, and a range record carries the lab badge.
    expect(rows[1]).toBe('Proven in range on 6/1/26 by wazuh:990003 (alerted) source lylat-range:CORNERIA-ROOT-01 lab stale');
  });

  it('the Covered block lists each mark with qualifier, basis and via; Confirm on a partial mark reuses P2-16\'s path', () => {
    const s = state({ rung: 'covered', bucket: 'partial', subStates: ['partial'], covered: [PARTIAL] });
    const el = render(s, true, 'posture');
    const covered = block(el, 'ev-covered')!;
    expect(text(covered.querySelector('h3'))).toBe('Covered (self-attested or range)');
    const row = covered.querySelector('[data-testid="ev-mark"]')!;
    expect(text(row)).toContain('self-attested');
    expect(text(row)).toContain('mitigation implemented via M1038');
    expect(text(row)).toContain('partial · source manual');
    (row.querySelector('[data-testid="ev-confirm"]') as HTMLButtonElement).click();
    expect(confirm).toHaveBeenCalledOnceWith('attack/enterprise/T1078@19.2', { via: 'M1038' });
    expect(block(el, 'ev-proven')!.textContent).toContain('No recorded detection for this technique.');
  });

  it('a full mark offers no Confirm', () => {
    const s = state({ rung: 'covered', bucket: 'covered', qualifiers: ['range'], covered: [FULL_RANGE] });
    const el = render(s, true, 'posture');
    const row = block(el, 'ev-covered')!.querySelector('[data-testid="ev-mark"]')!;
    expect(text(row)).toContain('range detection authored in the range via wazuh:990003');
    expect(text(row)).toContain('full · source lylat-range:CORNERIA-ROOT-01 · 6/1/26');
    expect(row.querySelector('[data-testid="ev-confirm"]')).toBeNull();
  });

  it('the Known block lists the five reference families with counts and sources', () => {
    const el = render(state(), false);
    const known = block(el, 'ev-known')!;
    expect(text(known.querySelector('.ev-summary'))).toBe('mapped 3 of 5 reference families');
    const rows = Array.from(known.querySelectorAll('.ev-known-row')).map(r => text(r));
    expect(rows).toEqual([
      'ATT&CK mitigations 8 Enterprise ATT&CK 19.2',
      'Detection content 3 SigmaHQ rules 2, MITRE CAR analytics 1',
      'Control mappings 0 CTID: NIST 800-53, CRI, CIS, CSA CCM, M365',
      'D3FEND countermeasures 0 MITRE D3FEND',
      'Atomic tests 4 Atomic Red Team',
    ]);
  });

  it('the threat-profile line says which stored groups the domain lacks, and is plain when none is absent (RP-F decision 6)', () => {
    profileLabel = 'FIN7';            // what resolveProfile names a {APT29, FIN7} profile on ICS
    profileActors = [];
    domainNotice.set('1 of 2 groups present in ICS: FIN7; APT29 has no ICS use');
    const el = render(state(), false);
    const line = () => text(block(el, 'ev-threat')!.querySelector('[data-testid="ev-threat-profile"]'));
    expect(line()).toBe('Threat profile (1 of 2 groups present in ICS: FIN7; APT29 has no ICS use): used by 0');

    domainNotice.set(null);           // back on Enterprise: every group present, the line is the plain label
    fixture.detectChanges();
    expect(line()).toBe('Threat profile (FIN7): used by 0');
  });

  // RP-F decision 28: the profile line rolled sub-technique uses up to the parent while the
  // bundle line counted direct uses only. Both now count direct uses; the roll-up is labelled.
  it('the Threat block counts direct uses on both lines, and labels the roll-up over sub-techniques when it is larger', () => {
    profileActors = ['APT29'];
    profileRollup = ['APT28', 'APT29', 'FIN7'];
    const el = render(state(), false);
    const threat = block(el, 'ev-threat')!;
    expect(text(threat.querySelector('[data-testid="ev-threat-profile"]')))
      .toBe('Threat profile (Top 20 groups by prevalence): used by 1: APT29; 3 counting its sub-techniques');
    expect(text(threat)).toContain('Used by 3 groups in the loaded ATT&CK bundle');
  });

  it('the Threat block names the profile actors, the bundle groups and the KEV-linked CVEs', () => {
    const el = render(state(), false);
    const threat = block(el, 'ev-threat')!;
    expect(text(threat.querySelector('[data-testid="ev-threat-profile"]')))
      .toBe('Threat profile (Top 20 groups by prevalence): used by 2: APT28, APT29');
    expect(text(threat)).toContain('Used by 3 groups in the loaded ATT&CK bundle');
    expect(text(threat.querySelector('[data-testid="ev-kev"]'))).toBe('KEV-linked CVEs: 2 (CVE-2024-3400)');

    kevLoaded.next(false);
    fixture.detectChanges();
    expect(text(threat.querySelector('[data-testid="ev-kev"]'))).toBe('KEV-linked CVEs: the KEV catalogue is not loaded in this session');
  });
});
