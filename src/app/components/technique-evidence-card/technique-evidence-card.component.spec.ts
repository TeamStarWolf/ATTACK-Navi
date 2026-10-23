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
import { EVIDENCE_CARD_IDLE, TechniqueEvidenceCardComponent, legacySwatch } from './technique-evidence-card.component';
import { PanelNavService } from '../../services/panel-nav.service';
import { SAFE_SEQ } from '../../models/safe-palette';
import type { Technique } from '../../models/technique';
import type { Domain } from '../../models/domain';
import type { CoveredMark, PostureState, ProofRecord, RunSummary } from '../../models/posture/posture.types';
import { DEFAULT_POSTURE_RULES, derivePosture } from '../../models/posture/derive-posture';
import { POSTURE_TODAY } from '../../models/posture/posture-today';
import { heatmapModeDef } from '../../models/heatmap-modes';
import { DataService, type AttackDomain } from '../../services/data.service';
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
import { RecordRunRequestService } from '../../services/record-run-request.service';
import { lylatRowsToRuns, validateLylatExport } from '../../contracts/lylat-validated-detections';
import { runInputs, runInputsFor } from '../../services/posture-adapters';
import { rpf8Runs } from '../../testing/rpf8-shapes';
import RANGE_FIXTURE from '../../../testing/fixtures/lylat/validated-detections.fixture.json';

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
const PARTIAL: CoveredMark = { qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'partial', via: 'M1038', source: 'manual', partialCause: 'breadth' };
const FULL_RANGE: CoveredMark = { qualifier: 'range', basis: 'range-detection-authored', strength: 'full', via: 'wazuh:990003', source: 'lylat-range:CORNERIA-ROOT-01', at: '2026-06-01' };

/**
 * A technique's PostureState through the range contract path (RP-F decision 31): the
 * export is validated, mapped to runs (lylatRowsToRuns), turned into posture inputs
 * (runInputs) and derived, as PostureService does after Import range results.
 */
function rangeState(attackId: string, exportJson: unknown, extraCovered: readonly CoveredMark[] = []): PostureState {
  const checked = validateLylatExport(exportJson);
  if (!checked.ok) throw new Error(checked.errors.join('; '));
  const runs = lylatRowsToRuns(checked.value, id => id, 'enterprise', '19.2', () => true);
  const inputs = [...runs.bySource.values()].flat().filter(r => r.run.techniqueId === attackId).map(r => runInputs(r.run));
  return derivePosture(`attack/enterprise/${attackId}@19.2`, {
    knownSignals: 0, threatWeight: 0, exposureWeight: 0,
    covered: [...extraCovered, ...inputs.flatMap(i => i.covered)], proof: inputs.flatMap(i => i.proof), verdicts: inputs.flatMap(i => i.verdicts),
    runs: inputs.map(i => i.summary),
  }, DEFAULT_POSTURE_RULES, new Date('2026-10-22T00:00:00.000Z'));
}

/** Round 6, letter A: one telemetry-observed range row on T1200, imported through the contract path. */
const T1200_TELEMETRY_EXPORT = {
  schema: 'lylat-validated-detections/1', range_build_ref: 'a1b2c3d', generated_at: '2026-10-21T00:00:00Z',
  rows: [{
    mission_id: 'SYNTH-MISSION-T', technique_ref: { domain: 'enterprise', id: 'T1200', attack_version: '19.2' },
    detection_ref: 'wazuh:5', coverage_state: 'telemetry-observed', outcome: 'logged',
    negative_control: 'detection-only', validated_at: '2026-10-21', evidence_ref: 'SYNTH-MISSION-T-step1',
  }],
};
const T1200 = { ...TECH, id: 'attack-pattern--t1200', attackId: 'T1200', name: 'Hardware Additions' } as unknown as Technique;

/**
 * Round 7, letters A and G: telemetry-observed range rows whose rule fired (T1082
 * alerted via wazuh:12, T1083 blocked via wazuh:13, T1106 alerted via wazuh:14 with
 * M1038 implemented), beside the no-alert shape (T1200 logged via wazuh:5).
 */
const ROUND7_EXPORT = {
  schema: 'lylat-validated-detections/1', range_build_ref: 'a1b2c3d', generated_at: '2026-10-21T00:00:00Z',
  rows: ([['T1082', 'wazuh:12', 'alerted'], ['T1083', 'wazuh:13', 'blocked'], ['T1106', 'wazuh:14', 'alerted'], ['T1200', 'wazuh:5', 'logged']] as const)
    .map(([id, rule, outcome], i) => ({
      mission_id: 'SYNTH-MISSION-R7', technique_ref: { domain: 'enterprise', id, attack_version: '19.2' },
      detection_ref: rule, coverage_state: 'telemetry-observed', outcome,
      negative_control: 'detection-only', validated_at: '2026-10-20', evidence_ref: `SYNTH-MISSION-R7-step${i + 1}`,
    })),
};
const T1082 = { ...TECH, id: 'attack-pattern--t1082', attackId: 'T1082', name: 'System Information Discovery' } as unknown as Technique;
const T1083 = { ...TECH, id: 'attack-pattern--t1083', attackId: 'T1083', name: 'File and Directory Discovery' } as unknown as Technique;
const T1106 = { ...TECH, id: 'attack-pattern--t1106', attackId: 'T1106', name: 'Native API' } as unknown as Technique;
const T1003_001 = { ...TECH, id: 'attack-pattern--t1003-001', attackId: 'T1003.001', name: 'LSASS Memory', isSubtechnique: true } as unknown as Technique;

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
  let recordRequest: jasmine.Spy;
  /** The technique the card renders (TECH unless a spec names another). */
  let techInput: Technique;
  let kevLoaded: BehaviorSubject<boolean>;
  // The drawer's threat-profile line (RP-F decision 6): the shared notice replaces the label.
  let domainNotice: WritableSignal<string | null>;
  let profileLabel: string;
  let profileActors: string[];
  /** The profile's roll-up over sub-techniques (usedBy); null reads as the direct uses. */
  let profileRollup: string[] | null;
  /** The ATT&CK domain on screen (technique page design PR 1: not applicable outside Enterprise). */
  let domainId: AttackDomain;
  /** The CTID CVE-to-technique mappings have loaded (the KEV count waits for them). */
  let cvesLoaded: BehaviorSubject<boolean>;
  /** The CVE ids the mocked KEV catalogue lists. */
  let kevSet: Set<string>;
  let loadKev: jasmine.Spy;
  let ctidRetry: jasmine.Spy;
  let panelOpen: jasmine.Spy;
  /** The idle tasks the card scheduled, run by the spec (EVIDENCE_CARD_IDLE). */
  let idleTasks: Array<() => void>;
  let settingsNow: Record<string, unknown>;
  beforeEach(() => {
    domainNotice = signal<string | null>(null);
    profileLabel = 'Top 20 groups by prevalence';
    profileActors = ['APT28', 'APT29'];
    profileRollup = null;
    techInput = TECH;
    domainId = 'enterprise';
    kevSet = new Set(['CVE-2024-3400']);
    idleTasks = [];
    settingsNow = {};
  });

  function render(s: PostureState, ownerWords: boolean, mode: HeatmapMode = 'frequency', extra: (Provider | EnvironmentProviders)[] = []): HTMLElement {
    heat = new BehaviorSubject<HeatmapMode>(mode);
    confirm = jasmine.createSpy('confirm').and.returnValue(true);
    recordRequest = jasmine.createSpy('request');
    kevLoaded = new BehaviorSubject(true);
    cvesLoaded = new BehaviorSubject(true);
    loadKev = jasmine.createSpy('loadKev');
    ctidRetry = jasmine.createSpy('retry');
    panelOpen = jasmine.createSpy('open');
    TestBed.configureTestingModule({
      imports: [TechniqueEvidenceCardComponent],
      providers: [
        provideRouter([]),
        { provide: EVIDENCE_CARD_IDLE, useValue: (task: () => void) => { idleTasks.push(task); return () => undefined; } },
        { provide: PanelNavService, useValue: { open: panelOpen } },
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
            domain$: new BehaviorSubject(DOMAIN), currentDomain$: new BehaviorSubject(domainId),
            getCurrentAttackDomain: () => domainId, getCurrentDomain: () => DOMAIN,
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
          useValue: { kevLoaded$: kevLoaded, kevTechScores$: of(new Map([['T1078', 2]])), isKev: (id: string) => kevSet.has(id), loadKev },
        },
        {
          provide: AttackCveService,
          useValue: { loaded$: cvesLoaded, retry: ctidRetry, getCvesForTechnique: () => [{ cveId: 'CVE-2024-3400' }, { cveId: 'CVE-2019-0001' }] },
        },
        { provide: SettingsService, useValue: { settings$: of(settingsNow), getCoverageColors: () => ['#c0', '#c1', '#c2', '#c3', '#c4'] } },
        { provide: TechniqueMarksService, useValue: { confirm } },
        { provide: RecordRunRequestService, useValue: { request: recordRequest } },
        { provide: POSTURE_TODAY, useValue: signal(new Date('2026-10-21T00:00:00.000Z')) },
        ...extra,
      ],
    });
    fixture = TestBed.createComponent(TechniqueEvidenceCardComponent);
    fixture.componentRef.setInput('technique', techInput);
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
    // Technique page design 4.5: the swatch's band follows the why line in words (3 of 6: the 50-74% quartile).
    expect(text(block(el, 'ev-why'))).toBe(`Why this colour: score 3 of max 6: ${freq} (band 50-74% of the highest) Lens: Frequency`);

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
        .toBe('No proof: no rule fired in your run on 10/20/26 (status failed); earlier, 1 rule fired in your run on 10/18/26 (status passed); a later run outranks it.');
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
    expect(rows[1]).toBe('Proven in a range run on 6/1/26 by wazuh:990003 (alerted) source lylat-range:CORNERIA-ROOT-01 lab stale');
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

  // RP-F decision 31 (round 6, letter A): a range telemetry partial is partial by
  // telemetry. Round 6 read the breadth-threshold sentence and offered Confirm, which
  // minted a self-attested mark 'via wazuh:5' and turned the technique full Covered.
  describe('a range telemetry partial (RP-F decision 31)', () => {
    const WORDS = 'range telemetry observed via wazuh:5: partial, no detection alerted';

    for (const [mode, line] of [
      ['posture', `Covered (range, partial via wazuh:5) from ${WORDS}`],
      ['covered', `Covered (self-attested or range), partial via wazuh:5 from ${WORDS}`],
    ] as const) {
      it(`T1200 through the contract path, lens ${mode}: the why line names the telemetry, never the threshold`, () => {
        techInput = T1200;
        const s = rangeState('T1200', T1200_TELEMETRY_EXPORT);
        expect(s.partialCauses).toEqual(['telemetry']);
        const why = text(block(render(s, true, mode), 'ev-why'));
        expect(why).toContain(line);
        expect(why).not.toContain('breadth threshold');
      });
    }

    it('the Covered block names the row; no Confirm; "Record a run" asks Detect > Validation for the technique', () => {
      techInput = T1200;
      const el = render(rangeState('T1200', T1200_TELEMETRY_EXPORT), true, 'posture');
      const row = block(el, 'ev-covered')!.querySelector('[data-testid="ev-mark"]')!;
      expect(text(row)).toContain('range telemetry observed in the range via wazuh:5');
      expect(text(row)).toContain('partial · source lylat-range:SYNTH-MISSION-T · 10/21/26');
      expect(el.querySelector('[data-testid="ev-confirm"]')).toBeNull();
      const record = row.querySelector('[data-testid="ev-record-run"]') as HTMLButtonElement;
      expect(text(record)).toBe('Record a run');
      record.click();
      expect(recordRequest).toHaveBeenCalledOnceWith('T1200');
      expect(confirm).not.toHaveBeenCalled();
    });

    it('Confirm never mints a mark via a range rule, even when called directly', () => {
      techInput = T1200;
      render(rangeState('T1200', T1200_TELEMETRY_EXPORT), true, 'posture');
      fixture.componentInstance.confirm('wazuh:5');
      expect(confirm).not.toHaveBeenCalled();
    });

    it("the P2-20 fixture's T1003.001 (alerted plus telemetry rows) stays Proven; the why line names the telemetry row", () => {
      techInput = T1003_001;
      const el = render(rangeState('T1003.001', RANGE_FIXTURE), true, 'posture');
      const why = text(block(el, 'ev-why'));
      expect(why).toContain('Proven in a range run on 10/19/26 by lylat-range:SYNTH-MISSION-A; 1 rule fired; a later run on 10/20/26 observed telemetry only');
      const marks = Array.from(block(el, 'ev-covered')!.querySelectorAll('[data-testid="ev-mark"]'));
      expect(marks.map(m => text(m.querySelector('.ev-line')))).toEqual(['telemetry observed in the range via wazuh:990007']);
      expect(el.querySelector('[data-testid="ev-confirm"]')).toBeNull();
      expect(el.querySelector('[data-testid="ev-record-run"]')).not.toBeNull();
    });

    // RP-F decision 35 (round 7, letters A and G): the telemetry cause carries the row's
    // outcome. A row whose rule alerted or blocked read "partial, no detection alerted"
    // beside a pill and a Proven block that said the rule fired.
    describe('a telemetry row whose rule fired (RP-F decision 35)', () => {
      const fired = (rule: string, verb: string) =>
        `range telemetry observed via ${rule}: partial; the rule ${verb} in this run, but the range reports telemetry-only coverage, so it is not proof (range run on 10/20/26)`;
      for (const [t, rule, verb, mode] of [
        [T1082, 'wazuh:12', 'alerted', 'posture'], [T1082, 'wazuh:12', 'alerted', 'covered'],
        [T1083, 'wazuh:13', 'blocked', 'posture'], [T1083, 'wazuh:13', 'blocked', 'covered'],
      ] as const) {
        it(`${t.attackId} (${verb} via ${rule}), lens ${mode}: the why line, the Covered block, the Record-a-run tooltip and the Proven block agree`, () => {
          techInput = t;
          const s = rangeState(t.attackId, ROUND7_EXPORT);
          expect(s.covered.map(m => [m.partialCause, m.telemetryOutcome])).toEqual([['telemetry', verb]]);
          const el = render(s, true, mode);
          const why = text(block(el, 'ev-why'));
          expect(why).toContain(fired(rule, verb));
          expect(why).not.toContain('no detection alerted');
          expect(why).not.toContain('breadth threshold');
          const row = block(el, 'ev-covered')!.querySelector('[data-testid="ev-mark"]')!;
          expect(text(row.querySelector('[data-testid="ev-mark-cause"]'))).toBe(fired(rule, verb));
          expect((row.querySelector('[data-testid="ev-record-run"]') as HTMLButtonElement).title)
            .toBe(`${fired(rule, verb)}; record a validation run of this technique in Detect > Validation`);
          expect(el.querySelector('[data-testid="ev-confirm"]')).toBeNull();
          // The Proven block keeps the fired count and names the run as the range's, never 'your run'.
          expect(text(block(el, 'ev-proven-empty')))
            .toBe('No proof: 1 rule fired in the range run on 10/20/26 (status partial); a run is proof only when its status is passed.');
        });
      }

      it('T1106 under M1038 implemented (mixed): the threshold sentence and the alerted telemetry words, Confirm for M1038 only, Record a run for the row', () => {
        techInput = T1106;
        const s = rangeState('T1106', ROUND7_EXPORT, [PARTIAL]);
        expect(s.partialCauses).toEqual(['breadth', 'telemetry']);
        const el = render(s, true, 'posture');
        const why = text(block(el, 'ev-why'));
        expect(why).toContain(`: reached only through a mitigation or control mapped to more techniques than the breadth threshold; ${fired('wazuh:14', 'alerted')}`);
        expect(why).not.toContain('no detection alerted');
        const causes = Array.from(el.querySelectorAll('[data-testid="ev-mark-cause"]')).map(text);
        expect(causes).toEqual(['reached only through a mitigation or control mapped to more techniques than the breadth threshold', fired('wazuh:14', 'alerted')]);
        expect(el.querySelectorAll('[data-testid="ev-confirm"]').length).toBe(1);
        expect(el.querySelectorAll('[data-testid="ev-record-run"]').length).toBe(1);
        expect(text(block(el, 'ev-proven-empty'))).toContain('No proof: 1 rule fired in the range run on 10/20/26 (status partial)');
      });

      // RP-F decision 44: a range run whose attack did not execute is named as not credited
    // in the Covered block, never as a mark whose rule alerted.
    it('T1027.013 (an errored range run): the Covered block reads "did not execute (errored): not credited"; the runs line says so', () => {
      techInput = T1200;
      const runs = rpf8Runs().get('T1027.013')!;
      const inputs = runInputsFor(runs);
      const s = derivePosture('attack/enterprise/T1027.013@19.2', {
        knownSignals: 2, threatWeight: 1, exposureWeight: 0, covered: inputs.flatMap(i => i.covered),
        proof: inputs.flatMap(i => i.proof), verdicts: inputs.flatMap(i => i.verdicts), runs: inputs.map(i => i.summary),
      }, DEFAULT_POSTURE_RULES, new Date(2026, 9, 23, 12));
      const el = render(s, true, 'covered');
      expect(Array.from(el.querySelectorAll('[data-testid="ev-not-credited"]')).map(text))
        .toEqual(['range run on 10/21/26 did not execute (errored): not credited']);
      expect(text(el.querySelector('[data-testid="ev-runs-without-proof"]'))).toContain('(source lylat-range:J35, attack did not execute: errored)');
      expect(text(el)).not.toContain('alerted in this run');
      expect(text(el)).not.toMatch(/[1-9]\d* rules? fired/);
    });

    it('T1200 (logged via wazuh:5) keeps the no-alert words on the why line, the Covered block and the tooltip', () => {
        techInput = T1200;
        const el = render(rangeState('T1200', ROUND7_EXPORT), true, 'posture');
        const words = 'range telemetry observed via wazuh:5: partial, no detection alerted (range run on 10/20/26)';
        expect(text(block(el, 'ev-why'))).toContain(`Covered (range, partial via wazuh:5) from ${words}`);
        const row = block(el, 'ev-covered')!.querySelector('[data-testid="ev-mark"]')!;
        expect(text(row.querySelector('[data-testid="ev-mark-cause"]'))).toBe(words);
        expect((row.querySelector('[data-testid="ev-record-run"]') as HTMLButtonElement).title).toContain(`${words}; record a validation run`);
        expect(text(block(el, 'ev-proven-empty'))).toBe('No recorded detection for this technique.');
      });

      it('a manual run that fired a rule without proof is still named as your run', () => {
        const run: RunSummary = { runId: 'm1', status: 'untested', date: '2026-10-15T12:00:00.000Z', source: 'manual', rulesFired: 1, rules: ['siem:a'] };
        const el = render(state({ runsWithoutProof: [run] }), true, 'posture');
        expect(text(block(el, 'ev-proven-empty'))).toContain('1 rule fired in your run on 10/15/26 (status untested)');
      });
    });

    it('a breadth partial (M1038) keeps its threshold sentence and Confirm, and offers no Record a run', () => {
      const el = render(state({ rung: 'covered', bucket: 'partial', subStates: ['partial'], covered: [PARTIAL], partialCauses: ['breadth'] }), true, 'posture');
      expect(text(block(el, 'ev-why'))).toContain('Covered (self-attested, partial via M1038): reached only through a mitigation or control mapped to more techniques than the breadth threshold');
      expect(el.querySelector('[data-testid="ev-confirm"]')).not.toBeNull();
      expect(el.querySelector('[data-testid="ev-record-run"]')).toBeNull();
    });
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
    // Technique page design 4.6: never "not loaded in this session"; the catalogue is on its way.
    expect(text(threat.querySelector('[data-testid="ev-kev"]'))).toBe('KEV-linked CVEs: loading the CISA KEV catalogue…');
  });

  // ─── Technique page design PR 1: KEV on demand, the swatch, not applicable ──────

  describe('KEV on demand (design 4.6)', () => {
    const kevLine = (el: HTMLElement) => el.querySelector<HTMLElement>('[data-testid="ev-kev"]')!;

    it('asks for the KEV catalogue once, on idle after the first render, never before', async () => {
      render(state(), false);
      expect(idleTasks.length).withContext('nothing is scheduled before the first render has finished').toBe(0);
      await fixture.whenStable();
      fixture.detectChanges();
      expect(idleTasks.length).withContext('one idle task scheduled after the first render').toBe(1);
      expect(loadKev).not.toHaveBeenCalled();
      idleTasks[0]();
      expect(loadKev).toHaveBeenCalledTimes(1);
      kevLoaded.next(false);
      fixture.detectChanges();
      fixture.componentRef.setInput('technique', OTHER);
      fixture.detectChanges();
      expect(idleTasks.length).withContext('asked once per card').toBe(1);
    });

    it('reads loading while the catalogue or the CVE-to-technique mappings are on their way, in a polite live region', () => {
      const el = render(state(), false);
      kevLoaded.next(false);
      fixture.detectChanges();
      expect(kevLine(el).getAttribute('data-kev-state')).toBe('loading');
      expect(text(kevLine(el))).toBe('KEV-linked CVEs: loading the CISA KEV catalogue…');
      expect(kevLine(el).closest('[aria-live="polite"]')).not.toBeNull();
      kevLoaded.next(true);
      cvesLoaded.next(false);
      fixture.detectChanges();
      expect(text(kevLine(el))).toBe('KEV-linked CVEs: loading the CTID CVE-to-technique mappings…');
      cvesLoaded.next(true);
      fixture.detectChanges();
      expect(kevLine(el).getAttribute('data-kev-state')).toBe('loaded');
      expect(text(kevLine(el))).toBe('KEV-linked CVEs: 2 (CVE-2024-3400)');
      expect(kevLine(el).querySelector('a')!.getAttribute('href')).toBe('/exposure/cve');
    });

    it('says failed with Retry when the live feed and the bundled snapshot both failed; Retry asks again', () => {
      const el = render(state(), false);
      kevLoaded.next(false);
      const sources = TestBed.inject(SourceRegistryService);
      sources.fail('cisa-kev', 'network error');
      fixture.detectChanges();
      expect(kevLine(el).getAttribute('data-kev-state')).withContext('the snapshot is still loading').toBe('loading');
      sources.fail('cisa-kev-snapshot', 'network error');
      fixture.detectChanges();
      expect(kevLine(el).getAttribute('data-kev-state')).toBe('failed');
      expect(text(kevLine(el))).toBe('KEV catalogue unavailable: the live feed and the bundled snapshot both failed · Retry');
      expect(text(kevLine(el))).not.toMatch(/\b0\b/);
      (el.querySelector('[data-testid="ev-kev-retry"]') as HTMLButtonElement).click();
      expect(loadKev).toHaveBeenCalledTimes(1);
      expect(ctidRetry).not.toHaveBeenCalled();
    });

    it('says failed with Retry when both CTID mapping datasets failed; Retry fetches each failed one', () => {
      const el = render(state(), false);
      cvesLoaded.next(false);
      const sources = TestBed.inject(SourceRegistryService);
      sources.fail('ctid-attack-to-cve', 'network error');
      sources.fail('ctid-kev', 'network error');
      fixture.detectChanges();
      expect(text(kevLine(el))).toBe('KEV-linked CVEs unavailable: the CTID CVE-to-technique mappings did not load · Retry');
      (el.querySelector('[data-testid="ev-kev-retry"]') as HTMLButtonElement).click();
      expect(ctidRetry.calls.allArgs()).toEqual([['ctid-attack-to-cve'], ['ctid-kev']]);
      expect(loadKev).not.toHaveBeenCalled();
    });

    it('a loaded catalogue with no KEV-linked CVE says so, not a bare 0', () => {
      kevSet = new Set();
      techInput = OTHER;
      const el = render(state(), false);
      expect(text(kevLine(el))).toBe('KEV-linked CVEs: 0 in the KEV catalogue');
      expect(kevLine(el).querySelector('a')).toBeNull();
    });
  });

  describe('not applicable outside Enterprise (SOURCE_DOMAINS)', () => {
    for (const [dom, label] of [['ics', 'ICS ATT&CK'], ['mobile', 'Mobile ATT&CK']] as const) {
      it(`on ${label} the Enterprise-only families and the KEV line read "not applicable", never 0`, async () => {
        domainId = dom;
        const el = render(state(), false);
        await fixture.whenStable();
        fixture.detectChanges();
        const known = block(el, 'ev-known')!;
        expect(text(known.querySelector('[data-testid="ev-known-summary"]')))
          .toBe(`mapped 1 of 5 reference families (4 not applicable in ${label})`);
        const rows = Array.from(known.querySelectorAll('.ev-known-row')).map(r => text(r));
        expect(rows[0]).toBe('ATT&CK mitigations 8 Enterprise ATT&CK 19.2');
        expect(rows.slice(1).every(r => r.includes(`not applicable in ${label}`))).withContext(rows.join(' | ')).toBeTrue();
        expect(rows[1]).toBe(`Detection content n/a not applicable in ${label}: SigmaHQ coverage, MITRE CAR layer and CAR seed have Enterprise ATT&CK data only`);
        expect(rows[4]).toBe(`Atomic tests n/a not applicable in ${label}: Atomic Red Team has Enterprise ATT&CK data only`);
        expect(known.querySelectorAll('[data-testid="ev-known-na"]').length).toBe(4);
        for (const r of rows.slice(1)) expect(r).not.toMatch(/\b0\b/);
        const kev = el.querySelector('[data-testid="ev-kev"]')!;
        expect(kev.getAttribute('data-kev-state')).toBe('not-applicable');
        expect(text(kev)).toContain(`KEV-linked CVEs: not applicable in ${label}`);
        expect(idleTasks.length).withContext('no KEV request outside Enterprise').toBe(0);
      });
    }
  });

  describe('the swatch beside Why this colour (design 4.5)', () => {
    it('a legacy relative lens shows the cell colour from its ramp, with the band in words', () => {
      const el = render(state(), false, 'frequency');   // 3 of max 6: the 50-74% quartile
      const ramp = heatmapModeDef('frequency')!.ramp.stops;
      const swatch = el.querySelector<HTMLElement>('[data-testid="ev-swatch"]')!;
      expect(swatch).not.toBeNull();
      expect(swatch.getAttribute('aria-hidden')).toBe('true');
      expect(swatch.style.backgroundColor).toBe(hexToRgb(ramp[3].color));
      expect(text(el.querySelector('[data-testid="ev-band"]'))).toBe(`(band ${ramp[3].label} of the highest)`);
    });

    it('a registry lens shows the colour its colour function gives the cell', () => {
      const el = render(state(), true, 'posture');
      const swatch = el.querySelector<HTMLElement>('[data-testid="ev-swatch"]');
      expect(swatch).not.toBeNull();
      expect(swatch!.style.backgroundColor).not.toBe('');
      expect(el.querySelector('[data-testid="ev-score-on-matrix"]')).toBeNull();
    });

    it('a lens with no score outside the matrix shows no swatch and offers the matrix', () => {
      const el = render(state(), false, 'sigma');
      expect(el.querySelector('[data-testid="ev-swatch"]')).toBeNull();
      const open = el.querySelector<HTMLButtonElement>('[data-testid="ev-score-on-matrix"]')!;
      expect(text(open)).toBe('This lens is scored on the matrix: open it there');
      open.click();
      expect(panelOpen).toHaveBeenCalledOnceWith('matrix', { keepTechniqueSelection: true });
    });

    it('legacySwatch follows the cell renderer: zero stop, quartiles, coverage colours, viridis when colour-blind safe', () => {
      const freq = heatmapModeDef('frequency')!;
      const stops = freq.ramp.stops;
      const opts = { coverageColors: ['#c0', '#c1', '#c2', '#c3', '#c4'], colorblindSafe: false };
      expect(legacySwatch(freq, 0, 10, opts)).toEqual({ color: stops[0].color, band: `band ${stops[0].label}` });
      expect(legacySwatch(freq, 1, 10, opts)!.color).toBe(stops[1].color);
      expect(legacySwatch(freq, 3, 10, opts)!.color).toBe(stops[2].color);
      expect(legacySwatch(freq, 6, 10, opts)!.color).toBe(stops[3].color);
      expect(legacySwatch(freq, 10, 10, opts)!.color).toBe(stops[4].color);
      expect(legacySwatch(freq, 6, 10, { ...opts, colorblindSafe: true })!.color).toBe(SAFE_SEQ[2]);
      const coverage = heatmapModeDef('coverage')!;
      expect(legacySwatch(coverage, 2, 4, opts)).toEqual({ color: '#c2', band: 'band 2' });
      expect(legacySwatch(coverage, 9, 4, opts)).toEqual({ color: '#c4', band: 'band 4+' });
      expect(legacySwatch(heatmapModeDef('epss')!, 1, 1, opts)).withContext('a ramp the card cannot place a score on').toBeNull();
    });
  });
});

/** '#0ea5e9' as the browser reports an inline background colour. */
function hexToRgb(hex: string): string {
  const n = parseInt(hex.slice(1), 16);
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`;
}
