// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The technique evidence card (Phase 2 design §3 P2-18, E2.3-b): why a
// technique has its colour, and the evidence behind it, rung by rung.
//
//   Why this colour  lensExplain(def, cell) on the lens on screen
//   Proven           each proof record: rule, date, source, outcome, lab, stale
//   Runs without proof  each run of yours that yields no proof: status and date (RP-F decision 9)
//   Covered          each mark: qualifier, basis, via; Confirm on a breadth partial,
//                    "Record a run" on a range telemetry partial (RP-F decision 31)
//   Known            the five reference families with counts and sources
//   Threat           the threat profile's actors using it; KEV-linked CVEs
//
// The Proven and Covered blocks render only when PostureService.ownerWords()
// is true (§1.3), so a fresh profile shows Known and Threat only; their titles
// come from the vocabulary module. The card is OnPush and every value is a
// computed over signals: the drawer that hosts it is large and eager.
import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import type { Technique } from '../../models/technique';
import type { CoveredMark } from '../../models/posture/posture.types';
import {
  type LensCell, type LensContext, heatmapModeDef, lensAvailability,
} from '../../models/heatmap-modes';
import { lensOnScreen } from '../../models/lens-registry';
import { KNOWN_FAMILY_COUNT, basisWords, lensExplain, provenNoneLine } from '../../models/lens-explain';
import { PROVEN, lensLabel, proofLine } from '../../models/posture/posture-vocabulary';
import { notCreditedWords, partialMarkWords, recordRunTooltip } from '../../models/posture/partial-cause';
import { NOT_EXECUTED_WORDS, attackResultWords } from '../../models/posture/fired-rules';
import { runTime, validationDay } from '../../models/local-date';
import { POSTURE_TODAY } from '../../models/posture/posture-today';
import { refForTechnique, techniqueRefKey } from '../../models/technique-ref';
import { DataService } from '../../services/data.service';
import { DEFAULT_HEATMAP_MODE, FilterService } from '../../services/filter.service';
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

const DAY_MS = 86_400_000;

/**
 * Legacy lenses whose whole score is one runtime layer (SourceRegistry id). When
 * that layer failed to load, every cell scores 0 and the card would say
 * 'score 0 of max 1', a number that reads as "no rules"; it says n/a and why
 * instead (RP-F item 6). Sigma: the SigmaHQ coverage layer.
 */
export const LENS_LOAD_SOURCES: Readonly<Partial<Record<string, string>>> = {
  sigma: 'sigmahq-coverage',
};
/** KEV-linked CVE ids listed by name; the count covers the rest. */
const KEV_LISTED = 5;

/**
 * A legacy lens's score from the loaded domain alone, for when the matrix has
 * not scored it (the technique page in a new context): the lenses whose score
 * is a relationship count in the bundle. Null for every other lens.
 */
function domainScore(mode: string, t: Technique, domain: NonNullable<ReturnType<DataService['getCurrentDomain']>>, coverageTop: number): { score: number; max: number } | null {
  const fromMap = (m: ReadonlyMap<string, readonly unknown[]>) => {
    let max = 0;
    for (const v of m.values()) max = Math.max(max, v.length);
    return { score: m.get(t.id)?.length ?? 0, max: Math.max(1, max) };
  };
  switch (mode) {
    case 'coverage': return { score: Math.min(Math.max(t.mitigationCount, 0), coverageTop), max: coverageTop };
    case 'frequency': return fromMap(domain.groupsByTechnique);
    case 'software': return fromMap(domain.softwareByTechnique);
    case 'campaign': return fromMap(domain.campaignsByTechnique);
    default: return null;
  }
}

@Component({
  selector: 'app-technique-evidence-card',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './technique-evidence-card.component.html',
  styleUrl: './technique-evidence-card.component.scss',
})
export class TechniqueEvidenceCardComponent {
  readonly technique = input.required<Technique>();

  private readonly posture = inject(PostureService);
  private readonly data = inject(DataService);
  private readonly enrichment = inject(EnrichmentService);
  private readonly matrixControl = inject(MatrixControlService);
  private readonly cve = inject(CveService);
  private readonly attackCve = inject(AttackCveService);
  private readonly settings = inject(SettingsService);
  private readonly marks = inject(TechniqueMarksService);
  private readonly today = inject(POSTURE_TODAY);
  private readonly sources = inject(SourceRegistryService);
  private readonly recordRuns = inject(RecordRunRequestService);
  private readonly sourceRecords = toSignal(this.sources.records$, { initialValue: this.sources.all() });

  private readonly domain = toSignal(this.data.domain$, { initialValue: null });
  private readonly domainId = toSignal(this.data.currentDomain$, { initialValue: this.data.getCurrentAttackDomain() });
  private readonly mode = toSignal(inject(FilterService).heatmapMode$, { initialValue: DEFAULT_HEATMAP_MODE });
  private readonly threatProfile = inject(ThreatProfileService);
  private readonly profile = toSignal(this.threatProfile.profile$, { initialValue: null });
  private readonly settingsNow = toSignal(this.settings.settings$, { initialValue: null });
  private readonly kevLoaded = toSignal(this.cve.kevLoaded$, { initialValue: false });
  private readonly kevScores = toSignal(this.cve.kevTechScores$, { initialValue: new Map<string, number>() });
  private readonly cvesLoaded = toSignal(this.attackCve.loaded$, { initialValue: false });

  /** Block titles: the rung words come from the vocabulary module. */
  readonly provenTitle = PROVEN;
  readonly coveredTitle = lensLabel('covered');
  readonly knownFamilies = KNOWN_FAMILY_COUNT;

  /** Covered and Proven words may render (§1.3). */
  readonly ownerWords = this.posture.ownerWords;

  /** The technique's PostureState; follows every owner store and the Known sources (PostureService.states). */
  readonly state = computed(() => this.posture.stateFor(this.technique()));

  /** The lens on screen: an owner-word lens falls back to the default while its name may not render. */
  private readonly lens = computed(() =>
    heatmapModeDef(lensOnScreen(this.mode(), this.ownerWords(), DEFAULT_HEATMAP_MODE)) ?? heatmapModeDef(DEFAULT_HEATMAP_MODE)!);

  /** Why this colour: the lens's label and one sentence from lensExplain. */
  readonly why = computed(() => {
    const def = this.lens();
    const t = this.technique();
    const state = this.state();
    const availability = lensAvailability(def, this.domainId());
    if (!availability.available) return { lens: def.label, text: `n/a in this domain: ${availability.reason}` };
    const failed = this.failedLayer(def.value);
    if (failed) return { lens: def.label, text: `n/a: ${failed.name} did not load (${failed.lastError ?? 'unknown error'}), so no count is known` };
    let cell: LensCell | null = null;
    let max: number | null = null;
    if (def.project) {
      cell = def.project(this.lensContext(), t);
    } else {
      const readout = this.matrixControl.legacyReadout();
      const domain = this.domain();
      this.settingsNow();
      const scored = readout && readout.techId === t.id && readout.mode === def.value
        ? readout
        : domain ? domainScore(def.value, t, domain, Math.max(1, this.settings.getCoverageColors().length - 1)) : null;
      if (scored) { cell = { score: scored.score }; max = scored.max; }
    }
    return { lens: def.label, text: lensExplain(def, cell, { state, max, decayDays: this.posture.decayDays() }) };
  });

  /** The failed runtime layer a lens's whole score depends on (LENS_LOAD_SOURCES), or null. */
  private failedLayer(mode: string): { name: string; lastError: string | null } | null {
    const id = LENS_LOAD_SOURCES[mode];
    if (!id) return null;
    const record = this.sourceRecords().find(r => r.id === id);
    return record?.status === 'failed' ? { name: record.name, lastError: record.lastError } : null;
  }

  /** The Known reference families: count and source of each, and how many are mapped. */
  readonly known = computed(() => {
    this.state();   // the Known sources' revision: PostureService.states tracks SourceRegistry records
    const domain = this.domain();
    const c = this.enrichment.referenceDefenseCounts(this.technique(), domain);
    const bundle = domain ? `${domain.name} ${domain.attackVersion}` : 'the loaded ATT&CK bundle';
    const rows = [
      { family: 'ATT&CK mitigations', count: c.mitigations, source: bundle },
      { family: 'Detection content', count: c.sigma + c.car, source: `SigmaHQ rules ${c.sigma}, MITRE CAR analytics ${c.car}` },
      { family: 'Control mappings', count: c.controls, source: 'CTID: NIST 800-53, CRI, CIS, CSA CCM, M365' },
      { family: 'D3FEND countermeasures', count: c.d3fend, source: 'MITRE D3FEND' },
      { family: 'Atomic tests', count: c.atomic, source: 'Atomic Red Team' },
    ];
    return { mapped: rows.filter(r => r.count > 0).length, rows };
  });

  /** The Proven block: every qualifying proof record, best first. Empty while no owner words. */
  readonly proofs = computed(() => {
    if (!this.ownerWords()) return [];
    const windows = this.posture.decayDays();
    const now = this.today().getTime();
    return this.state().proof.map(p => {
      const t = runTime(p.date);
      const age = t === null ? null : Math.max(0, Math.floor((now - t) / DAY_MS));
      return {
        key: `${p.runId}|${p.detectionRef}|${p.date}`,
        line: proofLine(p), rule: p.detectionRef, date: validationDay(p.date), outcome: p.outcome, source: p.source,
        lab: p.scope === 'range', stale: age !== null && age > windows[p.scope], window: windows[p.scope],
      };
    });
  });

  /**
   * The Proven block's line when it lists no proof record (RP-F decision 28): 'No
   * recorded detection for this technique', or, beside a run that fired a rule
   * without proof, that run's date and status (provenNoneLine, the Proven lens's words).
   */
  readonly provenEmpty = computed(() => provenNoneLine(this.state()));

  /**
   * The runs of yours on the technique that yield no proof (RP-F decision 9), newest
   * first: 'untested on 10/21/26 (source manual); failed on ...', or '' with none.
   * A run that lists fired rules says how many, as the Validation pill does
   * ('untested on 10/15/26 (source manual, 1 rule fired)', RP-F decision 28).
   * The Proven block stays proof-only (P2-14); this line names each run's status
   * and date, never a rung, so it renders whether or not owner words may render.
   * Every date on the card is the local day the Detection Validation pill prints
   * (validationDay, RP-F decision 16), never the UTC day of the ISO timestamp.
   */
  readonly runsWithoutProof = computed(() =>
    this.state().runsWithoutProof.map(r => {
      const n = r.rulesFired ?? 0;
      const fired = n > 0 ? `, ${n} rule${n === 1 ? '' : 's'} fired` : '';
      // RP-F decision 44: a run whose attack did not execute says so, never a fired count.
      const notRun = r.notExecuted ? `, ${NOT_EXECUTED_WORDS}: ${attackResultWords(r.notExecuted)}` : '';
      return `${r.status} on ${validationDay(r.date)} (source ${r.source}${fired}${notRun})`;
    }).join('; '));

  /**
   * The Covered block's lines for the range runs whose attack did not execute (RP-F
   * decision 44): 'range run on 10/21/26 did not execute (errored): not credited'. Their
   * rows credit no mark, so the block names them instead. Empty while no owner words.
   */
  readonly notCredited = computed(() => {
    if (!this.ownerWords()) return [];
    return this.state().runsWithoutProof.map(notCreditedWords).filter((w): w is string => w !== null);
  });

  /**
   * True when the card lists a run of yours: a proof record in the Proven block or
   * the Runs-without-proof line (RP-F decision 16). The Covered block's empty line
   * then stays out, so no block says nothing of yours is recorded beside a run.
   */
  readonly listsRun = computed(() => this.proofs().length > 0 || this.runsWithoutProof() !== '');

  /**
   * The Covered block: every mark with its qualifier, basis and via. Empty while no owner words.
   * The action on a partial mark follows its typed cause (RP-F decision 31), never its words:
   * - a breadth partial (partialCause 'breadth') offers P2-16's Confirm while the state is partial;
   * - a range telemetry partial (partialCause 'telemetry') never offers Confirm (range
   *   telemetry with no alerting detection is not the owner's to attest); it offers
   *   "Record a run", which opens Detect > Validation on the technique.
   * Each partial mark names its cause in the words of partial-cause.ts (`cause`), and the
   * "Record a run" tooltip starts with them (RP-F decision 35): a telemetry row whose rule
   * alerted or blocked says so, and says it is not proof, as the why line and the cell do.
   */
  readonly coveredMarks = computed(() => {
    if (!this.ownerWords()) return [];
    const state = this.state();
    return state.covered.map((m, i) => ({
      key: `${i}|${m.basis}|${m.via ?? ''}|${m.source}`,
      qualifier: m.qualifier, basis: basisWords(m.basis), via: m.via ?? null, strength: m.strength, source: m.source,
      at: m.at ? validationDay(m.at) : null,
      canConfirm: confirmable(m) && state.bucket === 'partial',
      canRecordRun: m.strength === 'partial' && m.partialCause === 'telemetry',
      cause: partialMarkWords(m),
      recordRunTitle: m.partialCause === 'telemetry' ? recordRunTooltip(m) : null,
    }));
  });

  /**
   * The Threat block: the threat profile's actors using the technique, every group in
   * the bundle, KEV-linked CVEs. Both counts are on one basis, direct uses of this
   * technique (RP-F decision 28: the profile line rolled sub-technique uses up while
   * the bundle line did not); the profile's roll-up over sub-techniques, the basis of
   * its threat weight, is shown only when larger, and labelled as such.
   */
  readonly threat = computed(() => {
    const t = this.technique();
    const domain = this.domain();
    const profile = this.profile();
    this.cvesLoaded();
    const kevLoaded = this.kevLoaded();
    const kevIds = kevLoaded
      ? [...new Set(this.attackCve.getCvesForTechnique(t.attackId).map(c => c.cveId))].filter(id => this.cve.isKev(id))
      : [];
    return {
      // RP-F decision 6: when some stored groups have no use in this domain, the line names
      // them (the one shared sentence, ThreatProfileService.domainNotice) instead of the
      // narrowed label; otherwise the label is unchanged.
      profileLabel: profile ? (this.threatProfile.domainNotice() ?? profile.label) : null,
      profileActors: profile ? profile.usedByDirect(t.id) : [],
      // A parent counts its sub-techniques' uses too; a sub-technique has no roll-up of its own.
      profileRollup: profile && !t.isSubtechnique ? profile.usedBy(t.id).length : 0,
      bundleGroups: domain?.groupsByTechnique.get(t.id)?.length ?? 0,
      kevLoaded,
      kevCount: Math.max(this.kevScores().get(t.attackId) ?? 0, kevIds.length),
      kevIds: kevIds.slice(0, KEV_LISTED),
    };
  });

  /** What a registry lens reads to project the technique, as the matrix builds it (minimap colours: dark, not CVD). */
  private lensContext(): LensContext {
    const domain = this.domain();
    return {
      posture: (t) => this.posture.stateFor(t),
      known: (t) => this.enrichment.referenceDefenseSignals(t, domain),
      knownCounts: (t) => {
        const c = this.enrichment.referenceDefenseCounts(t, domain);
        return { mitigations: c.mitigations, detectionContent: c.sigma + c.car, controls: c.controls, d3fend: c.d3fend, atomic: c.atomic };
      },
      implView: (t) => this.posture.implViewFor(t),
      theme: 'dark',
      colorblindSafe: false,
    };
  }

  /**
   * Confirm for this technique (P2-16's path): a 'technique-confirmed' mark (source
   * 'manual') naming the broad mitigation. Only a breadth partial's `via` is accepted
   * (RP-F decision 31): Confirm never mints a mark 'via <range rule>'.
   */
  confirm(via: string): void {
    if (!this.state().covered.some(m => confirmable(m) && m.via === via)) return;
    const domain = this.data.getCurrentDomain();
    if (!domain) return;
    const ref = techniqueRefKey(refForTechnique(this.technique(), this.data.getCurrentAttackDomain(), domain.attackVersion));
    this.marks.confirm(ref, { via });
  }

  /** "Record a run" on a range telemetry partial (RP-F decision 31): Detect > Validation, the technique preselected. */
  recordRun(): void {
    this.recordRuns.request(this.technique().attackId);
  }
}

/** A mark Confirm may name (RP-F decision 31): a breadth partial with a `via`. */
function confirmable(m: CoveredMark): boolean {
  return m.strength === 'partial' && m.partialCause === 'breadth' && !!m.via;
}
