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
//   Known            the five reference families with counts and sources; a
//                    family whose sources have no data for the domain reads
//                    "not applicable in <domain>", never 0 (SOURCE_DOMAINS); the
//                    D3FEND row reads loading while the technique's live D3FEND
//                    call is on its way and "did not load · Retry" when it failed,
//                    never the bundled seed's count (technique page design 4.4)
//   Threat           the threat profile's actors using it; KEV-linked CVEs, with
//                    the KEV catalogue asked for on idle after the first render
//                    (loading, the count, or failed with Retry; technique page
//                    design 4.6); each listed CVE is its id and KEV name, linked
//                    to its dossier (design 4.3)
//
// Beside "Why this colour" a swatch shows the colour the lens gives the
// technique, with its band in words. The categorical F3 Origin lens names the
// technique's category itself. On the technique page (surface 'page'), a scored
// lens the card cannot score outside the matrix offers the matrix instead of a
// swatch; the drawer, which is on the matrix, never offers it.
//
// The surface input ('drawer' or 'page') is the card's only drawer-versus-page
// switch (technique page design 4.1 rule 2); the page's wide layout is a
// container query on the page host's 'tpage' container, not a check of the host.
//
// The Proven and Covered blocks render only when PostureService.ownerWords()
// is true (§1.3), so a fresh profile shows Known and Threat only; their titles
// come from the vocabulary module. The card is OnPush and every value is a
// computed over signals: the drawer that hosts it is large and eager.
import {
  ChangeDetectionStrategy, Component, DestroyRef, InjectionToken, afterNextRender, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import type { Technique } from '../../models/technique';
import type { CoveredMark } from '../../models/posture/posture.types';
import {
  type HeatmapModeDef, type LensCell, type LensContext, heatmapModeDef, lensAvailability,
} from '../../models/heatmap-modes';
import { lensOnScreen, registryColor } from '../../models/lens-registry';
import { type LensSourceId, domainLabel, notApplicableWords, sourceDomainOf } from '../../models/lens-sources';
import { SAFE_SEQ } from '../../models/safe-palette';
import { KNOWN_FAMILY_COUNT, basisWords, lensExplain, provenNoneLine } from '../../models/lens-explain';
import { PROVEN, lensLabel, proofLine } from '../../models/posture/posture-vocabulary';
import { notCreditedWords, partialMarkWords, recordRunTooltip } from '../../models/posture/partial-cause';
import { notExecutedNote } from '../../models/posture/fired-rules';
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
import { D3fendService } from '../../services/d3fend.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { SettingsService } from '../../services/settings.service';
import { TechniqueMarksService } from '../../services/technique-marks.service';
import { SourceRegistryService } from '../../services/source-registry.service';
import { RecordRunRequestService } from '../../services/record-run-request.service';
import { ThemeService } from '../../services/theme.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { SourceRetryService } from '../../services/source-retry.service';

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

/** The sources behind each Known family: a family none of whose sources has data for the domain is not applicable there. */
const KNOWN_FAMILY_SOURCES: Readonly<Record<'mitigations' | 'detection' | 'controls' | 'd3fend' | 'atomic', readonly LensSourceId[]>> = {
  mitigations: ['attack-bundle'],
  detection: ['sigmahq', 'car', 'car-seed'],
  controls: ['ctid-nist-800-53', 'ctid-cri', 'cis-controls', 'ctid-csa-ccm', 'ctid-m365'],
  d3fend: ['d3fend-seed'],
  atomic: ['atomic'],
};

/** The sources behind the KEV-linked CVE count: the KEV catalogue joined with the CTID CVE-to-technique mappings. */
const KEV_SOURCES: readonly LensSourceId[] = ['cisa-kev', 'ctid-attack-to-cve', 'ctid-kev'];

/**
 * The SourceRegistry ids the KEV line's Retry asks again, each through its
 * SOURCE_RETRY entry: the bundled snapshot, the live feed, each CTID dataset.
 */
const KEV_RETRY_SOURCES = ['cisa-kev-snapshot', 'cisa-kev', 'ctid-attack-to-cve', 'ctid-kev'] as const;

/** Runs `task` once the browser is idle; returns a cancel. */
export type IdleScheduler = (task: () => void) => () => void;

/**
 * When the card asks for the KEV catalogue (technique page design 4.6): on idle
 * after its first render, so the catalogue never competes with the first paint.
 * requestIdleCallback with a 2 s ceiling; a short timeout where it is missing.
 */
export const EVIDENCE_CARD_IDLE = new InjectionToken<IdleScheduler>('EVIDENCE_CARD_IDLE', {
  providedIn: 'root',
  factory: () => (task) => {
    if (typeof requestIdleCallback === 'function') {
      const handle = requestIdleCallback(() => task(), { timeout: 2000 });
      return () => cancelIdleCallback(handle);
    }
    const handle = setTimeout(task, 200);
    return () => clearTimeout(handle);
  },
});

/** A KEV-linked CVE the Threat block lists: its id and its KEV vulnerability name (technique page design 4.3). */
export interface KevCve {
  readonly id: string;
  readonly name: string;
}

/**
 * What the Threat block's KEV line says (technique page design 4.6): once loaded, the
 * count, the first KEV_LISTED CVEs by id and name, and how many more the count holds.
 */
export type KevView =
  | { readonly kind: 'not-applicable'; readonly text: string }
  | { readonly kind: 'loading'; readonly text: string }
  | { readonly kind: 'failed'; readonly text: string }
  | { readonly kind: 'loaded'; readonly count: number; readonly cves: readonly KevCve[]; readonly more: number };

/** Where the card is rendered: the matrix drawer or the technique page (design 4.1 rule 2). */
export type EvidenceCardSurface = 'drawer' | 'page';

/**
 * A threat-profile actor the Threat block names: its ATT&CK id and name, linked
 * (technique page design 4.3 L1). A group or campaign links to its ATT&CK page
 * (new tab) until the Intel panels take a selection (#/intel/actors?group=,
 * design PRs 2 to 4); a library-layer profile links to the library's layers.
 */
export interface ThreatActorRef {
  readonly key: string;
  readonly id: string;
  readonly name: string;
  /** The actor's ATT&CK page, or null for an in-app link (routerLink). */
  readonly href: string | null;
  readonly routerLink: string | null;
}

/** Where a Known family's live source stands while it has not answered: on its way, or failed (Retry). */
export type KnownRowState = 'loading' | 'failed' | null;

/** The swatch beside "Why this colour": the cell colour and its band in words ('' when the why line names it). */
export interface LensSwatch {
  readonly color: string;
  readonly band: string;
}

/**
 * The colour the matrix gives a legacy lens's score, read from the lens's
 * declared ramp (HeatmapModeDef.ramp holds the renderer's colours, in its order):
 * a relative ramp picks the zero stop or a quartile of the domain's highest
 * score, as TechniqueCellComponent.computeRelativeColor does (viridis when the
 * colour-blind setting is on); Mitigations mapped indexes the coverage colours by
 * count. Null for a ramp the card cannot place a score on.
 */
export function legacySwatch(
  def: Pick<HeatmapModeDef, 'value' | 'ramp'>,
  score: number, max: number, opts: { readonly coverageColors: readonly string[]; readonly colorblindSafe: boolean },
): LensSwatch | null {
  const stops = def.ramp.stops;
  if (def.value === 'coverage') {
    const colors = opts.coverageColors;
    if (!colors.length) return null;
    const i = score <= 0 ? 0 : Math.min(score, colors.length - 1);
    return { color: colors[i], band: `band ${stops[Math.min(i, stops.length - 1)]?.label ?? String(score)}` };
  }
  if (def.ramp.scale !== 'relative' || stops.length !== 5) return null;
  if (score <= 0) return { color: stops[0].color, band: `band ${stops[0].label}` };
  const ratio = max > 0 ? score / max : 0;
  const q = ratio >= 0.75 ? 3 : ratio >= 0.5 ? 2 : ratio >= 0.25 ? 1 : 0;
  return { color: opts.colorblindSafe ? SAFE_SEQ[q] : stops[q + 1].color, band: `band ${stops[q + 1].label} of the highest` };
}

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

/**
 * The category a categorical legacy lens gives the technique, read from its
 * formula, for the one such lens (F3 Origin: a T-prefixed id is shared with
 * ATT&CK, an F-prefixed id is fraud-native). Null for every other lens.
 */
function categoricalCell(def: Pick<HeatmapModeDef, 'value' | 'ramp' | 'project'>, t: Technique): { color: string; label: string } | null {
  if (def.project || def.ramp.scale !== 'categorical' || def.value !== 'f3-origin') return null;
  const stop = def.ramp.stops[t.attackId.startsWith('F') ? 1 : 0];
  return stop ? { color: stop.color, label: stop.label } : null;
}

@Component({
  selector: 'app-technique-evidence-card',
  standalone: true,
  imports: [RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './technique-evidence-card.component.html',
  styleUrl: './technique-evidence-card.component.scss',
})
export class TechniqueEvidenceCardComponent {
  readonly technique = input.required<Technique>();
  /** The host: 'drawer' (the matrix drawer, the default) or 'page' (the technique page). */
  readonly surface = input<EvidenceCardSurface>('drawer');

  private readonly posture = inject(PostureService);
  private readonly data = inject(DataService);
  private readonly enrichment = inject(EnrichmentService);
  private readonly matrixControl = inject(MatrixControlService);
  private readonly cve = inject(CveService);
  private readonly d3fend = inject(D3fendService);
  private readonly attackCve = inject(AttackCveService);
  private readonly settings = inject(SettingsService);
  private readonly marks = inject(TechniqueMarksService);
  private readonly today = inject(POSTURE_TODAY);
  private readonly sources = inject(SourceRegistryService);
  private readonly recordRuns = inject(RecordRunRequestService);
  private readonly panelNav = inject(PanelNavService);
  private readonly sourceRetry = inject(SourceRetryService);
  private readonly idle = inject(EVIDENCE_CARD_IDLE);
  private readonly destroyRef = inject(DestroyRef);
  private readonly isLight = toSignal(inject(ThemeService).isLight$, { initialValue: false });
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

  /**
   * The domain whose source data this technique reads (sourceDomainOf): an F3
   * technique with an Enterprise id shares Enterprise data, so only ICS, Mobile
   * and fraud-native F3 techniques read "not applicable".
   */
  private readonly sourceDomain = computed(() => sourceDomainOf(this.domainId(), this.technique().attackId));

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

  /**
   * Why this colour: the lens's label, one sentence from lensExplain, and the swatch
   * (the colour the lens gives the technique; technique page design 4.5). `offer` is
   * the per-lens reason the page offers the matrix, or null: only a scored lens the
   * card cannot score outside the matrix offers it, and only on the page (the drawer
   * is on the matrix). The categorical F3 Origin lens is never scored: the card names
   * the technique's category from its id instead.
   */
  readonly why = computed<{ lens: string; text: string; swatch: LensSwatch | null; offer: string | null }>(() => {
    const def = this.lens();
    const t = this.technique();
    const state = this.state();
    const availability = lensAvailability(def, this.domainId());
    if (!availability.available) return { lens: def.label, text: `n/a in this domain: ${availability.reason}`, swatch: null, offer: null };
    const failed = this.failedLayer(def.value);
    if (failed) {
      return { lens: def.label, text: `n/a: ${failed.name} did not load (${failed.lastError ?? 'unknown error'}), so no count is known`, swatch: null, offer: null };
    }
    const category = categoricalCell(def, t);
    if (category) return { lens: def.label, text: `${category.label}: ${def.formula}`, swatch: { color: category.color, band: '' }, offer: null };
    let cell: LensCell | null = null;
    let max: number | null = null;
    let swatch: LensSwatch | null = null;
    const colorblindSafe = this.settingsNow()?.colorblindSafe === true;
    if (def.project) {
      cell = def.project(this.lensContext(), t);
      if (def.color) swatch = { color: registryColor(def, cell, { theme: this.isLight() ? 'light' : 'dark', colorblindSafe }), band: '' };
    } else {
      const readout = this.matrixControl.legacyReadout();
      const domain = this.domain();
      const coverageColors = this.settings.getCoverageColors();
      const scored = readout && readout.techId === t.id && readout.mode === def.value
        ? readout
        : domain ? domainScore(def.value, t, domain, Math.max(1, coverageColors.length - 1)) : null;
      if (scored) {
        cell = { score: scored.score };
        max = scored.max;
        swatch = legacySwatch(def, scored.score, scored.max, { coverageColors, colorblindSafe });
      }
    }
    // A scored legacy lens with no score here: the matrix scores it. The drawer is on
    // the matrix (its readout arrives a moment later), so only the page offers it.
    const offer = cell === null && !def.project && def.ramp.scale !== 'categorical' && this.surface() === 'page'
      ? 'This lens is scored on the matrix: open it there'
      : null;
    return { lens: def.label, text: lensExplain(def, cell, { state, max, decayDays: this.posture.decayDays() }), swatch, offer };
  });

  /** The failed runtime layer a lens's whole score depends on (LENS_LOAD_SOURCES), or null. */
  private failedLayer(mode: string): { name: string; lastError: string | null } | null {
    const id = LENS_LOAD_SOURCES[mode];
    if (!id) return null;
    const record = this.sourceRecords().find(r => r.id === id);
    return record?.status === 'failed' ? { name: record.name, lastError: record.lastError } : null;
  }

  /**
   * Where the technique's live D3FEND call stands (D3fendService.liveState; the
   * coordinator starts it in both hosts). Re-read on each SourceRegistry record:
   * the call begins, succeeds and fails on the 'd3fend-technique-api' source.
   */
  private readonly d3fendLive = computed(() => {
    this.sourceRecords();
    return this.d3fend.liveState(this.technique().attackId);
  });

  /** The Known reference families: count and source of each, and how many are mapped. */
  readonly known = computed(() => {
    this.state();   // the Known sources' revision: PostureService.states tracks SourceRegistry records
    const domain = this.domain();
    const c = this.enrichment.referenceDefenseCounts(this.technique(), domain);
    const bundle = domain ? `${domain.name} ${domain.attackVersion}` : 'the loaded ATT&CK bundle';
    const domainId = this.sourceDomain();
    const na = (family: keyof typeof KNOWN_FAMILY_SOURCES) => notApplicableWords(KNOWN_FAMILY_SOURCES[family], domainId);
    // The D3FEND count is the bundled seed's until the live call answers (T1037: 0, then 20):
    // while it is on its way the row says loading, after a failure "did not load", never that 0.
    const live = this.d3fendLive();
    const d3fendNa = na('d3fend');
    const d3fendState: KnownRowState = d3fendNa === null && (live === 'loading' || live === 'failed') ? live : null;
    const rows: readonly { family: string; short: string; count: number; source: string; na: string | null; state: KnownRowState }[] = [
      { family: 'ATT&CK mitigations', short: 'ATT&CK mitigations', count: c.mitigations, source: bundle, na: na('mitigations'), state: null },
      { family: 'Detection content', short: 'Detection content', count: c.sigma + c.car, source: `SigmaHQ rules ${c.sigma}, MITRE CAR analytics ${c.car}`, na: na('detection'), state: null },
      { family: 'Control mappings', short: 'Control mappings', count: c.controls, source: 'CTID: NIST 800-53, CRI, CIS, CSA CCM, M365', na: na('controls'), state: null },
      { family: 'D3FEND countermeasures', short: 'D3FEND', count: c.d3fend, source: 'MITRE D3FEND', na: d3fendNa, state: d3fendState },
      { family: 'Atomic tests', short: 'Atomic tests', count: c.atomic, source: 'Atomic Red Team', na: na('atomic'), state: null },
    ];
    const notApplicable = rows.filter(r => r.na !== null).length;
    const pending = rows.filter(r => r.state !== null).map(r => `${r.short} ${r.state === 'loading' ? 'loading' : 'did not load'}`);
    return {
      // A family that is not applicable, loading or failed is never counted as mapped, and never shows a 0.
      mapped: rows.filter(r => r.na === null && r.state === null && r.count > 0).length,
      rows,
      // ' (4 not applicable in ICS ATT&CK)', or '' when every family applies.
      notApplicable: notApplicable ? ` (${notApplicable} not applicable in ${domainLabel(domainId)})` : '',
      // ' · D3FEND loading' or ' · D3FEND did not load': the family the mapped count cannot speak for yet.
      pending: pending.length ? ` · ${pending.join(', ')}` : '',
    };
  });

  /** Retry on a failed D3FEND row: the data-health Retry (D3fendService.retryTechniqueApi) asks again. */
  retryD3fend(): void {
    this.d3fend.retryTechniqueApi(this.technique().attackId);
  }

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
      // RP-F decision 44: a run whose attack did not execute says so, never a fired count;
      // the words are the fired-rule helper's (notExecutedNote), not the card's own.
      const note = notExecutedNote(r.notExecuted);
      const notRun = note ? `, ${note}` : '';
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
      profileActors: profile ? this.actorRefs(profile.usedByDirect(t.id)) : [],
      // A parent counts its sub-techniques' uses too; a sub-technique has no roll-up of its own.
      profileRollup: profile && !t.isSubtechnique ? profile.usedBy(t.id).length : 0,
      bundleGroups: domain?.groupsByTechnique.get(t.id)?.length ?? 0,
      kevLoaded,
      kevCount: Math.max(this.kevScores().get(t.attackId) ?? 0, kevIds.length),
      kevIds: kevIds.slice(0, KEV_LISTED),
    };
  });

  /**
   * The threat profile's actors by ATT&CK id and name, linked (design 4.3 L1). A
   * profile names its actors (resolveProfile): a group or a campaign of the loaded
   * bundle, or the library layer a layer profile is.
   */
  private actorRefs(names: readonly string[]): ThreatActorRef[] {
    const domain = this.domain();
    const groups = new Map((domain?.groups ?? []).map(g => [g.name, g] as const));
    const campaigns = new Map((domain?.campaigns ?? []).map(c => [c.name, c] as const));
    return names.map((name): ThreatActorRef => {
      const g = groups.get(name);
      if (g) return { key: g.id, id: g.attackId, name, href: g.url || `https://attack.mitre.org/groups/${g.attackId}`, routerLink: null };
      const c = campaigns.get(name);
      if (c) return { key: c.id, id: c.attackId, name, href: c.url || `https://attack.mitre.org/campaigns/${c.attackId}`, routerLink: null };
      return { key: `layer|${name}`, id: 'library layer', name, href: null, routerLink: '/library/layers' };
    });
  }

  /** A KEV-linked CVE by id and name: its KEV vulnerability name, else its vendor and product. */
  private kevCve(id: string): KevCve {
    const entry = this.cve.getKevEntry(id);
    const name = entry?.vulnerabilityName?.trim() || [entry?.vendorProject, entry?.product].filter(Boolean).join(' ');
    return { id, name: name || 'listed in the CISA KEV catalogue' };
  }

  /**
   * The KEV line (technique page design 4.6). Never "not loaded in this session" and
   * never a bare 0 for a catalogue that has not arrived: not applicable outside
   * Enterprise; loading while the catalogue or the CVE-to-technique mappings are on
   * their way; failed (with Retry) when the live feed and the bundled snapshot both
   * failed, or both CTID mapping datasets did; else the count.
   */
  readonly kev = computed<KevView>(() => {
    const na = notApplicableWords(KEV_SOURCES, this.sourceDomain());
    if (na) return { kind: 'not-applicable', text: `KEV-linked CVEs: ${na}` };
    const records = this.sourceRecords();
    const failed = (id: string) => records.find(r => r.id === id)?.status === 'failed';
    const threat = this.threat();
    if (!threat.kevLoaded) {
      if (failed('cisa-kev') && failed('cisa-kev-snapshot')) {
        return { kind: 'failed', text: 'KEV catalogue unavailable: the live feed and the bundled snapshot both failed' };
      }
      return { kind: 'loading', text: 'KEV-linked CVEs: loading the CISA KEV catalogue…' };
    }
    if (!this.cvesLoaded()) {
      if (failed('ctid-attack-to-cve') && failed('ctid-kev')) {
        return { kind: 'failed', text: 'KEV-linked CVEs unavailable: the CTID CVE-to-technique mappings did not load' };
      }
      return { kind: 'loading', text: 'KEV-linked CVEs: loading the CTID CVE-to-technique mappings…' };
    }
    const cves = threat.kevIds.map(id => this.kevCve(id));
    return { kind: 'loaded', count: threat.kevCount, cves, more: Math.max(0, threat.kevCount - cves.length) };
  });

  /** The KEV line for the template: its state, its words, and once loaded the count, the listed CVEs and how many more. */
  readonly kevLine = computed(() => {
    const k = this.kev();
    return k.kind === 'loaded'
      ? { kind: k.kind, text: '', count: k.count, cves: k.cves, more: k.more }
      : { kind: k.kind, text: k.text, count: 0, cves: [] as readonly KevCve[], more: 0 };
  });

  /** Set after the first render: the KEV ask waits for it. */
  private readonly rendered = signal(false);
  private kevAsked = false;

  constructor() {
    afterNextRender(() => this.rendered.set(true));
    // Ask for the KEV catalogue on idle after the first render, once, and only in a
    // domain whose techniques it maps (Enterprise). The drawer inherits this: its KEV
    // line used to wait for a lens that loads KEV (technique page design 4.6).
    effect(() => {
      if (!this.rendered() || this.kev().kind === 'not-applicable') return;
      untracked(() => this.askKev());
    });
  }

  private askKev(): void {
    if (this.kevAsked) return;
    this.kevAsked = true;
    const cancel = this.idle(() => this.cve.loadKev());
    this.destroyRef.onDestroy(cancel);
  }

  /**
   * Retry on a failed KEV line, through the data-health Retry (SourceRetryService):
   * every KEV source that failed, each by its own entry, so the bundled snapshot is
   * asked again directly while the live feed is still failing. The loaders record
   * the outcome on the SourceRegistry, so a Retry that fails again reads failed
   * again, never 0.
   */
  retryKev(): void {
    const records = this.sourceRecords();
    for (const id of KEV_RETRY_SOURCES) {
      if (records.find(r => r.id === id)?.status === 'failed') this.sourceRetry.retry(id);
    }
  }

  /** "Score it on the matrix": the matrix, with this technique's drawer open on the same lens. */
  openInMatrix(): void {
    this.panelNav.open('matrix', { keepTechniqueSelection: true });
  }

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
