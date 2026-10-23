// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// PostureService (Phase 2 design §3 P2-05, E2.1-c): the one signal seam that
// turns the owner-data stores into one PostureState per technique of the
// loaded domain (§2.2). Read-only: it never writes a store. Its inputs are
// all bridged with toSignal, and every derived value is a `computed`, so a
// store write, a settings change (the D16 threshold, the D10 windows), a
// domain switch or a new day recomputes exactly once.
//
// No surface reads it yet except the matrix banner predicate (ownerWords);
// the count surfaces move to it in P2-07 and P2-08, the risk seams in P2-09
// and the lenses in P2-13 to P2-15.
//
// Threat weight comes only through THREAT_WEIGHT_PROVIDER (Addendum note 2):
// this file never imports ThreatProfileService; P2-10 binds it.
import { Injectable, Signal, computed, inject } from '@angular/core';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import { Observable } from 'rxjs';
import type { Domain } from '../models/domain';
import type { Technique } from '../models/technique';
import type {
  CoveredMark, PostureInputs, PostureRules, PostureState, PostureTally, ProofRecord, ProofScope, RunSummary, RunVerdict,
} from '../models/posture/posture.types';
import { DEFAULT_POSTURE_RULES, derivePosture, tallyPosture } from '../models/posture/derive-posture';
import { type PartialCauseTally, tallyPartialCauses } from '../models/posture/partial-cause';
import { type CoveredSourceTally, tallyCoveredSources } from '../models/posture/covered-source';
import { hasOwnerWords } from '../models/posture/posture-vocabulary';
import { THREAT_WEIGHT_PROVIDER } from '../models/posture/threat-weight';
import { POSTURE_TODAY } from '../models/posture/posture-today';
import { type TechniqueRefKey, refForTechnique, techniqueRefKey } from '../models/technique-ref';
import { AssetInventoryService } from './asset-inventory.service';
import { AttackIdResolverService } from './attack-id-resolver.service';
import { ControlsService } from './controls.service';
import { type AttackDomain, DataService } from './data.service';
import { EnrichmentService } from './enrichment.service';
import { EventLoggingService } from './event-logging.service';
import { type ImplStatus, ImplementationService } from './implementation.service';
import { type OwnerDataCounts, OwnerDataService } from './owner-data.service';
import {
  type ImplView, type RunInputs, type UnmatchedKey,
  controlsAdapter, implView, implementationAdapter, markKey, matchToTechniques, runInputsFor, techniqueMarkToCovered,
  telemetryMark,
} from './posture-adapters';
import { SettingsService } from './settings.service';
import { SourceRegistryService } from './source-registry.service';
import { type TechniqueMarkRecord, TechniqueMarksService } from './technique-marks.service';
import { TelemetryCoverageService, telemetryKey } from './telemetry-coverage.service';
import { ValidationService } from './validation.service';

/** A posture tally with the Known numbers of EnrichmentService.mappedRollup alongside. */
export interface PostureRollup {
  /**
   * `partialByCause` counts the partial techniques by their typed cause (RP-F decision
   * 36, tallyPartialCauses), so the Report Builder and the reports split the partial
   * card by cause instead of inferring one from the bucket. `coveredBySource` counts the
   * Covered techniques by source (RP-F decision 43, tallyCoveredSources), so the Covered
   * card names the range's and the owner's share. Both are absent in a hand-built rollup.
   */
  overall: PostureTally & { mapped: number; pct: number; partialByCause?: PartialCauseTally; coveredBySource?: CoveredSourceTally };
  byTactic: (PostureTally & { tacticId: string; tacticName: string; shortname: string; mapped: number; pct: number })[];
}

/** Days before a proof window lapses at which `expiringSoon` counts it (§7). */
export const EXPIRING_SOON_DAYS = 7;

const EMPTY_TALLY: PostureTally = {
  total: 0, assessable: 0, none: 0, known: 0, partial: 0, covered: 0, proven: 0, stale: 0, contradicted: 0, notReproducible: 0,
};

const NO_MARKS: readonly CoveredMark[] = [];

/** The mitigation maps of no domain: every mitigation key rolls up to nothing. */
const NO_DOMAIN: Pick<Domain, 'techniquesByMitigation' | 'mitigations'> = { techniquesByMitigation: new Map(), mitigations: [] };

@Injectable({ providedIn: 'root' })
export class PostureService {
  private readonly data = inject(DataService);
  private readonly resolver = inject(AttackIdResolverService);
  private readonly enrichment = inject(EnrichmentService);
  private readonly eventLog = inject(EventLoggingService);
  private readonly threatWeight = inject(THREAT_WEIGHT_PROVIDER);
  private readonly today = inject(POSTURE_TODAY);

  // ── Inputs (all bridged with toSignal) ─────────────────────────────────────
  private readonly domain = toSignal(this.data.domain$, { initialValue: null });
  private readonly domainId = toSignal(this.data.currentDomain$, { initialValue: 'enterprise' as AttackDomain });
  private readonly impl = toSignal(inject(ImplementationService).status$, { initialValue: new Map<string, ImplStatus>() });
  private readonly controls = toSignal(inject(ControlsService).controls$, { initialValue: [] });
  private readonly runs = toSignal(inject(ValidationService).runs$, { initialValue: [] });
  private readonly telemetry = toSignal(inject(TelemetryCoverageService).status$, { initialValue: new Set<string>() });
  private readonly marks = toSignal(inject(TechniqueMarksService).marks$, { initialValue: [] });
  private readonly settings = toSignal(inject(SettingsService).settings$);
  private readonly exposure = toSignal(inject(AssetInventoryService).exposureMap$, { initialValue: new Map<string, number>() });
  /** The Known-input revision trigger: reference sources finish loading after the domain (§3 P2-05). */
  private readonly knownRevision = toSignal(inject(SourceRegistryService).records$, { initialValue: [] });

  /** The display counts of the owner stores (OwnerDataService.counts$). */
  readonly ownerData: Signal<OwnerDataCounts> = toSignal(inject(OwnerDataService).counts$, {
    initialValue: { implementation: 0, validation: 0, stack: 0 },
  });

  // ── Derived ───────────────────────────────────────────────────────────────
  /** D16 threshold and D10 windows from settings (DEFAULT_POSTURE_RULES before settings load). */
  private readonly rules = computed<PostureRules>(() => {
    const p = this.settings()?.posture;
    if (!p) return DEFAULT_POSTURE_RULES;
    return { mitigationBreadthThreshold: p.mitigationBreadthThreshold, decayDays: { ...p.decayDays } };
  });

  private readonly threshold = computed(() => this.rules().mitigationBreadthThreshold);

  /** Classification needs no domain, so `unmatched()` is right before one loads. */
  private readonly implResult = computed(() =>
    implementationAdapter(this.impl(), this.domain() ?? NO_DOMAIN, this.threshold()));

  private readonly controlMarks = computed(() => {
    const domain = this.domain();
    return domain ? controlsAdapter(this.controls(), domain, this.threshold()) : new Map<string, readonly CoveredMark[]>();
  });

  /** Run inputs per technique STIX id of the loaded domain, matched by runMatches. */
  private readonly runInputsByTechnique = computed(() => {
    const domain = this.domain();
    const out = new Map<string, RunInputs[]>();
    if (!domain) return out;
    const matched = matchToTechniques(this.runs(), r => r, domain.techniques, this.domainId(), this.resolve);
    for (const [techId, runs] of matched) out.set(techId, runInputsFor(runs));
    return out;
  });

  /** Technique marks per technique STIX id of the loaded domain. */
  private readonly marksByTechnique = computed(() => {
    const domain = this.domain();
    if (!domain) return new Map<string, readonly TechniqueMarkRecord[]>();
    return matchToTechniques(this.marks(), markKey, domain.techniques, this.domainId(), this.resolve);
  });

  /** Every technique of the loaded domain (parents and sub-techniques), keyed by TechniqueRefKey. */
  readonly states: Signal<ReadonlyMap<TechniqueRefKey, PostureState>> = computed(() => {
    const domain = this.domain();
    const out = new Map<TechniqueRefKey, PostureState>();
    if (!domain) return out;
    this.knownRevision();
    this.threatWeight.revision();   // track the threat-weight source (P2-10: the bound profile) so a profile change recomputes states

    const domainId = this.domainId();
    const rules = this.rules();
    const now = this.today();
    const implMarks = this.implResult().marks;
    const controlMarks = this.controlMarks();
    const runs = this.runInputsByTechnique();
    const marks = this.marksByTechnique();
    const configured = this.telemetry();
    const exposure = this.exposure();
    for (const t of domain.techniques) {
      const covered: CoveredMark[] = [...(implMarks.get(t.id) ?? NO_MARKS), ...(controlMarks.get(t.id) ?? NO_MARKS)];
      for (const m of marks.get(t.id) ?? []) {
        const mark = techniqueMarkToCovered(m);
        if (mark) covered.push(mark);
      }
      const tele = telemetryMark(
        this.eventLog.getLoggingConfig(t.attackId).map(c => telemetryKey(c.source, c.eventId)),
        configured,
      );
      if (tele) covered.push(tele);
      const proof: ProofRecord[] = [];
      const verdicts: RunVerdict[] = [];
      const runSummaries: RunSummary[] = [];
      for (const r of runs.get(t.id) ?? []) {
        proof.push(...r.proof);
        covered.push(...r.covered);
        verdicts.push(...r.verdicts);
        runSummaries.push(r.summary);
      }
      const input: PostureInputs = {
        knownSignals: this.enrichment.referenceSignalCount(t, domain),
        covered, proof, verdicts, runs: runSummaries,
        threatWeight: this.threatWeight.weight(t.id),
        exposureWeight: domainId === 'enterprise' ? exposure.get(t.attackId) ?? 0 : 0,
      };
      const key = this.keyFor(t, domainId, domain);
      out.set(key, derivePosture(key, input, rules, now));
    }
    return out;
  });

  /** Guards every Covered/Proven render from P2-07 on (§2.4, Revision 3). */
  readonly ownerWords: Signal<boolean> = computed(() => hasOwnerWords(this.states().values()));

  /** Implementation-map keys that name no mitigation or technique: listed, never deleted. */
  readonly unmatched: Signal<readonly UnmatchedKey[]> = computed(() => this.implResult().unmatched);

  /** The D10 proof windows (days) the states are derived with; a stale cell names its window (§7). */
  readonly decayDays: Signal<Readonly<Record<ProofScope, number>>> = computed(() => this.rules().decayDays);

  /** Fresh proofs within EXPIRING_SOON_DAYS of their window (§7). */
  readonly expiringSoon: Signal<number> = computed(() => {
    const windows = this.rules().decayDays;
    let n = 0;
    for (const s of this.states().values()) {
      if (s.bucket !== 'proven' || s.proofScope === null || s.proofAge === null) continue;
      if (windows[s.proofScope] - s.proofAge <= EXPIRING_SOON_DAYS) n++;
    }
    return n;
  });

  /** toObservable bridge for the matrix (P2-13). */
  readonly states$: Observable<ReadonlyMap<TechniqueRefKey, PostureState>> = toObservable(this.states);

  private readonly resolve = (id: string): string => this.resolver.resolve(id);

  private keyFor(t: Pick<Technique, 'attackId'>, domainId: AttackDomain, domain: Domain | null): TechniqueRefKey {
    return techniqueRefKey(refForTechnique(t, domainId, domain?.attackVersion ?? ''));
  }

  /**
   * The state of one technique. A technique that is not in the loaded domain
   * (or before any domain loads) gets the empty derivation: no marks, no proof.
   */
  stateFor(t: Technique): PostureState {
    const domain = this.domain();
    const key = this.keyFor(t, this.domainId(), domain);
    return this.states().get(key) ?? derivePosture(key, {
      knownSignals: 0, covered: [], proof: [], verdicts: [], threatWeight: 0, exposureWeight: 0,
    }, this.rules(), this.today());
  }

  tallyFor(techs: readonly Technique[]): PostureTally {
    return tallyPosture(techs.map(t => this.stateFor(t)));
  }

  /**
   * The guarded implementation view of every technique of the loaded domain,
   * keyed by STIX id (P2-14): what the status lens, impl= and the exports
   * read, computed once per store, settings or domain change.
   */
  readonly implViews: Signal<ReadonlyMap<string, ImplView>> = computed(() => {
    const domain = this.domain();
    const out = new Map<string, ImplView>();
    if (!domain) return out;
    const impl = this.impl();
    const threshold = this.threshold();
    const marks = this.marksByTechnique();
    for (const t of domain.techniques) {
      out.set(t.id, implView(t, impl, domain, threshold, (marks.get(t.id) ?? []).map(m => m.status)));
    }
    return out;
  });

  /**
   * Techniques of the loaded domain whose only implemented mitigations are
   * broad (D16): 'implemented, partial via' on the status lens, matched by no
   * impl= value (P2-14). With the distinct broad mitigations, sorted.
   */
  readonly implPartialOnly: Signal<{ readonly count: number; readonly via: readonly string[] }> = computed(() => {
    let count = 0;
    const via = new Set<string>();
    for (const v of this.implViews().values()) {
      if (v.status !== 'implemented' || !v.partialVia) continue;
      count++;
      for (const m of v.partialVia.split(', ')) via.add(m);
    }
    return { count, via: [...via].sort() };
  });

  /** Guarded mitigation-implementation view per technique, for the status lens and impl= (P2-14). */
  implViewFor(t: Technique): ImplView {
    const cached = this.implViews().get(t.id);
    if (cached) return cached;
    const domain = this.domain();
    if (!domain) return { status: null, partialVia: null };
    const statuses = (this.marksByTechnique().get(t.id) ?? []).map(m => m.status);
    return implView(t, this.impl(), domain, this.threshold(), statuses);
  }

  /**
   * The posture rollup with the Known numbers alongside. R16: overall.total,
   * mapped and pct (and each tactic row's) are EnrichmentService.mappedRollup's
   * values unchanged, so Known numbers are identical by construction; an
   * excluded technique leaves `assessable` only.
   */
  rollup(opts: { includeSubtechniques?: boolean } = {}): PostureRollup {
    const domain = this.domain();
    const known = this.enrichment.mappedRollup(domain, opts);
    if (!domain) return { overall: { ...EMPTY_TALLY, ...known.overall }, byTactic: [] };
    this.knownRevision();
    const techs = opts.includeSubtechniques ? domain.techniques : domain.techniques.filter(t => !t.isSubtechnique);
    const overall = {
      ...this.tallyFor(techs), total: known.overall.total, mapped: known.overall.mapped, pct: known.overall.pct,
      partialByCause: tallyPartialCauses(techs.map(t => this.stateFor(t))),
      coveredBySource: tallyCoveredSources(techs.map(t => this.stateFor(t))),
    };
    const byTactic = (domain.tacticColumns ?? []).map((col, i) => {
      const row = known.byTactic[i];
      return {
        ...this.tallyFor(col.techniques),
        tacticId: col.tactic.id, tacticName: col.tactic.name, shortname: col.tactic.shortname,
        total: row.total, mapped: row.mapped, pct: row.pct,
      };
    });
    return { overall, byTactic };
  }
}
