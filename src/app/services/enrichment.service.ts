// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { Domain } from '../models/domain';
import { Technique } from '../models/technique';
import { type SignalFamilies, hasDefensiveReference } from '../models/known-signals';
import type { PostureBucket } from '../models/posture/posture.types';
import { SigmaService } from './sigma.service';
import { CARService } from './car.service';
import { AtomicService } from './atomic.service';
import { D3fendService } from './d3fend.service';
import { NistMappingService } from './nist-mapping.service';
import { CriProfileService } from './cri-profile.service';
import { CisControlsService } from './cis-controls.service';
import { CsaCcmService } from './csa-ccm.service';
import { M365ControlsService } from './m365-controls.service';
import { AttackCveService } from './attack-cve.service';

/**
 * Per-technique presence of each defensive / framework signal family.
 * Every flag is boolean "has ≥1", never a raw count, so no single framework's
 * volume dominates the headline.
 */
export interface EnrichmentSignals {
  mitigation: boolean;   // ATT&CK mitigation relationship (M-series)
  detection: boolean;    // Sigma + CAR analytic rules
  atomic: boolean;       // Atomic Red Team test
  d3fend: boolean;       // D3FEND countermeasure
  control: boolean;      // control-framework mapping (NIST/CRI/CIS/CSA/M365)
  threatIntel: boolean;  // threat-intel link (group / software / campaign)
  cve: boolean;          // CVE / KEV mapping
}

/**
 * Per-technique presence of each DEFENSIVE REFERENCE input: the Known rung of
 * plan 4.1 ("the world knows how to mitigate, detect or test it; no claim
 * about you"). These are exactly the inputs of the Reference depth lens
 * (models/reference-depth.ts): mitigations, detection content, CTID control
 * mappings, D3FEND and Atomic.
 *
 * There is deliberately no threat-intel or CVE field. Groups, software,
 * campaigns and CVE/KEV links say how much adversaries care, not what is
 * mapped to defend against it, so a Known-tier count must not move when a
 * group starts using a technique. The type has no field a threat signal could
 * flow through.
 */
export interface ReferenceDefenseSignals {
  mitigation: boolean;   // ATT&CK mitigation relationship (M-series)
  detection: boolean;    // detection content available: Sigma + CAR analytics
  control: boolean;      // CTID control-framework mapping (NIST/CRI/CIS/CSA/M365)
  d3fend: boolean;       // D3FEND countermeasure
  atomic: boolean;       // Atomic Red Team test
}

/** The counts behind ReferenceDefenseSignals (detection content is Sigma plus CAR). */
export interface ReferenceDefenseCounts {
  mitigations: number;   // ATT&CK mitigation relationships
  sigma: number;         // SigmaHQ rules
  car: number;           // MITRE CAR analytics
  controls: number;      // CTID control-framework mappings (NIST/CRI/CIS/CSA/M365)
  d3fend: number;        // D3FEND countermeasures
  atomic: number;        // Atomic Red Team tests
}

/** Known-tier aggregate across a set of techniques (defensive reference inputs only). */
export interface ReferenceDefenseTotals {
  total: number;
  mapped: number;        // >=1 defensive reference input (Known rung: 'mapped')
  mitigation: number;
  detection: number;
  control: number;
  d3fend: number;
  atomic: number;
}

/** Known-tier 'mapped' count over one set of techniques (defensive reference inputs only). */
export interface MappedCount {
  total: number;
  mapped: number;        // >=1 defensive reference input (Known rung: 'mapped')
  pct: number;           // mappedPct(mapped, total)
}

/** One tactic column's Known-tier 'mapped' count. */
export interface MappedTacticCount extends MappedCount {
  tacticId: string;      // tactic STIX id (the key timeline snapshots use)
  tacticName: string;
  shortname: string;
}

/**
 * The Known-tier 'mapped' rollup the summary surfaces show (E1.7): one overall
 * count and one count per tactic column, all from `isReferenceMapped()`.
 */
export interface MappedRollup {
  overall: MappedCount;
  byTactic: MappedTacticCount[];
}

/**
 * The one rounding every 'mapped %' uses, so two surfaces showing the same
 * count cannot print different percentages.
 */
export function mappedPct(mapped: number, total: number): number {
  return total > 0 ? Math.round((mapped / total) * 100) : 0;
}

/** Aggregate counts across a set of techniques, one flag family per column. */
export interface EnrichmentTotals {
  total: number;
  enriched: number;      // ≥1 of ANY family
  mitigation: number;
  detection: number;
  atomic: number;
  d3fend: number;
  control: number;
  threatIntel: number;
  cve: number;
  defended: number;      // mitigation OR detection OR control OR d3fend
}

/**
 * Per-technique signal families from the cross-framework reference data.
 *
 * Two different questions are answered here and must not be confused (plan
 * 4.1, epic E1.7):
 *
 * - Known tier ('mapped'): `referenceDefenseSignals()`, `isReferenceMapped()`
 *   and `referenceDefenseTotals()` read the defensive reference inputs only
 *   (mitigations, detection content, CTID controls, D3FEND, Atomic). Any count
 *   that describes defense uses these.
 * - Threat side: `signals()`, `signalCount()`, `totals()` and `coverage()`
 *   also mix in threat-intel links (groups, software, campaigns) and CVE
 *   mappings, so they rise when adversaries use a technique. They are kept for
 *   Threat-side counts only, never for a defensive summary. The yes/no tests
 *   over `signals()` are the pure `hasAnySignal()` and `hasDefensiveReference()`
 *   in models/known-signals.ts (P2-08 retired isEnriched and hasDefensiveSignal).
 *
 * Every service call is guarded: missing or unloaded data yields `false`,
 * never a throw.
 */
@Injectable({ providedIn: 'root' })
export class EnrichmentService {
  constructor(
    private sigmaService: SigmaService,
    private carService: CARService,
    private atomicService: AtomicService,
    private d3fendService: D3fendService,
    private nistMappingService: NistMappingService,
    private criProfileService: CriProfileService,
    private cisControlsService: CisControlsService,
    private csaCcmService: CsaCcmService,
    private m365ControlsService: M365ControlsService,
    private attackCveService: AttackCveService,
  ) {}

  /**
   * Whether the CTID ATT&CK-to-CVE mapping behind the CVE signal has loaded. It loads on
   * demand (the first read asks for it), so a view that shows the CVE count counts again
   * when this turns true.
   */
  cveMappingsLoaded$(): Observable<boolean> {
    return this.attackCveService.loaded$;
  }

  /** Guard a numeric service lookup — never let missing data throw. */
  private num(fn: () => number): number {
    try {
      const v = fn();
      return typeof v === 'number' && isFinite(v) ? v : 0;
    } catch {
      return 0;
    }
  }

  /** Guard an array/length service lookup — never let missing data throw. */
  private len(fn: () => { length: number } | null | undefined): number {
    try {
      return fn()?.length ?? 0;
    } catch {
      return 0;
    }
  }

  /** Count of threat-intel links (groups + software + campaigns) for a technique. */
  threatIntelCount(tech: Technique, domain?: Domain | null): number {
    if (!domain || !tech) return 0;
    const g = this.len(() => domain.groupsByTechnique?.get(tech.id));
    const s = this.len(() => domain.softwareByTechnique?.get(tech.id));
    const c = this.len(() => domain.campaignsByTechnique?.get(tech.id));
    return g + s + c;
  }

  /** Count of control-framework mappings (NIST + CRI + CIS + CSA + M365). */
  controlCount(attackId: string): number {
    return (
      this.num(() => this.nistMappingService.getControlCount(attackId)) +
      this.num(() => this.criProfileService.getControlCount(attackId)) +
      this.num(() => this.cisControlsService.getControlCount(attackId)) +
      this.num(() => this.csaCcmService.getControlCount(attackId)) +
      this.num(() => this.m365ControlsService.getControlCount(attackId))
    );
  }

  /**
   * Known tier: presence of each defensive reference input for one technique
   * (mitigations, detection content, CTID controls, D3FEND, Atomic). It never
   * reads the threat-intel (groups, software, campaigns) or CVE inputs, so
   * adding a group that uses a technique cannot change it. `domain` is read
   * only for the mitigation relationship, when the technique carries no
   * precomputed mitigationCount.
   */
  referenceDefenseSignals(tech: Technique, domain?: Domain | null): ReferenceDefenseSignals {
    if (!tech) {
      return { mitigation: false, detection: false, control: false, d3fend: false, atomic: false };
    }
    const c = this.referenceDefenseCounts(tech, domain);
    return {
      mitigation: c.mitigations > 0,
      detection: c.sigma + c.car > 0,
      control: c.controls > 0,
      d3fend: c.d3fend > 0,
      atomic: c.atomic > 0,
    };
  }

  /**
   * Known tier: the count behind each defensive reference input of one
   * technique (the numbers {@link referenceDefenseSignals} tests against 0).
   * The technique evidence card (P2-18) lists them with their sources.
   */
  referenceDefenseCounts(tech: Technique, domain?: Domain | null): ReferenceDefenseCounts {
    const id = tech.attackId;
    return {
      mitigations: (tech.mitigationCount ?? 0) || this.len(() => domain?.mitigationsByTechnique?.get(tech.id)),
      sigma: this.num(() => this.sigmaService.getRuleCount(id)),
      car: this.num(() => this.carService.getLiveCount(id)),
      controls: this.controlCount(id),
      d3fend: this.len(() => this.d3fendService.getCountermeasures(id)),
      atomic: this.num(() => this.atomicService.getTestCount(id)),
    };
  }

  /**
   * Known tier: whether a technique has at least one defensive reference input
   * mapped (the 'mapped' count on summary surfaces). Threat-independent.
   */
  isReferenceMapped(tech: Technique, domain?: Domain | null): boolean {
    const r = this.referenceDefenseSignals(tech, domain);
    return r.mitigation || r.detection || r.control || r.d3fend || r.atomic;
  }

  /** Known tier: aggregate defensive reference counts across a set of techniques in one pass. */
  referenceDefenseTotals(techs: readonly Technique[], domain?: Domain | null): ReferenceDefenseTotals {
    const t: ReferenceDefenseTotals = {
      total: 0, mapped: 0, mitigation: 0, detection: 0, control: 0, d3fend: 0, atomic: 0,
    };
    for (const tech of techs ?? []) {
      t.total++;
      const r = this.referenceDefenseSignals(tech, domain);
      if (r.mitigation) t.mitigation++;
      if (r.detection) t.detection++;
      if (r.control) t.control++;
      if (r.d3fend) t.d3fend++;
      if (r.atomic) t.atomic++;
      if (r.mitigation || r.detection || r.control || r.d3fend || r.atomic) t.mapped++;
    }
    return t;
  }

  /**
   * Known tier: how many of the five defensive reference inputs a technique
   * has (0-5). The breadth used to rank "most mapped" techniques; it never
   * counts threat-intel or CVE links.
   */
  referenceSignalCount(tech: Technique, domain?: Domain | null): number {
    const r = this.referenceDefenseSignals(tech, domain);
    return (
      (r.mitigation ? 1 : 0) + (r.detection ? 1 : 0) + (r.control ? 1 : 0) +
      (r.d3fend ? 1 : 0) + (r.atomic ? 1 : 0)
    );
  }

  /** Known tier: the 'mapped' count over one set of techniques. */
  mappedCount(techs: readonly Technique[], domain?: Domain | null): MappedCount {
    let total = 0;
    let mapped = 0;
    for (const tech of techs ?? []) {
      total++;
      if (this.isReferenceMapped(tech, domain)) mapped++;
    }
    return { total, mapped, pct: mappedPct(mapped, total) };
  }

  /**
   * Known tier: the single 'mapped' rollup every summary surface reads
   * (stats-bar, tactic-summary, analytics-panel, the timeline snapshots that
   * timeline-panel and coverage-diff-panel show, roadmap-panel and
   * dashboard-panel). One method and one filter, so the seven surfaces cannot
   * disagree (E1.7 equality spec).
   *
   * Filter: `overall` counts parent techniques, or every technique when
   * `includeSubtechniques` is set; each `byTactic` row counts that tactic
   * column's techniques (parents only, as TacticColumn holds them).
   *
   * P2 SEAM (E2.1, E9.3): PostureService's tactic rollup replaces this method
   * with Known / Covered / Proven per tactic. Each surface reaches its
   * defensive count only through here, so the swap is one call per surface.
   */
  mappedRollup(
    domain: Domain | null | undefined,
    opts: { includeSubtechniques?: boolean } = {},
  ): MappedRollup {
    if (!domain) return { overall: { total: 0, mapped: 0, pct: 0 }, byTactic: [] };
    const techs = opts.includeSubtechniques
      ? domain.techniques ?? []
      : (domain.techniques ?? []).filter((t) => !t.isSubtechnique);
    const byTactic = (domain.tacticColumns ?? []).map((col) => ({
      tacticId: col.tactic.id,
      tacticName: col.tactic.name,
      shortname: col.tactic.shortname,
      ...this.mappedCount(col.techniques, domain),
    }));
    return { overall: this.mappedCount(techs, domain), byTactic };
  }

  /**
   * Presence of each signal family for a single technique: the five defensive
   * reference inputs (from `referenceDefenseSignals()`) plus the threat-intel
   * and CVE inputs. Threat side; for a Known-tier view use
   * `referenceDefenseSignals()`.
   */
  signals(tech: Technique, domain?: Domain | null): EnrichmentSignals {
    if (!tech) {
      return {
        mitigation: false, detection: false, atomic: false, d3fend: false,
        control: false, threatIntel: false, cve: false,
      };
    }
    const id = tech.attackId;
    const r = this.referenceDefenseSignals(tech, domain);
    return {
      mitigation: r.mitigation,
      detection: r.detection,
      atomic: r.atomic,
      d3fend: r.d3fend,
      control: r.control,
      threatIntel: this.threatIntelCount(tech, domain) > 0,
      cve: this.len(() => this.attackCveService.getCvesForTechnique(id)) > 0,
    };
  }

  /** How many of the 7 signal families a technique carries (breadth of coverage). */
  signalCount(tech: Technique, domain?: Domain | null): number {
    const s = this.signals(tech, domain);
    return (
      (s.mitigation ? 1 : 0) + (s.detection ? 1 : 0) + (s.atomic ? 1 : 0) +
      (s.d3fend ? 1 : 0) + (s.control ? 1 : 0) + (s.threatIntel ? 1 : 0) + (s.cve ? 1 : 0)
    );
  }

  /** Aggregate signal-family counts across a set of techniques in one pass. */
  totals(techs: readonly Technique[], domain?: Domain | null): EnrichmentTotals {
    const t: EnrichmentTotals = {
      total: 0, enriched: 0, mitigation: 0, detection: 0, atomic: 0,
      d3fend: 0, control: 0, threatIntel: 0, cve: 0, defended: 0,
    };
    for (const tech of techs ?? []) {
      t.total++;
      const s = this.signals(tech, domain);
      if (s.mitigation) t.mitigation++;
      if (s.detection) t.detection++;
      if (s.atomic) t.atomic++;
      if (s.d3fend) t.d3fend++;
      if (s.control) t.control++;
      if (s.threatIntel) t.threatIntel++;
      if (s.cve) t.cve++;
      if (s.mitigation || s.detection || s.atomic || s.d3fend || s.control || s.threatIntel || s.cve) t.enriched++;
      if (s.mitigation || s.detection || s.control || s.d3fend) t.defended++;
    }
    return t;
  }

  /** Enrichment coverage {covered, total, pct} across a set of techniques. */
  coverage(techs: readonly Technique[], domain?: Domain | null): { covered: number; total: number; pct: number } {
    const t = this.totals(techs, domain);
    return { covered: t.enriched, total: t.total, pct: t.total > 0 ? Math.round((t.enriched / t.total) * 100) : 0 };
  }

  /**
   * Multi-signal risk score for "Sort by risk". Higher = riskier: threat
   * pressure (groups weighted 2×, plus software + campaigns) and KEV exposure,
   * doubled when the technique is an unrecorded gap (`isUnrecordedGap`): no defensive
   * reference input other than an Atomic test, and nothing of the owner's
   * recorded at Covered or above. `bucket` is the technique's posture bucket
   * (PostureService.stateFor; P2-09, E2.1-d3). The default 'none' gives the
   * pre-posture answer, so on a fresh profile the order is unchanged; only
   * owner Covered or Proven data lowers a technique.
   */
  riskScore(tech: Technique, domain?: Domain | null, kevScore = 0, bucket: PostureBucket = 'none'): number {
    if (!tech) return 0;
    const groups = this.len(() => domain?.groupsByTechnique?.get(tech.id));
    const software = this.len(() => domain?.softwareByTechnique?.get(tech.id));
    const campaigns = this.len(() => domain?.campaignsByTechnique?.get(tech.id));
    const threat = groups * 2 + software + campaigns;
    const exposure = threat + (kevScore > 0 ? kevScore * 3 : 0);
    return exposure * (isUnrecordedGap(this.signals(tech, domain), bucket) ? 2 : 1);
  }
}

/** Buckets that record something of the owner's at Covered or above (§2.2): full Covered, Proven, stale Proven. */
const OWNER_RECORDED: ReadonlySet<PostureBucket> = new Set<PostureBucket>(['covered', 'proven', 'stale']);

/**
 * An unrecorded gap (P2-09, E2.1-d3; R9, S8): wholly unmapped (no mitigation,
 * detection content, control mapping or D3FEND countermeasure, the Known test
 * `hasDefensiveReference`) AND nothing of the owner's recorded at Covered or
 * above: the posture bucket is not covered, proven or stale. A partial bucket
 * still counts here. The risk sort doubles an unrecorded gap's exposure; the
 * dashboard's critical-risk and KEV-exposed-gap counters count them. On a fresh
 * profile every bucket is 'none' or 'known', so this equals
 * `!hasDefensiveReference(s)`.
 *
 * This is NOT the "threat gap" of the Threat gaps overlay (design §10.4 item
 * 13, P2-17: bucket None or Known only, plus contradicted; partial is not a
 * gap). The two rules differ on partial and contradicted techniques; do not
 * reuse this function for the overlay.
 */
export function isUnrecordedGap(s: SignalFamilies, bucket: PostureBucket): boolean {
  return !hasDefensiveReference(s) && !OWNER_RECORDED.has(bucket);
}
