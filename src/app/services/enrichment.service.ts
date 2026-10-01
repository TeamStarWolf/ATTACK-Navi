// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { Domain } from '../models/domain';
import { Technique } from '../models/technique';
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
 * Single source of truth for "coverage" in ATTACK-Navi.
 *
 * The app is ATT&CK/framework-centric, not mitigation-centric: a technique is
 * "covered" (enriched) when it carries ANY cross-framework defensive/framework
 * signal, so mitigation is one contributor among seven rather than the sole
 * definition of coverage. Every service call is guarded — missing/unloaded data
 * yields `false`, never a throw.
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

  /** Presence of each signal family for a single technique. */
  signals(tech: Technique, domain?: Domain | null): EnrichmentSignals {
    if (!tech) {
      return {
        mitigation: false, detection: false, atomic: false, d3fend: false,
        control: false, threatIntel: false, cve: false,
      };
    }
    const id = tech.attackId;
    const mitCount =
      (tech.mitigationCount ?? 0) ||
      this.len(() => domain?.mitigationsByTechnique?.get(tech.id));
    const detection =
      this.num(() => this.sigmaService.getRuleCount(id)) +
      this.num(() => this.carService.getLiveCount(id));
    return {
      mitigation: mitCount > 0,
      detection: detection > 0,
      atomic: this.num(() => this.atomicService.getTestCount(id)) > 0,
      d3fend: this.len(() => this.d3fendService.getCountermeasures(id)) > 0,
      control: this.controlCount(id) > 0,
      threatIntel: this.threatIntelCount(tech, domain) > 0,
      cve: this.len(() => this.attackCveService.getCvesForTechnique(id)) > 0,
    };
  }

  /**
   * Canonical coverage test: a technique is "covered/enriched" when it carries
   * ANY cross-framework signal. This is the definition reused everywhere the app
   * reports "Coverage".
   */
  isEnriched(tech: Technique, domain?: Domain | null): boolean {
    const s = this.signals(tech, domain);
    return (
      s.mitigation || s.detection || s.atomic ||
      s.d3fend || s.control || s.threatIntel || s.cve
    );
  }

  /** How many of the 7 signal families a technique carries (breadth of coverage). */
  signalCount(tech: Technique, domain?: Domain | null): number {
    const s = this.signals(tech, domain);
    return (
      (s.mitigation ? 1 : 0) + (s.detection ? 1 : 0) + (s.atomic ? 1 : 0) +
      (s.d3fend ? 1 : 0) + (s.control ? 1 : 0) + (s.threatIntel ? 1 : 0) + (s.cve ? 1 : 0)
    );
  }

  /**
   * Whether a technique has a genuine DEFENSIVE signal (mitigation, detection,
   * control, or D3FEND countermeasure). Excludes atomic tests, threat-intel and
   * CVE links, which describe exposure/validation rather than a control. Used to
   * flag critical-risk gaps (threat-relevant but wholly undefended).
   */
  hasDefensiveSignal(tech: Technique, domain?: Domain | null): boolean {
    const s = this.signals(tech, domain);
    return s.mitigation || s.detection || s.control || s.d3fend;
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
   * doubled when the technique has NO defensive signal of any kind.
   */
  riskScore(tech: Technique, domain?: Domain | null, kevScore = 0): number {
    if (!tech) return 0;
    const groups = this.len(() => domain?.groupsByTechnique?.get(tech.id));
    const software = this.len(() => domain?.softwareByTechnique?.get(tech.id));
    const campaigns = this.len(() => domain?.campaignsByTechnique?.get(tech.id));
    const threat = groups * 2 + software + campaigns;
    const exposure = threat + (kevScore > 0 ? kevScore * 3 : 0);
    return exposure * (this.hasDefensiveSignal(tech, domain) ? 1 : 2);
  }
}
