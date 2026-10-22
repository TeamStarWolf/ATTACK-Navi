// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Profile-scoped threat simulation (Phase 2 design §3 P2-12a, E2.6-b3).
// The simulation runs over the shared threat profile's parent techniques
// (THREAT_WEIGHT_PROVIDER.parents(), the §2.6 denominator), not a single actor:
// the scenario panel's former multi-actor overlay collapses to this one result.
// Actor-versus-actor comparison moves to the compare panels (#/intel/compare).
//
// "Covered" here mirrors P2-07's report "Yes" rule: a technique counts as
// covered when its PostureService bucket is covered, proven OR stale (stale is
// still rung Proven, only aged). `partial` is NOT covered and reference-only
// content never counts. The gap/priority inputs (KEV, exploits, EPSS) are
// unchanged.
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { PostureService } from './posture.service';
import { AttackCveService } from './attack-cve.service';
import { ExploitdbService } from './exploitdb.service';
import { EpssService } from './epss.service';
import { Technique } from '../models/technique';
import { Domain } from '../models/domain';
import { PostureBucket } from '../models/posture/posture.types';
import { tallyPosture } from '../models/posture/derive-posture';
import { THREAT_WEIGHT_PROVIDER } from '../models/posture/threat-weight';

// ─── Interfaces ────────────────────────────────────────────────────────────────

export interface SimulationGap {
  technique: Technique;
  tactic: string;
  kevCount: number;
  hasExploit: boolean;
  epssAvg: number | null;
  priority: 'critical' | 'high' | 'medium' | 'low';
}

export interface SimulationResult {
  /** Techniques whose posture bucket is covered, proven or stale (P2-07's Yes rule); the % numerator. */
  techniquesCovered: number;
  /** The profile's parent-technique count (the §2.6 denominator). */
  techniquesTotal: number;
  coveragePercent: number;
  // Per-bucket breakdown over the profile's parents, from tallyPosture — equal, number for
  // number, to the ctem posture card for the same profile (no two-answer window, §2.6).
  coveredCount: number;        // bucket 'covered'
  partialCount: number;        // bucket 'partial' — its own number, never covered and never a gap
  provenCount: number;         // bucket 'proven'
  staleCount: number;          // bucket 'stale'
  knownCount: number;          // bucket 'known' — reference mapping only (internal gap maths)
  mappedCount: number;         // parents with a reference mapping (knownSignals > 0) — the ctem "Known: mapped" numerator
  noneCount: number;           // bucket 'none'
  contradictedCount: number;   // the 'contradicted' sub-state — a gap (§10.4 item 13)
  gaps: SimulationGap[];
  riskScore: number;       // 0-100
  tacticBreakdown: { tactic: string; covered: number; total: number }[];
}

/** A posture bucket counts as "covered" for the simulation when it is covered, proven or stale. */
const COVERED_BUCKETS: ReadonlySet<PostureBucket> = new Set<PostureBucket>(['covered', 'proven', 'stale']);

// ─── Service ───────────────────────────────────────────────────────────────────

@Injectable({ providedIn: 'root' })
export class ThreatSimulationService {
  private readonly posture = inject(PostureService);
  private readonly threatWeight = inject(THREAT_WEIGHT_PROVIDER);

  constructor(
    private attackCveService: AttackCveService,
    private exploitdbService: ExploitdbService,
    private epssService: EpssService,
  ) {
    // Simulations count CVEs from the CTID ATT&CK-to-CVE mapping, which loads on demand:
    // the scenario view (this service's only user) asks for it when it opens.
    this.attackCveService.loadOnDemand();
  }

  /**
   * Emits once the CTID mapping behind the KEV and CVE counts has settled ('loaded' or
   * 'failed'; at once when it already has). The scenario view waits on it before
   * simulating, so the counts are never taken from an index that has not arrived.
   */
  cveMappingsSettled$(): Observable<'loaded' | 'failed'> {
    return this.attackCveService.settled$();
  }

  /** Whether the CTID mapping has loaded (it loads on demand). */
  cveMappingsLoaded$(): Observable<boolean> {
    return this.attackCveService.loaded$;
  }

  /**
   * Simulate the shared threat profile against the owner's posture: coverage over
   * the profile's parent techniques, and the uncovered ones as prioritised gaps.
   */
  simulate(domain: Domain): SimulationResult {
    const parentIds = this.threatWeight.parents();
    const techniques = domain.techniques.filter(t => parentIds.has(t.id));
    const techniquesTotal = techniques.length;

    // One state per technique; the tally gives the per-bucket breakdown the ctem card shows.
    const states = techniques.map(t => this.posture.stateFor(t));
    const tally = tallyPosture(states);
    const techniquesCovered = tally.covered + tally.proven + tally.stale;
    // Mirrors the ctem posture card's "Known: mapped" numerator (knownSignals > 0),
    // which is mapped-of-total, not the bucket-'known' count.
    const mappedCount = states.filter(s => s.knownSignals > 0).length;

    const gaps: SimulationGap[] = [];
    const tacticMap = new Map<string, { covered: number; total: number }>();

    techniques.forEach((tech, i) => {
      const state = states[i];
      const isCovered = COVERED_BUCKETS.has(state.bucket);
      // §10.4 item 13: a gap is bucket none or known, or the contradicted sub-state.
      // partial is NOT a gap (and is not covered); reference-only (known) is a gap.
      const isGap = state.bucket === 'none' || state.bucket === 'known'
        || state.subStates.includes('contradicted');

      for (const tactic of tech.tacticShortnames) {
        if (!tacticMap.has(tactic)) tacticMap.set(tactic, { covered: 0, total: 0 });
        const entry = tacticMap.get(tactic)!;
        entry.total++;
        if (isCovered) entry.covered++;
      }

      if (isGap) {
        const kevCount = this.attackCveService.getKevCvesForTechnique(tech.attackId).length;
        const hasExploit = this.exploitdbService.hasExploits(tech.attackId);

        const allCves = this.attackCveService.getCvesForTechnique(tech.attackId);
        let epssSum = 0;
        let epssCount = 0;
        for (const cveMapping of allCves) {
          const score = this.epssService.getScore(cveMapping.cveId);
          if (score) { epssSum += score.epss; epssCount++; }
        }
        const epssAvg = epssCount > 0 ? epssSum / epssCount : null;

        gaps.push({
          technique: tech,
          tactic: tech.tacticShortnames[0] ?? 'unknown',
          kevCount,
          hasExploit,
          epssAvg,
          priority: this.computePriority(kevCount, hasExploit, epssAvg),
        });
      }
    });

    const coveragePercent = techniquesTotal > 0
      ? Math.round((techniquesCovered / techniquesTotal) * 100)
      : 0;

    // Risk score: inverse of coverage, amplified by gap severity.
    const criticalGaps = gaps.filter(g => g.priority === 'critical').length;
    const highGaps = gaps.filter(g => g.priority === 'high').length;
    const gapPenalty = techniquesTotal > 0
      ? ((criticalGaps * 4 + highGaps * 2 + (gaps.length - criticalGaps - highGaps)) / techniquesTotal) * 25
      : 0;
    const riskScore = Math.min(100, Math.max(0, Math.round(100 - coveragePercent + gapPenalty)));

    const tacticBreakdown = Array.from(tacticMap.entries())
      .map(([tactic, stats]) => ({ tactic, covered: stats.covered, total: stats.total }))
      .sort((a, b) => a.tactic.localeCompare(b.tactic));

    return {
      techniquesCovered,
      techniquesTotal,
      coveragePercent,
      coveredCount: tally.covered,
      partialCount: tally.partial,
      provenCount: tally.proven,
      staleCount: tally.stale,
      knownCount: tally.known,
      mappedCount,
      noneCount: tally.none,
      contradictedCount: tally.contradicted,
      gaps: this.prioritizeGaps(gaps),
      riskScore,
      tacticBreakdown,
    };
  }

  /**
   * Sort gaps by priority: critical > high > medium > low, with secondary sort
   * by KEV count, exploit presence, then EPSS.
   */
  prioritizeGaps(gaps: SimulationGap[]): SimulationGap[] {
    const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return [...gaps].sort((a, b) => {
      const po = priorityOrder[a.priority] - priorityOrder[b.priority];
      if (po !== 0) return po;
      if (a.kevCount !== b.kevCount) return b.kevCount - a.kevCount;
      if (a.hasExploit !== b.hasExploit) return a.hasExploit ? -1 : 1;
      return (b.epssAvg ?? 0) - (a.epssAvg ?? 0);
    });
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  private computePriority(
    kevCount: number,
    hasExploit: boolean,
    epssAvg: number | null,
  ): 'critical' | 'high' | 'medium' | 'low' {
    if (kevCount > 0 && hasExploit) return 'critical';
    if (kevCount > 0 && epssAvg !== null && epssAvg >= 0.3) return 'critical';
    if (kevCount > 0) return 'high';
    if (hasExploit) return 'high';
    if (epssAvg !== null && epssAvg >= 0.2) return 'high';
    if (epssAvg !== null && epssAvg >= 0.05) return 'medium';
    return 'low';
  }
}
