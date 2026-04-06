// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { DataService } from './data.service';
import { ImplementationService } from './implementation.service';
import { AttackCveService } from './attack-cve.service';
import { ExploitdbService } from './exploitdb.service';
import { EpssService } from './epss.service';
import { ThreatGroup } from '../models/group';
import { Technique } from '../models/technique';
import { Domain } from '../models/domain';

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
  actor: ThreatGroup;
  techniquesCovered: number;
  techniquesTotal: number;
  coveragePercent: number;
  gaps: SimulationGap[];
  riskScore: number;       // 0-100
  tacticBreakdown: { tactic: string; covered: number; total: number }[];
}

// ─── Service ───────────────────────────────────────────────────────────────────

@Injectable({ providedIn: 'root' })
export class ThreatSimulationService {

  constructor(
    private dataService: DataService,
    private implService: ImplementationService,
    private attackCveService: AttackCveService,
    private exploitdbService: ExploitdbService,
    private epssService: EpssService,
  ) {}

  /**
   * Compute coverage gaps for a specific threat actor's TTPs
   * against current mitigations.
   */
  simulateActor(actorId: string, domain: Domain): SimulationResult {
    const group = domain.groups.find(g => g.id === actorId);
    if (!group) {
      return this.emptyResult(actorId);
    }

    const techniques = domain.techniquesByGroup.get(actorId) ?? [];
    const statusMap = this.implService.getStatusMap();
    const techniquesTotal = techniques.length;

    let techniquesCovered = 0;
    const gaps: SimulationGap[] = [];
    const tacticMap = new Map<string, { covered: number; total: number }>();

    for (const tech of techniques) {
      const mitRels = domain.mitigationsByTechnique?.get(tech.id) ?? [];

      // Count implemented mitigations
      let implementedCount = 0;
      for (const rel of mitRels) {
        const s = statusMap.get(rel.mitigation.id);
        if (s === 'implemented') implementedCount++;
      }

      const isCovered = implementedCount >= 1;
      if (isCovered) techniquesCovered++;

      // Update tactic breakdown
      for (const tactic of tech.tacticShortnames) {
        if (!tacticMap.has(tactic)) {
          tacticMap.set(tactic, { covered: 0, total: 0 });
        }
        const entry = tacticMap.get(tactic)!;
        entry.total++;
        if (isCovered) entry.covered++;
      }

      // If not covered, record as a gap
      if (!isCovered) {
        const kevMappings = this.attackCveService.getKevCvesForTechnique(tech.attackId);
        const kevCount = kevMappings.length;
        const hasExploit = this.exploitdbService.hasExploits(tech.attackId);

        // Compute average EPSS for mapped CVEs
        const allCves = this.attackCveService.getCvesForTechnique(tech.attackId);
        let epssSum = 0;
        let epssCount = 0;
        for (const cveMapping of allCves) {
          const score = this.epssService.getScore(cveMapping.cveId);
          if (score) {
            epssSum += score.epss;
            epssCount++;
          }
        }
        const epssAvg = epssCount > 0 ? epssSum / epssCount : null;

        const priority = this.computePriority(kevCount, hasExploit, epssAvg);

        gaps.push({
          technique: tech,
          tactic: tech.tacticShortnames[0] ?? 'unknown',
          kevCount,
          hasExploit,
          epssAvg,
          priority,
        });
      }
    }

    const coveragePercent = techniquesTotal > 0
      ? Math.round((techniquesCovered / techniquesTotal) * 100)
      : 0;

    // Risk score: inverse of coverage, amplified by gap severity
    const criticalGaps = gaps.filter(g => g.priority === 'critical').length;
    const highGaps = gaps.filter(g => g.priority === 'high').length;
    const gapPenalty = techniquesTotal > 0
      ? ((criticalGaps * 4 + highGaps * 2 + (gaps.length - criticalGaps - highGaps)) / techniquesTotal) * 25
      : 0;
    const riskScore = Math.min(100, Math.max(0,
      Math.round(100 - coveragePercent + gapPenalty),
    ));

    const tacticBreakdown = Array.from(tacticMap.entries()).map(
      ([tactic, stats]) => ({ tactic, covered: stats.covered, total: stats.total }),
    ).sort((a, b) => a.tactic.localeCompare(b.tactic));

    return {
      actor: group,
      techniquesCovered,
      techniquesTotal,
      coveragePercent,
      gaps: this.prioritizeGaps(gaps),
      riskScore,
      tacticBreakdown,
    };
  }

  /**
   * Compare coverage across multiple actors.
   */
  simulateMultipleActors(actorIds: string[], domain: Domain): SimulationResult[] {
    return actorIds.map(id => this.simulateActor(id, domain));
  }

  /**
   * Sort gaps by priority: critical > high > medium > low,
   * with secondary sort by KEV count, exploit presence, EPSS.
   */
  prioritizeGaps(gaps: SimulationGap[]): SimulationGap[] {
    const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return [...gaps].sort((a, b) => {
      const po = priorityOrder[a.priority] - priorityOrder[b.priority];
      if (po !== 0) return po;
      // Secondary: more KEV CVEs first
      if (a.kevCount !== b.kevCount) return b.kevCount - a.kevCount;
      // Then exploit presence
      if (a.hasExploit !== b.hasExploit) return a.hasExploit ? -1 : 1;
      // Then higher EPSS first
      const aEpss = a.epssAvg ?? 0;
      const bEpss = b.epssAvg ?? 0;
      return bEpss - aEpss;
    });
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  private computePriority(
    kevCount: number,
    hasExploit: boolean,
    epssAvg: number | null,
  ): 'critical' | 'high' | 'medium' | 'low' {
    // Critical: has KEV entries AND exploit code
    if (kevCount > 0 && hasExploit) return 'critical';
    // Critical: high EPSS + KEV
    if (kevCount > 0 && epssAvg !== null && epssAvg >= 0.3) return 'critical';
    // High: has KEV or exploit or high EPSS
    if (kevCount > 0) return 'high';
    if (hasExploit) return 'high';
    if (epssAvg !== null && epssAvg >= 0.2) return 'high';
    // Medium: moderate EPSS or some CVE data
    if (epssAvg !== null && epssAvg >= 0.05) return 'medium';
    // Low: everything else
    return 'low';
  }

  private emptyResult(actorId: string): SimulationResult {
    return {
      actor: {
        id: actorId,
        attackId: '',
        name: 'Unknown',
        description: '',
        url: '',
        aliases: [],
      },
      techniquesCovered: 0,
      techniquesTotal: 0,
      coveragePercent: 0,
      gaps: [],
      riskScore: 0,
      tacticBreakdown: [],
    };
  }
}
