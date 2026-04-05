import { Injectable } from '@angular/core';
import { Domain } from '../models/domain';
import { Technique } from '../models/technique';
import { DataService } from './data.service';
import { SigmaService } from './sigma.service';
import { ElasticService } from './elastic.service';
import { SplunkContentService } from './splunk-content.service';
import { M365DefenderService } from './m365-defender.service';
import { AtomicService } from './atomic.service';
import { CARService } from './car.service';
import { AttackCveService } from './attack-cve.service';
import { CveService } from './cve.service';
import { EpssService } from './epss.service';
import { ExploitdbService } from './exploitdb.service';
import { ImplementationService } from './implementation.service';

// ─── Interfaces ────────────────────────────────────────────────────────────────

export interface GapAnalysisResult {
  generatedAt: string;
  domain: string;
  selectedActors: string[];
  summary: GapSummary;
  tacticBreakdown: TacticGapRow[];
  prioritizedGaps: PrioritizedGap[];
  detectionCoverage: DetectionCoverage;
}

export interface GapSummary {
  totalTechniques: number;
  actorTechniques: number;
  mitigated: number;
  detected: number;
  validated: number;
  fullyBlind: number;
  coveragePercent: number;
  detectionPercent: number;
  ragStatus: 'red' | 'amber' | 'green';
}

export interface TacticGapRow {
  tactic: string;
  shortname: string;
  total: number;
  mitigated: number;
  detected: number;
  blind: number;
  ragStatus: 'red' | 'amber' | 'green';
}

export interface PrioritizedGap {
  technique: { attackId: string; name: string };
  tactic: string;
  usedByGroups: string[];
  kevCount: number;
  epssAvg: number | null;
  hasExploit: boolean;
  detectionSources: string[];
  priority: 'critical' | 'high' | 'medium' | 'low';
  recommendation: string;
}

export interface DetectionCoverage {
  sigma: { covered: number; total: number };
  elastic: { covered: number; total: number };
  splunk: { covered: number; total: number };
  m365: { covered: number; total: number };
  atomic: { covered: number; total: number };
  car: { covered: number; total: number };
}

// ─── Service ───────────────────────────────────────────────────────────────────

@Injectable({ providedIn: 'root' })
export class GapAnalysisService {

  constructor(
    private dataService: DataService,
    private sigmaService: SigmaService,
    private elasticService: ElasticService,
    private splunkService: SplunkContentService,
    private m365Service: M365DefenderService,
    private atomicService: AtomicService,
    private carService: CARService,
    private attackCveService: AttackCveService,
    private cveService: CveService,
    private epssService: EpssService,
    private exploitdbService: ExploitdbService,
    private implService: ImplementationService,
  ) {}

  // ─── Main report generator ──────────────────────────────────────────────────

  generateReport(domain: Domain, actorIds: string[]): GapAnalysisResult {
    // Determine techniques in scope
    const parentTechniques = domain.techniques.filter(t => !t.isSubtechnique);
    let techniquesInScope: Technique[];

    if (actorIds.length === 0) {
      // Analyze all techniques
      techniquesInScope = parentTechniques;
    } else {
      // Get techniques used by selected actors
      const techStixIds = new Set<string>();
      for (const actorId of actorIds) {
        const techs = domain.techniquesByGroup.get(actorId) ?? [];
        for (const t of techs) {
          if (!t.isSubtechnique) techStixIds.add(t.id);
        }
      }
      techniquesInScope = parentTechniques.filter(t => techStixIds.has(t.id));
    }

    // Get actor names for the report
    const selectedActors = actorIds.map(id => {
      const group = domain.groups.find(g => g.id === id);
      return group?.name ?? id;
    });

    // Compute per-technique metrics
    const techMetrics = techniquesInScope.map(t => this.computeTechniqueMetrics(t, domain));

    // Compute summary
    const summary = this.computeSummary(techMetrics, techniquesInScope.length);

    // Compute tactic breakdown
    const tacticBreakdown = this.computeTacticBreakdown(techMetrics, domain);

    // Compute detection coverage totals
    const detectionCoverage = this.computeDetectionCoverage(techMetrics);

    // Build prioritized gaps (all techniques that lack full detection)
    const prioritizedGaps = this.buildPrioritizedGaps(techMetrics, domain)
      .sort((a, b) => {
        const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        return (order[a.priority] ?? 4) - (order[b.priority] ?? 4);
      });

    return {
      generatedAt: new Date().toISOString(),
      domain: `${domain.name || 'Enterprise'} ATT&CK v${domain.attackVersion}`,
      selectedActors,
      summary,
      tacticBreakdown,
      prioritizedGaps,
      detectionCoverage,
    };
  }

  // ─── Per-technique metrics ──────────────────────────────────────────────────

  private computeTechniqueMetrics(tech: Technique, domain: Domain): TechniqueMetrics {
    const mitigations = domain.mitigationsByTechnique.get(tech.id) ?? [];
    const hasMitigation = mitigations.length > 0;

    const sigmaCount = this.sigmaService.getRuleCount(tech.attackId);
    const elasticCount = this.elasticService.getRuleCount(tech.attackId);
    const splunkCount = this.splunkService.getRuleCount(tech.attackId);
    const m365Count = this.m365Service.getQueriesForTechnique(tech.attackId).length;
    const atomicCount = this.atomicService.getTestCount(tech.attackId);
    const carCount = this.carService.getAnalytics(tech.attackId).length;

    const detectionSources: string[] = [];
    if (sigmaCount > 0) detectionSources.push('Sigma');
    if (elasticCount > 0) detectionSources.push('Elastic');
    if (splunkCount > 0) detectionSources.push('Splunk');
    if (m365Count > 0) detectionSources.push('M365');
    if (carCount > 0) detectionSources.push('CAR');

    const hasDetection = detectionSources.length > 0;
    const hasValidation = atomicCount > 0;

    // CVE/KEV/EPSS/ExploitDB exposure
    const kevMappings = this.attackCveService.getKevCvesForTechnique(tech.attackId);
    const kevCount = kevMappings.length;
    const exploitCount = this.exploitdbService.getExploitCount(tech.attackId);
    const hasExploit = exploitCount > 0;

    // Groups using this technique
    const groups = domain.groupsByTechnique.get(tech.id) ?? [];

    return {
      technique: tech,
      hasMitigation,
      hasDetection,
      hasValidation,
      detectionSources,
      sigmaCount,
      elasticCount,
      splunkCount,
      m365Count,
      atomicCount,
      carCount,
      kevCount,
      hasExploit,
      groups: groups.map(g => g.name),
      mitigationNames: mitigations.map(m => `${m.mitigation.attackId} (${m.mitigation.name})`),
    };
  }

  // ─── Summary computation ────────────────────────────────────────────────────

  private computeSummary(metrics: TechniqueMetrics[], totalTechniques: number): GapSummary {
    const mitigated = metrics.filter(m => m.hasMitigation).length;
    const detected = metrics.filter(m => m.hasDetection).length;
    const validated = metrics.filter(m => m.hasValidation).length;
    const fullyBlind = metrics.filter(m => !m.hasMitigation && !m.hasDetection).length;

    const coveragePercent = totalTechniques > 0
      ? Math.round((mitigated / totalTechniques) * 100) : 0;
    const detectionPercent = totalTechniques > 0
      ? Math.round((detected / totalTechniques) * 100) : 0;

    const combinedPercent = totalTechniques > 0
      ? Math.round((metrics.filter(m => m.hasMitigation || m.hasDetection).length / totalTechniques) * 100)
      : 0;

    return {
      totalTechniques,
      actorTechniques: metrics.length,
      mitigated,
      detected,
      validated,
      fullyBlind,
      coveragePercent,
      detectionPercent,
      ragStatus: this.computeRag(combinedPercent),
    };
  }

  // ─── Tactic breakdown ───────────────────────────────────────────────────────

  private computeTacticBreakdown(metrics: TechniqueMetrics[], domain: Domain): TacticGapRow[] {
    const tacticMap = new Map<string, { tactic: string; shortname: string; total: number; mitigated: number; detected: number; blind: number }>();

    for (const col of domain.tacticColumns) {
      tacticMap.set(col.tactic.shortname, {
        tactic: col.tactic.name,
        shortname: col.tactic.shortname,
        total: 0,
        mitigated: 0,
        detected: 0,
        blind: 0,
      });
    }

    for (const m of metrics) {
      for (const shortname of m.technique.tacticShortnames) {
        const row = tacticMap.get(shortname);
        if (!row) continue;
        row.total++;
        if (m.hasMitigation) row.mitigated++;
        if (m.hasDetection) row.detected++;
        if (!m.hasMitigation && !m.hasDetection) row.blind++;
      }
    }

    return Array.from(tacticMap.values())
      .filter(r => r.total > 0)
      .map(r => ({
        ...r,
        ragStatus: this.computeRag(
          r.total > 0 ? Math.round(((r.mitigated + r.detected) / r.total) * 50 + (r.mitigated / r.total) * 50) : 0,
        ),
      }));
  }

  // ─── Detection coverage totals ──────────────────────────────────────────────

  private computeDetectionCoverage(metrics: TechniqueMetrics[]): DetectionCoverage {
    const total = metrics.length;
    return {
      sigma:   { covered: metrics.filter(m => m.sigmaCount > 0).length,   total },
      elastic: { covered: metrics.filter(m => m.elasticCount > 0).length, total },
      splunk:  { covered: metrics.filter(m => m.splunkCount > 0).length,  total },
      m365:    { covered: metrics.filter(m => m.m365Count > 0).length,    total },
      atomic:  { covered: metrics.filter(m => m.atomicCount > 0).length,  total },
      car:     { covered: metrics.filter(m => m.carCount > 0).length,     total },
    };
  }

  // ─── Prioritized gaps ──────────────────────────────────────────────────────

  private buildPrioritizedGaps(metrics: TechniqueMetrics[], domain: Domain): PrioritizedGap[] {
    // Only include techniques that are missing something (not fully covered)
    const gaps = metrics.filter(m => !m.hasMitigation || !m.hasDetection);

    return gaps.map(m => {
      const priority = this.computePriority(m);
      const recommendation = this.buildRecommendation(m, domain);

      return {
        technique: { attackId: m.technique.attackId, name: m.technique.name },
        tactic: m.technique.tacticShortnames
          .map(s => s.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()))
          .join(', '),
        usedByGroups: m.groups,
        kevCount: m.kevCount,
        epssAvg: null, // EPSS requires async fetch; null until enriched
        hasExploit: m.hasExploit,
        detectionSources: m.detectionSources,
        priority,
        recommendation,
      };
    });
  }

  private computePriority(m: TechniqueMetrics): PrioritizedGap['priority'] {
    const noDetection = !m.hasDetection;
    const noMitigation = !m.hasMitigation;

    // Critical: KEV + no detection + actor uses it
    if (m.kevCount > 0 && noDetection && m.groups.length > 0) return 'critical';
    // Critical: KEV + fully blind
    if (m.kevCount > 0 && noDetection && noMitigation) return 'critical';
    // High: has exploit + no detection
    if (m.hasExploit && noDetection) return 'high';
    // High: actor uses + fully blind
    if (m.groups.length > 0 && noDetection && noMitigation) return 'high';
    // Medium: no detection at all
    if (noDetection) return 'medium';
    // Low: partial detection exists
    return 'low';
  }

  private buildRecommendation(m: TechniqueMetrics, domain: Domain): string {
    const parts: string[] = [];

    if (!m.hasDetection) {
      parts.push('Add Sigma rule');
      if (m.splunkCount === 0 && m.elasticCount === 0) {
        parts.push('consider Elastic/Splunk content');
      }
    }

    if (!m.hasMitigation) {
      // Suggest mitigations from other techniques in the same tactic
      const possibleMitigations = this.suggestMitigations(m.technique, domain);
      if (possibleMitigations.length > 0) {
        parts.push(`implement mitigation ${possibleMitigations.slice(0, 2).join(', ')}`);
      } else {
        parts.push('implement compensating controls');
      }
    }

    if (!m.hasValidation) {
      parts.push('validate with Atomic Red Team test');
    }

    return parts.length > 0 ? parts.join(' + ') : 'Monitor for coverage changes';
  }

  private suggestMitigations(tech: Technique, domain: Domain): string[] {
    // Check if there are mitigations for this technique itself
    const ownMitigations = domain.mitigationsByTechnique.get(tech.id) ?? [];
    if (ownMitigations.length > 0) {
      return ownMitigations.map(m => `${m.mitigation.attackId}`);
    }

    // Find common mitigations used in the same tactic
    const tacticMitigations = new Map<string, number>();
    for (const col of domain.tacticColumns) {
      if (!tech.tacticShortnames.includes(col.tactic.shortname)) continue;
      for (const colTech of col.techniques) {
        const mits = domain.mitigationsByTechnique.get(colTech.id) ?? [];
        for (const mit of mits) {
          tacticMitigations.set(
            mit.mitigation.attackId,
            (tacticMitigations.get(mit.mitigation.attackId) ?? 0) + 1,
          );
        }
      }
    }

    return Array.from(tacticMitigations.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([id]) => id);
  }

  // ─── RAG helper ─────────────────────────────────────────────────────────────

  private computeRag(percent: number): 'red' | 'amber' | 'green' {
    if (percent >= 70) return 'green';
    if (percent >= 40) return 'amber';
    return 'red';
  }

  // ─── CSV Export ─────────────────────────────────────────────────────────────

  exportCsv(result: GapAnalysisResult): void {
    const rows: string[] = [];

    // Header
    rows.push([
      'Technique ID', 'Technique Name', 'Tactic', 'Priority',
      'Used By Groups', 'KEV Count', 'Has Exploit',
      'Detection Sources', 'Recommendation',
    ].join(','));

    // Gap rows
    for (const gap of result.prioritizedGaps) {
      rows.push([
        gap.technique.attackId,
        `"${gap.technique.name.replace(/"/g, '""')}"`,
        `"${gap.tactic.replace(/"/g, '""')}"`,
        gap.priority,
        gap.usedByGroups.length.toString(),
        gap.kevCount.toString(),
        gap.hasExploit ? 'Yes' : 'No',
        `"${gap.detectionSources.join('; ')}"`,
        `"${gap.recommendation.replace(/"/g, '""')}"`,
      ].join(','));
    }

    // Summary section
    rows.push('');
    rows.push('--- Summary ---');
    rows.push(`Generated,${result.generatedAt}`);
    rows.push(`Domain,${result.domain}`);
    rows.push(`Selected Actors,"${result.selectedActors.join('; ')}"`);
    rows.push(`Total Techniques,${result.summary.totalTechniques}`);
    rows.push(`Mitigated,${result.summary.mitigated}`);
    rows.push(`Detected,${result.summary.detected}`);
    rows.push(`Validated,${result.summary.validated}`);
    rows.push(`Fully Blind,${result.summary.fullyBlind}`);
    rows.push(`Coverage %,${result.summary.coveragePercent}`);
    rows.push(`Detection %,${result.summary.detectionPercent}`);
    rows.push(`RAG Status,${result.summary.ragStatus.toUpperCase()}`);

    const blob = new Blob([rows.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `gap-analysis-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // ─── PDF Export (via iframe print) ──────────────────────────────────────────

  exportPdf(result: GapAnalysisResult): void {
    const html = this.buildPdfHtml(result);
    this.printViaIframe(html);
  }

  private printViaIframe(html: string): void {
    const iframe = document.createElement('iframe');
    iframe.style.position = 'fixed';
    iframe.style.left = '-9999px';
    iframe.style.top = '-9999px';
    iframe.style.width = '0';
    iframe.style.height = '0';
    iframe.style.border = 'none';
    document.body.appendChild(iframe);

    const iframeDoc = iframe.contentDocument ?? iframe.contentWindow?.document;
    if (!iframeDoc) {
      document.body.removeChild(iframe);
      return;
    }

    iframeDoc.open();
    iframeDoc.write(html);
    iframeDoc.close();

    iframe.onload = () => {
      setTimeout(() => {
        iframe.contentWindow?.print();
        setTimeout(() => document.body.removeChild(iframe), 1000);
      }, 300);
    };

    setTimeout(() => {
      try { iframe.contentWindow?.print(); } catch { /* noop */ }
      setTimeout(() => {
        if (iframe.parentNode) document.body.removeChild(iframe);
      }, 1000);
    }, 1500);
  }

  private esc(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  private buildPdfHtml(result: GapAnalysisResult): string {
    const generatedDate = new Date(result.generatedAt).toLocaleDateString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });

    const ragColor = result.summary.ragStatus === 'green' ? '#4caf50'
      : result.summary.ragStatus === 'amber' ? '#ff9800' : '#f44336';

    // Tactic rows
    const tacticRows = result.tacticBreakdown.map(t => {
      const rowColor = t.ragStatus === 'green' ? '#e8f5e9'
        : t.ragStatus === 'amber' ? '#fff3e0' : '#ffebee';
      return `<tr style="background:${rowColor}">
        <td>${this.esc(t.tactic)}</td>
        <td style="text-align:center">${t.total}</td>
        <td style="text-align:center">${t.mitigated}</td>
        <td style="text-align:center">${t.detected}</td>
        <td style="text-align:center">${t.blind}</td>
        <td style="text-align:center"><span style="background:${t.ragStatus === 'green' ? '#4caf50' : t.ragStatus === 'amber' ? '#ff9800' : '#f44336'};color:#fff;padding:2px 8px;border-radius:4px;font-size:9px;font-weight:700">${t.ragStatus.toUpperCase()}</span></td>
      </tr>`;
    }).join('');

    // Gap rows (top 20)
    const gapRows = result.prioritizedGaps.slice(0, 20).map(g => {
      const prColor = g.priority === 'critical' ? '#f44336'
        : g.priority === 'high' ? '#ff9800'
        : g.priority === 'medium' ? '#2196f3' : '#4caf50';
      return `<tr>
        <td>${this.esc(g.technique.attackId)}</td>
        <td>${this.esc(g.technique.name)}</td>
        <td><span style="background:${prColor};color:#fff;padding:2px 6px;border-radius:3px;font-size:9px;font-weight:700">${g.priority.toUpperCase()}</span></td>
        <td style="text-align:center">${g.usedByGroups.length}</td>
        <td style="text-align:center">${g.kevCount}</td>
        <td>${this.esc(g.detectionSources.join(', ') || 'None')}</td>
        <td style="font-size:9px">${this.esc(g.recommendation)}</td>
      </tr>`;
    }).join('');

    // Detection coverage bars
    const sources = ['sigma', 'elastic', 'splunk', 'm365', 'atomic', 'car'] as const;
    const coverageBars = sources.map(s => {
      const cov = result.detectionCoverage[s];
      const pct = cov.total > 0 ? Math.round((cov.covered / cov.total) * 100) : 0;
      return `<div style="margin:4px 0">
        <div style="display:flex;justify-content:space-between;font-size:10px;margin-bottom:2px">
          <span>${s.toUpperCase()}</span><span>${cov.covered}/${cov.total} (${pct}%)</span>
        </div>
        <div style="background:#e0e0e0;border-radius:4px;height:14px;overflow:hidden">
          <div style="background:#2196f3;height:100%;width:${pct}%;border-radius:4px"></div>
        </div>
      </div>`;
    }).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Detection Gap Analysis Report</title>
  <style>
    @media print {
      @page { size: A4 landscape; margin: 12mm 10mm; }
      body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .page-break { page-break-before: always; }
      .no-break { page-break-inside: avoid; }
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Arial, sans-serif; font-size: 10px; line-height: 1.5; color: #111; background: #fff; }
    h1 { font-size: 20px; font-weight: 700; margin-bottom: 4px; }
    h2 { font-size: 13px; font-weight: 700; margin: 16px 0 6px; border-bottom: 2px solid #333; padding-bottom: 3px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 10px; font-size: 9px; }
    th { background: #f0f0f0; padding: 4px 6px; text-align: left; font-weight: 600; border: 1px solid #ccc; font-size: 8px; text-transform: uppercase; }
    td { padding: 3px 6px; border: 1px solid #ddd; }
    .summary-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 6px; margin-bottom: 12px; }
    .summary-box { border: 1px solid #ccc; padding: 6px 8px; text-align: center; }
    .summary-box .num { font-size: 18px; font-weight: 700; }
    .summary-box .lbl { font-size: 8px; color: #555; text-transform: uppercase; }
    .footer { margin-top: 20px; padding-top: 6px; border-top: 1px solid #ccc; font-size: 8px; color: #777; text-align: center; }
  </style>
</head>
<body>

<div style="border-bottom:3px solid #111;padding-bottom:8px;margin-bottom:12px">
  <h1>Detection Gap Analysis Report</h1>
  <div style="font-size:9px;color:#555">
    Domain: ${this.esc(result.domain)}
    &nbsp;|&nbsp; Generated: ${generatedDate}
    ${result.selectedActors.length > 0 ? `&nbsp;|&nbsp; Actors: ${this.esc(result.selectedActors.join(', '))}` : '&nbsp;|&nbsp; All techniques analyzed'}
  </div>
</div>

<h2>Summary</h2>
<div class="summary-grid no-break">
  <div class="summary-box"><div class="num">${result.summary.totalTechniques}</div><div class="lbl">Total</div></div>
  <div class="summary-box"><div class="num" style="color:#4caf50">${result.summary.mitigated}</div><div class="lbl">Mitigated</div></div>
  <div class="summary-box"><div class="num" style="color:#2196f3">${result.summary.detected}</div><div class="lbl">Detected</div></div>
  <div class="summary-box"><div class="num" style="color:#9c27b0">${result.summary.validated}</div><div class="lbl">Validated</div></div>
  <div class="summary-box"><div class="num" style="color:#f44336">${result.summary.fullyBlind}</div><div class="lbl">Fully Blind</div></div>
  <div class="summary-box"><div class="num" style="color:${ragColor}">${result.summary.ragStatus.toUpperCase()}</div><div class="lbl">RAG Status</div></div>
</div>

<h2>Tactic Breakdown</h2>
<table class="no-break">
  <thead><tr><th>Tactic</th><th style="text-align:center">Total</th><th style="text-align:center">Mitigated</th><th style="text-align:center">Detected</th><th style="text-align:center">Blind</th><th style="text-align:center">RAG</th></tr></thead>
  <tbody>${tacticRows}</tbody>
</table>

<h2>Detection Source Coverage</h2>
<div class="no-break" style="max-width:500px">${coverageBars}</div>

<div class="page-break"></div>
<h2>Prioritized Gaps (Top 20)</h2>
<table>
  <thead><tr><th>ID</th><th>Technique</th><th>Priority</th><th style="text-align:center">Groups</th><th style="text-align:center">KEV</th><th>Detection</th><th>Recommendation</th></tr></thead>
  <tbody>${gapRows}</tbody>
</table>

<div class="footer">
  Generated by MITRE ATT&amp;CK Mitigation Navigator &mdash; ${this.esc(result.domain)} &mdash; ${generatedDate}
</div>

</body>
</html>`;
  }
}

// ─── Internal type ────────────────────────────────────────────────────────────

interface TechniqueMetrics {
  technique: Technique;
  hasMitigation: boolean;
  hasDetection: boolean;
  hasValidation: boolean;
  detectionSources: string[];
  sigmaCount: number;
  elasticCount: number;
  splunkCount: number;
  m365Count: number;
  atomicCount: number;
  carCount: number;
  kevCount: number;
  hasExploit: boolean;
  groups: string[];
  mitigationNames: string[];
}
