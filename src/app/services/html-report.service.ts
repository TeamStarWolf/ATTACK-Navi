// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { Domain } from '../models/domain';
import { ImplStatus } from './implementation.service';

@Injectable({ providedIn: 'root' })
export class HtmlReportService {

  generateAndOpen(domain: Domain, implStatusMap: Map<string, ImplStatus>): void {
    const html = this.buildHtml(domain, implStatusMap);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    window.open(url, '_blank');
  }

  private esc(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  private buildHtml(domain: Domain, implStatusMap: Map<string, ImplStatus>): string {
    // ── Core data computation ──────────────────────────────────────────────────
    const allTechs = domain.techniques;
    const parentTechs = allTechs.filter(t => !t.isSubtechnique);
    const coveredCount = parentTechs.filter(t => t.mitigationCount > 0).length;
    const uncoveredCount = parentTechs.length - coveredCount;
    const coveragePct = parentTechs.length
      ? Math.round((coveredCount / parentTechs.length) * 100)
      : 0;

    // Avg mitigations per covered technique
    const totalMitRels = parentTechs.reduce((sum, t) => sum + t.mitigationCount, 0);
    const avgMits = coveredCount
      ? (totalMitRels / coveredCount).toFixed(1)
      : '0';

    // Fully implemented: all mitigations for the technique are 'implemented'
    const fullyImplemented = parentTechs.filter(t => {
      if (t.mitigationCount === 0) return false;
      const rels = domain.mitigationsByTechnique.get(t.id) ?? [];
      return rels.every(r => implStatusMap.get(r.mitigation.id) === 'implemented');
    }).length;

    // Per-tactic stats
    const tacticStats = domain.tacticColumns.map(col => {
      const parents = col.techniques.filter(t => !t.isSubtechnique);
      const covered = parents.filter(t => t.mitigationCount > 0).length;
      const pct = parents.length ? Math.round((covered / parents.length) * 100) : 0;
      return { name: col.tactic.name, total: parents.length, covered, pct };
    }).sort((a, b) => b.pct - a.pct);

    // Impl status breakdown (across mitigations in implStatusMap)
    const implCounts = { implemented: 0, inProgress: 0, planned: 0, notStarted: 0 };
    for (const [, status] of implStatusMap) {
      if (status === 'implemented') implCounts.implemented++;
      else if (status === 'in-progress') implCounts.inProgress++;
      else if (status === 'planned') implCounts.planned++;
      else if (status === 'not-started') implCounts.notStarted++;
    }
    const totalTracked = implCounts.implemented + implCounts.inProgress + implCounts.planned + implCounts.notStarted;
    const hasImplData = totalTracked > 0;

    // Top 10 coverage gaps (0 mitigations), sorted by threat group count desc then alpha
    const gapTechs = parentTechs
      .filter(t => t.mitigationCount === 0)
      .sort((a, b) => {
        const ga = (domain.groupsByTechnique.get(a.id) ?? []).length;
        const gb = (domain.groupsByTechnique.get(b.id) ?? []).length;
        if (gb !== ga) return gb - ga;
        return a.attackId.localeCompare(b.attackId);
      })
      .slice(0, 10);

    // Top 10 best covered techniques
    const bestCovered = [...parentTechs]
      .filter(t => t.mitigationCount > 0)
      .sort((a, b) => b.mitigationCount - a.mitigationCount)
      .slice(0, 10);

    // Mitigations grouped by status (for section 7)
    const mitsByStatus: Record<string, Array<{ id: string; attackId: string; name: string; techCount: number }>> = {
      implemented: [],
      'in-progress': [],
      planned: [],
      'not-started': [],
    };
    for (const [mitId, status] of implStatusMap) {
      const mit = domain.mitigations.find(m => m.id === mitId);
      if (!mit) continue;
      const techCount = (domain.techniquesByMitigation.get(mit.id) ?? []).filter(t => !t.isSubtechnique).length;
      const entry = { id: mit.id, attackId: mit.attackId, name: mit.name, techCount };
      if (mitsByStatus[status]) mitsByStatus[status].push(entry);
    }
    // Sort each group by techCount desc
    for (const key of Object.keys(mitsByStatus)) {
      mitsByStatus[key].sort((a, b) => b.techCount - a.techCount);
    }

    const generatedDate = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

    // ── Helper: bar color based on coverage % ─────────────────────────────────
    const barColor = (pct: number): string => {
      if (pct >= 70) return 'linear-gradient(90deg,#22c55e,#16a34a)';
      if (pct >= 40) return 'linear-gradient(90deg,#f59e0b,#d97706)';
      return 'linear-gradient(90deg,#ef4444,#dc2626)';
    };

    // ── Impl badge helper ──────────────────────────────────────────────────────
    const implBadge = (techId: string): string => {
      const rels = domain.mitigationsByTechnique.get(techId) ?? [];
      if (rels.length === 0) return '';
      const statuses = rels.map(r => implStatusMap.get(r.mitigation.id)).filter(Boolean) as ImplStatus[];
      if (statuses.length === 0) return '<span class="badge badge-grey">Untracked</span>';
      if (statuses.every(s => s === 'implemented')) return '<span class="badge badge-green">Implemented</span>';
      if (statuses.some(s => s === 'implemented')) return '<span class="badge badge-blue">Partial</span>';
      if (statuses.some(s => s === 'in-progress')) return '<span class="badge badge-blue">In Progress</span>';
      if (statuses.some(s => s === 'planned')) return '<span class="badge badge-purple">Planned</span>';
      return '<span class="badge badge-grey">Not Started</span>';
    };

    // ── Status badge for mitigation table ─────────────────────────────────────
    const statusBadge = (status: string): string => {
      switch (status) {
        case 'implemented': return '<span class="badge badge-green">Implemented</span>';
        case 'in-progress': return '<span class="badge badge-blue">In Progress</span>';
        case 'planned': return '<span class="badge badge-purple">Planned</span>';
        case 'not-started': return '<span class="badge badge-red">Not Started</span>';
        default: return '';
      }
    };

    // ── Tactic bar chart rows ──────────────────────────────────────────────────
    const tacticRows = tacticStats.map(ts => `
      <div class="tactic-row">
        <div class="tactic-name">${this.esc(ts.name)}</div>
        <div class="bar-container">
          <div class="bar-fill" style="width:${ts.pct}%;background:${barColor(ts.pct)}"></div>
        </div>
        <div class="tactic-pct">${ts.pct}%</div>
        <div class="tactic-count">${ts.covered}/${ts.total}</div>
      </div>`).join('');

    // ── Gap table rows ─────────────────────────────────────────────────────────
    const gapRows = gapTechs.map(t => {
      const groupCount = (domain.groupsByTechnique.get(t.id) ?? []).length;
      const tactics = t.tacticShortnames.map(s => s.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase())).join(', ');
      return `<tr>
        <td><a href="${this.esc(t.url)}" target="_blank">${this.esc(t.attackId)}</a></td>
        <td>${this.esc(t.name)}</td>
        <td>${this.esc(tactics)}</td>
        <td>${groupCount > 0 ? `<span class="badge badge-red">${groupCount} groups</span>` : '—'}</td>
      </tr>`;
    }).join('');

    // ── Best covered table rows ────────────────────────────────────────────────
    const bestRows = bestCovered.map(t => `
      <tr>
        <td><a href="${this.esc(t.url)}" target="_blank">${this.esc(t.attackId)}</a></td>
        <td>${this.esc(t.name)}</td>
        <td><span class="badge badge-blue">${t.mitigationCount}</span></td>
        <td>${implBadge(t.id)}</td>
      </tr>`).join('');

    // ── Mitigation status table (section 7) ───────────────────────────────────
    const mitSectionGroups: Array<{ label: string; key: string; headerClass: string }> = [
      { label: 'Implemented', key: 'implemented', headerClass: 'group-header-green' },
      { label: 'In Progress', key: 'in-progress', headerClass: 'group-header-blue' },
      { label: 'Planned', key: 'planned', headerClass: 'group-header-purple' },
      { label: 'Not Started', key: 'not-started', headerClass: 'group-header-grey' },
    ];

    const mitTableRows = mitSectionGroups.map(g => {
      const items = mitsByStatus[g.key] ?? [];
      if (items.length === 0) return '';
      const rows = items.map(m => `
        <tr>
          <td>${this.esc(m.attackId)}</td>
          <td>${this.esc(m.name)}</td>
          <td>${statusBadge(g.key)}</td>
          <td>${m.techCount}</td>
        </tr>`).join('');
      return `
        <tr class="${g.headerClass}">
          <td colspan="4" style="padding:10px 12px;font-weight:700;font-size:13px;">${this.esc(g.label)} (${items.length})</td>
        </tr>
        ${rows}`;
    }).join('');

    // ── Impl status summary stat cards ─────────────────────────────────────────
    const implSummaryCards = hasImplData ? `
      <div class="stat-grid">
        <div class="stat-card" style="border-left-color:#22c55e">
          <div class="stat-number" style="color:#15803d">${implCounts.implemented}</div>
          <div class="stat-label">Implemented</div>
        </div>
        <div class="stat-card" style="border-left-color:#3b82f6">
          <div class="stat-number" style="color:#1d4ed8">${implCounts.inProgress}</div>
          <div class="stat-label">In Progress</div>
        </div>
        <div class="stat-card" style="border-left-color:#8b5cf6">
          <div class="stat-number" style="color:#6d28d9">${implCounts.planned}</div>
          <div class="stat-label">Planned</div>
        </div>
        <div class="stat-card" style="border-left-color:#6b7280">
          <div class="stat-number" style="color:#374151">${implCounts.notStarted}</div>
          <div class="stat-label">Not Started</div>
        </div>
        <div class="stat-card" style="border-left-color:#f59e0b">
          <div class="stat-number" style="color:#92400e">${domain.mitigations.length - totalTracked}</div>
          <div class="stat-label">Untracked Mitigations</div>
        </div>
      </div>` : '';

    // ── Donut progress ring for coverage ──────────────────────────────────────
    const donutDeg = Math.round(coveragePct * 3.6);

    // ── Full HTML ──────────────────────────────────────────────────────────────
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ATT&amp;CK Coverage Report — ${generatedDate}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f5f7fa; color: #1a202c; }

    /* Header */
    .report-header { background: #07101a; color: white; padding: 32px 48px; }
    .header-top { display: flex; align-items: flex-start; justify-content: space-between; flex-wrap: wrap; gap: 16px; }
    .header-title { font-size: 28px; font-weight: 800; letter-spacing: -0.5px; color: #ffffff; }
    .header-subtitle { font-size: 14px; color: #58a6ff; margin-top: 4px; font-weight: 500; }
    .header-meta { text-align: right; font-size: 13px; color: #8b949e; line-height: 1.8; }
    .header-meta strong { color: #c9d1d9; }

    /* Container */
    .container { max-width: 1100px; margin: 0 auto; padding: 32px 48px; }

    /* Section cards */
    .section { background: white; border-radius: 8px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .section-title { font-size: 18px; font-weight: 700; color: #1a202c; border-bottom: 2px solid #e2e8f0; padding-bottom: 12px; margin: 0 0 20px 0; }
    .section-subtitle { font-size: 13px; color: #718096; margin-top: -14px; margin-bottom: 16px; }

    /* Stat grid */
    .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; }
    .stat-card { background: #f8fafc; border-radius: 8px; padding: 16px; text-align: center; border-left: 4px solid #58a6ff; }
    .stat-number { font-size: 28px; font-weight: 700; color: #07101a; line-height: 1.2; }
    .stat-label { font-size: 12px; color: #718096; margin-top: 4px; }

    /* Coverage ring */
    .coverage-ring-wrap { display: flex; align-items: center; gap: 40px; flex-wrap: wrap; }
    .donut { width: 120px; height: 120px; border-radius: 50%; background: conic-gradient(#22c55e 0deg ${donutDeg}deg, #e2e8f0 ${donutDeg}deg 360deg); display: flex; align-items: center; justify-content: center; flex-shrink: 0; position: relative; }
    .donut::after { content: ''; position: absolute; width: 80px; height: 80px; background: white; border-radius: 50%; }
    .donut-label { position: relative; z-index: 1; font-size: 22px; font-weight: 800; color: #07101a; }

    /* Tactic bar chart */
    .tactic-row { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
    .tactic-name { width: 180px; font-size: 13px; font-weight: 500; flex-shrink: 0; color: #374151; }
    .bar-container { background: #e2e8f0; border-radius: 4px; height: 14px; flex: 1; overflow: hidden; min-width: 0; }
    .bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s ease; }
    .tactic-pct { width: 40px; text-align: right; font-size: 13px; font-weight: 700; color: #374151; flex-shrink: 0; }
    .tactic-count { width: 56px; text-align: right; font-size: 12px; color: #718096; flex-shrink: 0; }

    /* Tables */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { background: #f1f5f9; padding: 8px 12px; text-align: left; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #475569; border-bottom: 1px solid #e2e8f0; }
    td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #f8fafc; }

    /* Status group headers */
    .group-header-green td { background: #d1fae5 !important; color: #065f46; }
    .group-header-blue td { background: #dbeafe !important; color: #1e40af; }
    .group-header-purple td { background: #ede9fe !important; color: #5b21b6; }
    .group-header-grey td { background: #f3f4f6 !important; color: #374151; }

    /* Badges */
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; white-space: nowrap; }
    .badge-green { background: #d1fae5; color: #065f46; }
    .badge-blue { background: #dbeafe; color: #1e40af; }
    .badge-purple { background: #ede9fe; color: #5b21b6; }
    .badge-grey { background: #f3f4f6; color: #374151; }
    .badge-red { background: #fee2e2; color: #991b1b; }

    /* Links */
    a { color: #2563eb; text-decoration: none; }
    a:hover { text-decoration: underline; }

    /* Footer */
    .report-footer { background: #07101a; color: #8b949e; padding: 24px 48px; text-align: center; font-size: 12px; line-height: 2; }
    .report-footer strong { color: #58a6ff; }

    /* Print */
    @media print {
      .report-header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .section { page-break-inside: avoid; }
    }
  </style>
</head>
<body>

<!-- ── HEADER ─────────────────────────────────────────────────────────────── -->
<div class="report-header">
  <div class="header-top">
    <div>
      <div class="header-title">ATT&amp;CK Mitigation Coverage Report</div>
      <div class="header-subtitle">MITRE ATT&amp;CK&#174; Enterprise Matrix &mdash; v${this.esc(domain.attackVersion)}</div>
    </div>
    <div class="header-meta">
      <div><strong>Organization:</strong> Security Team</div>
      <div><strong>Domain:</strong> ${this.esc(domain.name)}</div>
      <div><strong>Generated:</strong> ${generatedDate}</div>
    </div>
  </div>
</div>

<div class="container">

  <!-- ── 1. EXECUTIVE SUMMARY ──────────────────────────────────────────────── -->
  <div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="coverage-ring-wrap" style="margin-bottom:24px">
      <div class="donut"><span class="donut-label">${coveragePct}%</span></div>
      <div>
        <div style="font-size:22px;font-weight:700;color:#07101a;margin-bottom:4px">${coveragePct}% Technique Coverage</div>
        <div style="font-size:14px;color:#718096">${coveredCount} of ${parentTechs.length} parent techniques have at least one mitigation mapped.</div>
        ${hasImplData ? `<div style="font-size:14px;color:#718096;margin-top:4px">${implCounts.implemented} mitigations fully implemented across the environment.</div>` : ''}
      </div>
    </div>
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-number">${parentTechs.length}</div>
        <div class="stat-label">Total Techniques</div>
      </div>
      <div class="stat-card" style="border-left-color:#22c55e">
        <div class="stat-number" style="color:#15803d">${coveredCount}</div>
        <div class="stat-label">Techniques Covered</div>
      </div>
      <div class="stat-card" style="border-left-color:#ef4444">
        <div class="stat-number" style="color:#b91c1c">${uncoveredCount}</div>
        <div class="stat-label">Techniques at Risk</div>
      </div>
      <div class="stat-card" style="border-left-color:#8b5cf6">
        <div class="stat-number" style="color:#6d28d9">${fullyImplemented}</div>
        <div class="stat-label">Fully Implemented</div>
      </div>
      <div class="stat-card" style="border-left-color:#f59e0b">
        <div class="stat-number" style="color:#92400e">${avgMits}</div>
        <div class="stat-label">Avg Mitigations / Covered Tech</div>
      </div>
      <div class="stat-card" style="border-left-color:#06b6d4">
        <div class="stat-number" style="color:#0e7490">${domain.mitigations.length}</div>
        <div class="stat-label">Total Mitigations</div>
      </div>
    </div>
  </div>

  <!-- ── 2. COVERAGE BY TACTIC ─────────────────────────────────────────────── -->
  <div class="section">
    <div class="section-title">Coverage by Tactic</div>
    <div class="section-subtitle">Sorted by coverage percentage (highest first). Shows parent techniques only.</div>
    ${tacticRows}
  </div>

  ${hasImplData ? `
  <!-- ── 3. IMPLEMENTATION STATUS SUMMARY ──────────────────────────────────── -->
  <div class="section">
    <div class="section-title">Implementation Status Summary</div>
    <div class="section-subtitle">Breakdown of ${totalTracked} tracked mitigations by implementation status.</div>
    ${implSummaryCards}
  </div>` : ''}

  <!-- ── 4. TOP 10 COVERAGE GAPS ────────────────────────────────────────────── -->
  <div class="section">
    <div class="section-title">Top 10 Coverage Gaps</div>
    <div class="section-subtitle">Techniques with zero mitigations mapped, prioritized by threat group adoption.</div>
    ${gapTechs.length > 0 ? `
    <table>
      <thead>
        <tr>
          <th>ATT&amp;CK ID</th>
          <th>Technique</th>
          <th>Tactics</th>
          <th>Threat Groups</th>
        </tr>
      </thead>
      <tbody>${gapRows}</tbody>
    </table>` : '<p style="color:#718096;font-size:14px;margin:0">No coverage gaps — all techniques have at least one mitigation mapped.</p>'}
  </div>

  <!-- ── 5. TOP 10 BEST COVERED TECHNIQUES ────────────────────────────────── -->
  <div class="section">
    <div class="section-title">Top 10 Best Covered Techniques</div>
    <div class="section-subtitle">Techniques with the most mitigations mapped, sorted by mitigation count.</div>
    <table>
      <thead>
        <tr>
          <th>ATT&amp;CK ID</th>
          <th>Technique</th>
          <th>Mitigations</th>
          <th>Impl Status</th>
        </tr>
      </thead>
      <tbody>${bestRows}</tbody>
    </table>
  </div>

  ${hasImplData ? `
  <!-- ── 6. MITIGATION IMPLEMENTATION PROGRESS ─────────────────────────────── -->
  <div class="section">
    <div class="section-title">Mitigation Implementation Progress</div>
    <div class="section-subtitle">All tracked mitigations grouped by implementation status. Sorted by technique coverage count.</div>
    <table>
      <thead>
        <tr>
          <th>Mitigation ID</th>
          <th>Mitigation Name</th>
          <th>Status</th>
          <th>Techniques Covered</th>
        </tr>
      </thead>
      <tbody>${mitTableRows}</tbody>
    </table>
  </div>` : ''}

</div>

<!-- ── FOOTER ─────────────────────────────────────────────────────────────── -->
<div class="report-footer">
  <div>Generated by <strong>MITRE ATT&amp;CK Mitigation Navigator</strong></div>
  <div>ATT&amp;CK&#174; is a registered trademark of The MITRE Corporation. This report is for internal security planning purposes only.</div>
  <div style="margin-top:4px;color:#6e7681;">ATT&amp;CK v${this.esc(domain.attackVersion)} &nbsp;&bull;&nbsp; ${generatedDate}</div>
</div>

</body>
</html>`;
  }
}
