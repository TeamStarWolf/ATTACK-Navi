// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, Injector, inject } from '@angular/core';
import { ImplStatus, ImplementationService } from './implementation.service';
import { Domain } from '../models/domain';
import { PostureService } from './posture.service';
import { computeReportSplit, coveredCardLines, partialCardLines, REPORT_SPLIT_LABELS } from '../models/report-split';
import { PROVEN } from '../models/posture/posture-vocabulary';

/** data-posture / data-split values (posture bucket keys) the equality spec reads. */
const DATA = { covered: 'covered', partial: 'partial', proven: 'proven', stale: 'stale' } as const;

@Injectable({ providedIn: 'root' })
export class PdfReportService {
  // Resolved when a report is built, so services that only hold this one (and
  // their specs) do not construct the posture graph.
  private readonly injector = inject(Injector);

  generateReport(domain: Domain, statusMap: Map<string, ImplStatus>): void {
    const html = this.buildReportHtml(domain, statusMap);
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

    // Wait for content to render before printing
    iframe.onload = () => {
      setTimeout(() => {
        iframe.contentWindow?.print();
        setTimeout(() => document.body.removeChild(iframe), 1000);
      }, 300);
    };

    // Fallback if onload already fired
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

  private buildReportHtml(domain: Domain, statusMap: Map<string, ImplStatus>): string {
    const allTechs = domain.techniques;
    const parentTechs = allTechs.filter(t => !t.isSubtechnique);
    // Known (reference mapping, with the Theoretical sub-line) and the posture
    // buckets of PostureService.rollup. Shared with the Report Builder panel and
    // the HTML report (P2-07).
    const L = REPORT_SPLIT_LABELS;
    const posture = this.injector.get(PostureService);
    const split = computeReportSplit(domain, posture.rollup(), this.injector.get(ImplementationService).summarize()['implemented']);
    // Covered and Proven words render only when the owner has recorded data (§2.4).
    const ownerWords = posture.ownerWords();

    // Tactic breakdown, lowest Theoretical share first
    const tacticStats = [...split.byTactic].sort((a, b) => a.theoreticalPct - b.theoreticalPct);

    // Techniques with no mitigation mapped (gap list)
    const gapTechs = parentTechs
      .filter(t => t.mitigationCount === 0)
      .sort((a, b) => {
        const ga = (domain.groupsByTechnique.get(a.id) ?? []).length;
        const gb = (domain.groupsByTechnique.get(b.id) ?? []).length;
        if (gb !== ga) return gb - ga;
        return a.attackId.localeCompare(b.attackId);
      })
      .slice(0, 15);

    // Implementation status counts
    const implCounts = { implemented: 0, inProgress: 0, planned: 0, notStarted: 0 };
    for (const [, status] of statusMap) {
      if (status === 'implemented') implCounts.implemented++;
      else if (status === 'in-progress') implCounts.inProgress++;
      else if (status === 'planned') implCounts.planned++;
      else if (status === 'not-started') implCounts.notStarted++;
    }
    const totalTracked = implCounts.implemented + implCounts.inProgress + implCounts.planned + implCounts.notStarted;

    // Data source summary
    const activeSources: string[] = [];
    activeSources.push('MITRE ATT&CK STIX');
    if (domain.groups.length > 0) activeSources.push(`Threat Groups (${domain.groups.length})`);
    if (domain.software.length > 0) activeSources.push(`Software (${domain.software.length})`);
    if (domain.campaigns.length > 0) activeSources.push(`Campaigns (${domain.campaigns.length})`);
    if (domain.dataSources.length > 0) activeSources.push(`Data Sources (${domain.dataSources.length})`);

    const generatedDate = new Date().toLocaleDateString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });

    const domainLabel = domain.name || 'Enterprise';

    // Build tactic rows
    const tacticRows = tacticStats.map(ts => `
      <tr>
        <td>${this.esc(ts.name)}</td>
        <td style="text-align:center">${ts.total}</td>
        <td style="text-align:center">${ts.known}</td>
        <td style="text-align:center">${ts.theoretical} (${ts.theoreticalPct}%)</td>${ownerWords ? `
        <td style="text-align:center" data-posture="${DATA.covered}">${ts.covered}</td>
        <td style="text-align:center" data-posture="${DATA.partial}">${ts.partial}</td>
        <td style="text-align:center" data-posture="${DATA.proven}">${ts.proven}</td>
        <td style="text-align:center" data-posture="${DATA.stale}">${ts.stale}</td>` : ''}
      </tr>`).join('');

    // Build gap rows
    const gapRows = gapTechs.map(t => {
      const groupCount = (domain.groupsByTechnique.get(t.id) ?? []).length;
      const tactics = t.tacticShortnames
        .map(s => s.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()))
        .join(', ');
      return `
      <tr>
        <td>${this.esc(t.attackId)}</td>
        <td>${this.esc(t.name)}</td>
        <td>${this.esc(tactics)}</td>
        <td style="text-align:center">${groupCount}</td>
      </tr>`;
    }).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>ATT&CK Mitigation Report</title>
  <style>
    @media print {
      @page {
        size: A4 portrait;
        margin: 15mm 12mm;
      }
      body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .page-break { page-break-before: always; }
      .no-break { page-break-inside: avoid; }
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Arial, sans-serif;
      font-size: 11px;
      line-height: 1.5;
      color: #111;
      background: #fff;
    }

    h1 { font-size: 22px; font-weight: 700; margin-bottom: 4px; }
    h2 { font-size: 14px; font-weight: 700; margin: 20px 0 8px 0; border-bottom: 2px solid #333; padding-bottom: 4px; }
    h3 { font-size: 12px; font-weight: 600; margin: 12px 0 6px 0; }

    .report-header {
      border-bottom: 3px solid #111;
      padding-bottom: 10px;
      margin-bottom: 16px;
    }
    .header-meta { font-size: 10px; color: #555; margin-top: 2px; }

    .summary-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 8px;
      margin-bottom: 16px;
    }
    .summary-box {
      border: 1px solid #ccc;
      padding: 8px 10px;
      text-align: center;
    }
    .summary-box .num { font-size: 20px; font-weight: 700; }
    .summary-box .lbl { font-size: 9px; color: #555; text-transform: uppercase; letter-spacing: 0.03em; }

    table { width: 100%; border-collapse: collapse; margin-bottom: 12px; font-size: 10px; }
    th { background: #f0f0f0; padding: 5px 8px; text-align: left; font-weight: 600; border: 1px solid #ccc; font-size: 9px; text-transform: uppercase; }
    td { padding: 4px 8px; border: 1px solid #ddd; }
    tr:nth-child(even) td { background: #fafafa; }

    .impl-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 8px;
      margin-bottom: 12px;
    }
    .impl-box {
      border: 1px solid #ccc;
      padding: 6px 8px;
      text-align: center;
    }
    .impl-box .num { font-size: 16px; font-weight: 700; }
    .impl-box .lbl { font-size: 9px; color: #555; }

    .ds-list { columns: 2; column-gap: 16px; list-style: none; font-size: 10px; }
    .ds-list li { padding: 2px 0; }
    .ds-list li::before { content: '\\2022'; color: #333; margin-right: 6px; }

    .footer {
      margin-top: 24px;
      padding-top: 8px;
      border-top: 1px solid #ccc;
      font-size: 9px;
      color: #777;
      text-align: center;
    }
  </style>
</head>
<body>

<div class="report-header">
  <h1>ATT&amp;CK Mitigation Report</h1>
  <div class="header-meta">
    Domain: ${this.esc(domainLabel)} (ATT&amp;CK v${this.esc(domain.attackVersion)})
    &nbsp;|&nbsp; Generated: ${generatedDate}
  </div>
</div>

<!-- Summary Stats -->
<h2>Summary</h2>
<p style="font-size:10px;color:#555"><strong>${L.known}</strong>: ${L.knownNote} <strong>${L.theoreticalShort}</strong>: ${L.theoreticalNote}${ownerWords ? ` <strong>${L.covered}</strong>: ${L.coveredNote} ${L.assessableNote}` : ` ${L.fresh}`}</p>
<div class="summary-grid no-break">
  <div class="summary-box">
    <div class="num" data-posture="known-total">${split.total}</div>
    <div class="lbl">Total Techniques</div>
  </div>
  <div class="summary-box">
    <div class="num"><span data-posture="known-mapped">${split.known}</span> (${split.knownPct}%)</div>
    <div class="lbl">${L.known}</div>
  </div>
  <div class="summary-box">
    <div class="num">${split.theoretical} (${split.theoreticalPct}%)</div>
    <div class="lbl">${L.theoretical}</div>
  </div>
  <div class="summary-box">
    <div class="num">${split.unmapped}</div>
    <div class="lbl">${L.unmapped}</div>
  </div>${ownerWords ? `
  <div class="summary-box">
    <div class="num" data-share-pct="${split.coveredPct}"><span data-posture="${DATA.covered}">${split.covered}</span> (${split.coveredPct}%)</div>
    <div class="lbl">${L.coveredCard}, of <span data-posture="assessable">${split.assessable}</span> ${L.assessable}</div>${coveredCardLines(split).map(line => `
    <div class="lbl" data-posture-source>${line}</div>`).join('')}
  </div>
  <div class="summary-box">
    <div class="num" data-posture="${DATA.partial}">${split.partial}</div>
    <div class="lbl">${L.partialCard}</div>${partialCardLines(split).map(line => `
    <div class="lbl" data-partial-cause>${line}</div>`).join('')}
  </div>
  <div class="summary-box">
    <div class="num" data-posture="${DATA.proven}">${split.proven}</div>
    <div class="lbl">${PROVEN}</div>
  </div>
  <div class="summary-box">
    <div class="num" data-posture="${DATA.stale}">${split.stale}</div>
    <div class="lbl">${L.stale}</div>
  </div>` : ''}
</div>

<!-- Tactic Breakdown -->
<h2>Tactic Breakdown</h2>
<table class="no-break">
  <thead>
    <tr>
      <th>Tactic</th>
      <th style="text-align:center">Total</th>
      <th style="text-align:center">${L.known}</th>
      <th style="text-align:center">${L.theoreticalShort} (mitigation mapped)</th>${ownerWords ? `
      <th style="text-align:center">${L.covered}</th>
      <th style="text-align:center">${L.partial}</th>
      <th style="text-align:center">${PROVEN}</th>
      <th style="text-align:center">${L.stale}</th>` : ''}
    </tr>
  </thead>
  <tbody>${tacticRows}</tbody>
</table>

<!-- Techniques with no mitigation mapped -->
<div class="page-break"></div>
<h2>Top Techniques with No Mitigation Mapped</h2>
${gapTechs.length > 0 ? `
<table class="no-break">
  <thead>
    <tr>
      <th>Technique ID</th>
      <th>Name</th>
      <th>Tactic</th>
      <th style="text-align:center">Threat Groups</th>
    </tr>
  </thead>
  <tbody>${gapRows}</tbody>
</table>` : '<p>Every technique has at least one mitigation mapped in ATT&amp;CK (reference mapping only).</p>'}

<!-- Implementation Status -->
<h2>Implementation Status (self-attested)</h2>
${totalTracked > 0 ? `
<div class="impl-grid no-break">
  <div class="impl-box">
    <div class="num">${implCounts.implemented}</div>
    <div class="lbl">Implemented</div>
  </div>
  <div class="impl-box">
    <div class="num">${implCounts.inProgress}</div>
    <div class="lbl">In Progress</div>
  </div>
  <div class="impl-box">
    <div class="num">${implCounts.planned}</div>
    <div class="lbl">Planned</div>
  </div>
  <div class="impl-box">
    <div class="num">${implCounts.notStarted}</div>
    <div class="lbl">Not Started</div>
  </div>
</div>
<p style="font-size:10px;color:#555">${totalTracked} of ${domain.mitigations.length} mitigations tracked. ${domain.mitigations.length - totalTracked} untracked.</p>
` : '<p>No implementation status data tracked yet.</p>'}

<!-- Data Source Summary -->
<h2>Active Data Sources</h2>
<ul class="ds-list no-break">
  ${activeSources.map(s => `<li>${this.esc(s)}</li>`).join('\n  ')}
</ul>

<div class="footer">
  Generated by ATT&amp;CK-Navi &mdash; ATT&amp;CK v${this.esc(domain.attackVersion)} &mdash; ${generatedDate}
</div>

</body>
</html>`;
  }
}
