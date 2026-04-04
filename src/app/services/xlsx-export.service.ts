import { Injectable } from '@angular/core';
import { Domain } from '../models/domain';
import { ImplStatus, IMPL_STATUS_LABELS } from './implementation.service';
import { CustomMitigation } from './custom-mitigation.service';
import { CoverageSnapshot } from './timeline.service';

type XLSX = typeof import('xlsx-js-style');

const STATUS_RANK: Record<string, number> = {
  'implemented': 4,
  'in-progress': 3,
  'planned': 2,
  'not-started': 1,
};

@Injectable({ providedIn: 'root' })
export class XlsxExportService {

  async exportWorkbook(
    domain: Domain,
    implStatusMap: Map<string, ImplStatus>,
    customMitigations: CustomMitigation[],
    snapshots: CoverageSnapshot[],
  ): Promise<void> {
    try {
      const XLSX = await import('xlsx-js-style');

      const wb = XLSX.utils.book_new();

      XLSX.utils.book_append_sheet(wb, this.buildOverviewSheet(XLSX, domain, implStatusMap, customMitigations), 'Overview');
      XLSX.utils.book_append_sheet(wb, this.buildTechniquesSheet(XLSX, domain, implStatusMap, false), 'Techniques');
      XLSX.utils.book_append_sheet(wb, this.buildTechniquesSheet(XLSX, domain, implStatusMap, true), 'Subtechniques');
      XLSX.utils.book_append_sheet(wb, this.buildMitigationsSheet(XLSX, domain, implStatusMap), 'Mitigations');
      XLSX.utils.book_append_sheet(wb, this.buildCoverageByTacticSheet(XLSX, domain), 'Coverage by Tactic');
      XLSX.utils.book_append_sheet(wb, this.buildGapsSheet(XLSX, domain), 'Gaps');
      XLSX.utils.book_append_sheet(wb, this.buildCustomControlsSheet(XLSX, customMitigations), 'Custom Controls');

      if (snapshots.length > 0) {
        XLSX.utils.book_append_sheet(wb, this.buildTimelineSheet(XLSX, snapshots), 'Timeline');
      }

      const filename = `attack-coverage-${new Date().toISOString().split('T')[0]}.xlsx`;
      XLSX.writeFile(wb, filename);
    } catch (err) {
      console.error('XLSX export failed:', err);
      alert('Excel export failed. Please try a CSV export instead.');
    }
  }

  // ── Sheet 1: Overview ────────────────────────────────────────────────────────

  private buildOverviewSheet(
    XLSX: XLSX,
    domain: Domain,
    implStatusMap: Map<string, ImplStatus>,
    customMitigations: CustomMitigation[],
  ): any {
    const parentTechniques = domain.techniques.filter(t => !t.isSubtechnique);
    const subtechniques = domain.techniques.filter(t => t.isSubtechnique);
    const coveredTechniques = parentTechniques.filter(t => t.mitigationCount > 0);
    const coverageRate = parentTechniques.length
      ? Math.round((coveredTechniques.length / parentTechniques.length) * 100)
      : 0;

    let implemented = 0, inProgress = 0, planned = 0, notStarted = 0;
    for (const s of implStatusMap.values()) {
      if (s === 'implemented') implemented++;
      else if (s === 'in-progress') inProgress++;
      else if (s === 'planned') planned++;
      else if (s === 'not-started') notStarted++;
    }

    const rows: any[][] = [
      ['ATT&CK Mitigation Coverage Report', '', '', '', ''],
      [`Generated: ${new Date().toLocaleString()}`, '', '', '', ''],
      [],
      ['EXECUTIVE SUMMARY', '', '', '', ''],
      [],
      ['Metric', 'Value'],
      ['Total Techniques', parentTechniques.length],
      ['Total Subtechniques', subtechniques.length],
      ['Covered Techniques', coveredTechniques.length],
      ['Coverage Rate', `${coverageRate}%`],
      ['Total Mitigations', domain.mitigations.length],
      ['Implemented', implemented],
      ['In Progress', inProgress],
      ['Planned', planned],
      ['Not Started', notStarted],
      ['Custom Controls', customMitigations.length],
    ];

    const ws = XLSX.utils.aoa_to_sheet(rows);
    this.setColumnWidths(ws, [30, 15, 15, 15, 15]);

    // Merge title row A1:E1
    ws['!merges'] = [{ s: { r: 0, c: 0 }, e: { r: 0, c: 4 } }];

    return ws;
  }

  // ── Sheet 2 & 3: Techniques / Subtechniques ──────────────────────────────────

  private buildTechniquesSheet(
    XLSX: XLSX,
    domain: Domain,
    implStatusMap: Map<string, ImplStatus>,
    subtechsOnly: boolean,
  ): any {
    const headers = [
      'ATT&CK ID', 'Name', 'Tactics', 'Is Subtechnique', 'Parent ID',
      'Platforms', 'Mitigation Count', 'Impl Status (best)', 'URL',
    ];

    const filtered = domain.techniques.filter(t => t.isSubtechnique === subtechsOnly);

    const dataRows = filtered.map(tech => {
      const rels = domain.mitigationsByTechnique.get(tech.id) ?? [];
      let bestStatus = '';
      let bestRank = 0;
      for (const rel of rels) {
        const s = implStatusMap.get(rel.mitigation.id);
        if (s && (STATUS_RANK[s] ?? 0) > bestRank) {
          bestRank = STATUS_RANK[s];
          bestStatus = s;
        }
      }

      // Find parent attackId
      let parentAttackId = '';
      if (tech.isSubtechnique && tech.parentId) {
        const parent = domain.techniques.find(t => t.id === tech.parentId);
        parentAttackId = parent?.attackId ?? '';
      }

      return [
        tech.attackId,
        tech.name,
        tech.tacticShortnames.join('; '),
        tech.isSubtechnique ? 'Yes' : 'No',
        parentAttackId,
        tech.platforms.join('; '),
        tech.mitigationCount,
        bestStatus || '',
        tech.url,
      ];
    });

    const ws = XLSX.utils.aoa_to_sheet([headers, ...dataRows]);
    this.setColumnWidths(ws, [12, 40, 35, 16, 12, 35, 16, 20, 55]);
    return ws;
  }

  // ── Sheet 4: Mitigations ─────────────────────────────────────────────────────

  private buildMitigationsSheet(
    XLSX: XLSX,
    domain: Domain,
    implStatusMap: Map<string, ImplStatus>,
  ): any {
    const headers = [
      'Mitigation ID', 'Name', 'Implementation Status', 'Status Label',
      'Techniques Covered (count)', 'Description',
    ];

    const dataRows = domain.mitigations.map(mit => {
      const status = implStatusMap.get(mit.id) ?? null;
      const statusLabel = status ? IMPL_STATUS_LABELS[status] : '';
      const techniqueCount = (domain.techniquesByMitigation.get(mit.id) ?? []).length;
      return [
        mit.attackId,
        mit.name,
        status ?? '',
        statusLabel,
        techniqueCount,
        mit.description,
      ];
    });

    const ws = XLSX.utils.aoa_to_sheet([headers, ...dataRows]);
    this.setColumnWidths(ws, [14, 40, 22, 22, 24, 80]);
    return ws;
  }

  // ── Sheet 5: Coverage by Tactic ──────────────────────────────────────────────

  private buildCoverageByTacticSheet(XLSX: XLSX, domain: Domain): any {
    const headers = ['Tactic', 'ATT&CK ID', 'Total Techniques', 'Covered', 'Coverage %', 'Avg Mitigations'];

    const dataRows = domain.tacticColumns.map(col => {
      const parents = col.techniques.filter(t => !t.isSubtechnique);
      const covered = parents.filter(t => t.mitigationCount > 0);
      const pct = parents.length ? Math.round((covered.length / parents.length) * 100) : 0;
      const avgMit = parents.length
        ? (parents.reduce((sum, t) => sum + t.mitigationCount, 0) / parents.length).toFixed(2)
        : '0.00';
      return [
        col.tactic.name,
        col.tactic.attackId,
        parents.length,
        covered.length,
        `${pct}%`,
        avgMit,
      ];
    });

    const ws = XLSX.utils.aoa_to_sheet([headers, ...dataRows]);
    this.setColumnWidths(ws, [30, 12, 18, 12, 14, 18]);
    return ws;
  }

  // ── Sheet 6: Gaps ────────────────────────────────────────────────────────────

  private buildGapsSheet(XLSX: XLSX, domain: Domain): any {
    const headers = ['ATT&CK ID', 'Name', 'Tactics', 'Platforms', 'Threat Groups (count)', 'URL'];

    const gaps = domain.techniques.filter(t => !t.isSubtechnique && t.mitigationCount === 0);

    const dataRows = gaps.map(tech => {
      const groupCount = (domain.groupsByTechnique.get(tech.id) ?? []).length;
      return [
        tech.attackId,
        tech.name,
        tech.tacticShortnames.join('; '),
        tech.platforms.join('; '),
        groupCount,
        tech.url,
      ];
    });

    const ws = XLSX.utils.aoa_to_sheet([headers, ...dataRows]);
    this.setColumnWidths(ws, [12, 40, 35, 35, 22, 55]);
    return ws;
  }

  // ── Sheet 7: Custom Controls ─────────────────────────────────────────────────

  private buildCustomControlsSheet(XLSX: XLSX, customMitigations: CustomMitigation[]): any {
    const headers = ['ID', 'Name', 'Category', 'Impl Status', 'Techniques Linked', 'Description', 'Created', 'Updated'];

    const dataRows = customMitigations.map(cm => [
      cm.id,
      cm.name,
      cm.category,
      cm.implStatus ?? '',
      cm.techniqueIds.join('; '),
      cm.description,
      cm.createdAt ? new Date(cm.createdAt).toLocaleDateString() : '',
      cm.updatedAt ? new Date(cm.updatedAt).toLocaleDateString() : '',
    ]);

    const ws = XLSX.utils.aoa_to_sheet([headers, ...dataRows]);
    this.setColumnWidths(ws, [10, 35, 15, 15, 35, 60, 14, 14]);
    return ws;
  }

  // ── Sheet 8: Timeline ────────────────────────────────────────────────────────

  private buildTimelineSheet(XLSX: XLSX, snapshots: CoverageSnapshot[]): any {
    const headers = [
      'Date', 'Label', 'Coverage %', 'Covered', 'Total',
      'Implemented', 'In Progress', 'Planned', 'Notes',
    ];

    const dataRows = snapshots.map(s => [
      s.createdAt ? new Date(s.createdAt).toLocaleString() : '',
      s.label,
      `${s.coveragePct}%`,
      s.coveredTechniques,
      s.totalTechniques,
      s.implCounts.implemented,
      s.implCounts.inProgress,
      s.implCounts.planned,
      s.notes,
    ]);

    const ws = XLSX.utils.aoa_to_sheet([headers, ...dataRows]);
    this.setColumnWidths(ws, [22, 30, 12, 10, 10, 14, 12, 10, 50]);
    return ws;
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────

  private setColumnWidths(ws: any, widths: number[]): void {
    ws['!cols'] = widths.map(w => ({ wch: w }));
  }
}
