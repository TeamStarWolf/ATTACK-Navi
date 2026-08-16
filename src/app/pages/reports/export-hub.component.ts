// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, Component } from '@angular/core';

import { ExportActionsService } from '../../services/export-actions.service';
import { WorkspaceBundleService } from '../../services/workspace-bundle.service';

interface ExportCard {
  icon: string;
  title: string;
  desc: string;
  action: (svc: ExportActionsService) => void;
}

interface ExportSection {
  title: string;
  cards: ExportCard[];
}

/**
 * Export Hub: every export/import action in one card grid, replacing the
 * 14-item flat toolbar menu. Actions run through ExportActionsService, so
 * they work from any workspace (matrix-image exports require the matrix to
 * be mounted and say so in their descriptions).
 */
@Component({
  selector: 'app-export-hub',
  standalone: true,
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './export-hub.component.html',
  styleUrl: './export-hub.component.scss',
})
export class ExportHubComponent {
  readonly sections: ExportSection[] = [
    {
      title: 'Coverage Data',
      cards: [
        { icon: '⬇', title: 'Coverage CSV', desc: 'Technique-by-technique coverage table', action: s => s.exportCsv() },
        { icon: '⬇', title: 'Tactic Summary', desc: 'Per-tactic coverage rollup as CSV', action: s => s.exportTacticCsv() },
        { icon: '⬇', title: 'Implementation Plan', desc: 'Mitigation statuses and owners as CSV', action: s => s.exportImplPlanCsv() },
        { icon: '📗', title: 'Excel Workbook', desc: 'Multi-sheet XLSX with coverage, plan and stats', action: s => s.exportXlsxWorkbook() },
      ],
    },
    {
      title: 'Reports',
      cards: [
        { icon: '⬇', title: 'Full Report', desc: 'Complete coverage report as CSV', action: s => s.exportFullReport() },
        { icon: '📊', title: 'HTML Report', desc: 'Standalone coverage report for sharing', action: s => s.exportHtmlCoverageReport() },
        { icon: '📄', title: 'PDF Report', desc: 'Printable coverage summary', action: s => s.exportPdf() },
        { icon: '🖨', title: 'Print Matrix', desc: 'Browser print of the current view', action: () => window.print() },
        { icon: '📷', title: 'Matrix PNG', desc: 'Screenshot of the matrix (open the Matrix first)', action: s => s.exportMatrixPng() },
      ],
    },
    {
      title: 'ATT&CK Navigator',
      cards: [
        { icon: '⬇', title: 'Export Navigator Layer', desc: 'Layer JSON for the official MITRE Navigator', action: s => s.exportNavigatorLayer() },
        { icon: '🧭', title: 'Open in Navigator', desc: 'Launch mitre-attack.github.io with this layer', action: s => s.openInNavigator() },
        { icon: '⬆', title: 'Import Navigator Layer', desc: 'Apply scores/colors from a layer file', action: s => s.importNavigatorLayer() },
      ],
    },
    {
      title: 'Workspace State',
      cards: [
        { icon: '⬇', title: 'Export State', desc: 'Filters, statuses, notes and views as JSON', action: s => s.exportStateJson() },
        { icon: '⬆', title: 'Import State', desc: 'Restore a previously exported state file', action: s => s.importStateJson() },
      ],
    },
  ];

  constructor(
    protected exportActions: ExportActionsService,
    private workspaceBundle: WorkspaceBundleService,
  ) {}

  run(card: ExportCard): void {
    card.action(this.exportActions);
  }

  exportWorkspace(): void {
    this.workspaceBundle.downloadBundle();
  }

  importWorkspace(): void {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (ev) => {
        try {
          const applied = this.workspaceBundle.importBundle(ev.target?.result as string);
          if (confirm(`Workspace restored (${applied} data sets). Reload now to apply everywhere?`)) {
            window.location.reload();
          }
        } catch (err: any) {
          alert(`Import failed: ${err?.message ?? err}`);
        }
      };
      reader.readAsText(file);
    };
    input.click();
  }
}
