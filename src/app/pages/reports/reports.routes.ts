// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Routes } from '@angular/router';
import { WorkspaceShellComponent } from '../../layout/workspace-shell/workspace-shell.component';

export const REPORTS_ROUTES: Routes = [
  {
    path: '',
    component: WorkspaceShellComponent,
    data: { title: 'Reports', icon: 'file-text' },
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'builder' },
      {
        path: 'builder',
        loadComponent: () =>
          import('../../components/report-panel/report-panel.component').then(c => c.ReportPanelComponent),
        data: { tab: 'Report Builder', icon: 'file-text', reuse: true },
      },
      {
        path: 'playbooks',
        loadComponent: () =>
          import('../../components/ir-playbook-panel/ir-playbook-panel.component').then(c => c.IRPlaybookPanelComponent),
        data: { tab: 'IR Playbooks', icon: 'siren' },
      },
      {
        path: 'exports',
        loadComponent: () =>
          import('./export-hub.component').then(c => c.ExportHubComponent),
        data: { tab: 'Export Hub', icon: 'download' },
      },
    ],
  },
];
