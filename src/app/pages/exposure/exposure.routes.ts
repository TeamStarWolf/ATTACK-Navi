// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Routes } from '@angular/router';
import { WorkspaceShellComponent } from '../../layout/workspace-shell/workspace-shell.component';

export const EXPOSURE_ROUTES: Routes = [
  {
    path: '',
    component: WorkspaceShellComponent,
    data: { title: 'Exposure', icon: 'shield-alert' },
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'cve' },
      {
        path: 'cve',
        loadComponent: () =>
          import('../../components/cve-panel/cve-panel.component').then(c => c.CvePanelComponent),
        data: { tab: 'CVE', icon: 'bug' },
      },
      {
        path: 'risk',
        loadComponent: () =>
          import('../../components/risk-matrix-panel/risk-matrix-panel.component').then(c => c.RiskMatrixPanelComponent),
        data: { tab: 'Risk', icon: 'trending-down' },
      },
      {
        path: 'kill-chain',
        loadComponent: () =>
          import('../../components/killchain-panel/killchain-panel.component').then(c => c.KillchainPanelComponent),
        data: { tab: 'Kill Chain', icon: 'link-2' },
      },
      {
        path: 'graph',
        loadComponent: () =>
          import('../../components/technique-graph-panel/technique-graph-panel.component').then(c => c.TechniqueGraphPanelComponent),
        data: { tab: 'Graph', icon: 'share-2' },
      },
      {
        path: 'gap-analysis',
        loadComponent: () =>
          import('../../components/gap-analysis-panel/gap-analysis-panel.component').then(c => c.GapAnalysisPanelComponent),
        data: { tab: 'Gap Analysis', icon: 'crosshair' },
      },
      {
        path: 'priority',
        loadComponent: () =>
          import('../../components/priority-panel/priority-panel.component').then(c => c.PriorityPanelComponent),
        data: { tab: 'Priority', icon: 'arrow-up' },
      },
      {
        path: 'what-if',
        loadComponent: () =>
          import('../../components/whatif-panel/whatif-panel.component').then(c => c.WhatifPanelComponent),
        data: { tab: 'What-If', icon: 'sparkles' },
      },
      {
        path: 'ctem',
        loadComponent: () =>
          import('./ctem-page.component').then(c => c.CtemPageComponent),
        data: { tab: 'CTEM', icon: 'compass' },
      },
    ],
  },
];
