// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Routes } from '@angular/router';
import { WorkspaceShellComponent } from '../../layout/workspace-shell/workspace-shell.component';

export const DASHBOARD_ROUTES: Routes = [
  {
    path: '',
    component: WorkspaceShellComponent,
    data: { title: 'Dashboard', icon: 'layout-dashboard' },
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'overview' },
      {
        path: 'overview',
        loadComponent: () =>
          import('../../components/dashboard-panel/dashboard-panel.component').then(c => c.DashboardPanelComponent),
        data: { tab: 'Overview', icon: 'layout-dashboard' },
      },
      {
        path: 'analytics',
        loadComponent: () =>
          import('../../components/analytics-panel/analytics-panel.component').then(c => c.AnalyticsPanelComponent),
        data: { tab: 'Analytics', icon: 'chart-line' },
      },
    ],
  },
];
