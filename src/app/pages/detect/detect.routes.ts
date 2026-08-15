// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Routes } from '@angular/router';
import { WorkspaceShellComponent } from '../../layout/workspace-shell/workspace-shell.component';

export const DETECT_ROUTES: Routes = [
  {
    path: '',
    component: WorkspaceShellComponent,
    data: { title: 'Detection', icon: 'radar' },
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'detections' },
      {
        path: 'detections',
        loadComponent: () =>
          import('../../components/detection-panel/detection-panel.component').then(c => c.DetectionPanelComponent),
        data: { tab: 'Detections', icon: 'microscope' },
      },
      {
        path: 'sigma',
        loadComponent: () =>
          import('../../components/sigma-export/sigma-export.component').then(c => c.SigmaExportComponent),
        data: { tab: 'Sigma', icon: 'sigma' },
      },
      {
        path: 'siem',
        loadComponent: () =>
          import('../../components/siem-export/siem-export.component').then(c => c.SiemExportComponent),
        data: { tab: 'SIEM', icon: 'zap' },
      },
      {
        path: 'yara',
        loadComponent: () =>
          import('../../components/yara-export/yara-export.component').then(c => c.YaraExportComponent),
        data: { tab: 'YARA', icon: 'file-code' },
      },
      {
        path: 'validation',
        loadComponent: () =>
          import('../../components/validation-panel/validation-panel.component').then(c => c.ValidationPanelComponent),
        data: { tab: 'Validation', icon: 'search-check' },
      },
      {
        path: 'data-sources',
        loadComponent: () =>
          import('../../components/datasource-panel/datasource-panel.component').then(c => c.DatasourcePanelComponent),
        data: { tab: 'Data Sources', icon: 'antenna' },
      },
      {
        path: 'purple-team',
        loadComponent: () =>
          import('../../components/purple-team-panel/purple-team-panel.component').then(c => c.PurpleTeamPanelComponent),
        data: { tab: 'Purple Team', icon: 'blend' },
      },
    ],
  },
];
