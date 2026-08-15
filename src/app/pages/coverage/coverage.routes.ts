// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Routes } from '@angular/router';
import { WorkspaceShellComponent } from '../../layout/workspace-shell/workspace-shell.component';

export const COVERAGE_ROUTES: Routes = [
  {
    path: '',
    component: WorkspaceShellComponent,
    data: { title: 'Coverage', icon: 'shield-check' },
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'assessment' },
      {
        path: 'assessment',
        loadComponent: () =>
          import('../../components/assessment-wizard/assessment-wizard.component').then(c => c.AssessmentWizardComponent),
        data: { tab: 'Assessment', icon: 'compass', reuse: true },
      },
      {
        path: 'controls',
        loadComponent: () =>
          import('../../components/controls-panel/controls-panel.component').then(c => c.ControlsPanelComponent),
        data: { tab: 'Controls', icon: 'lock' },
      },
      {
        path: 'custom-mitigations',
        loadComponent: () =>
          import('../../components/custom-mit-panel/custom-mit-panel.component').then(c => c.CustomMitPanelComponent),
        data: { tab: 'Custom Mitigations', icon: 'building' },
      },
      {
        path: 'compliance',
        loadComponent: () =>
          import('../../components/compliance-panel/compliance-panel.component').then(c => c.CompliancePanelComponent),
        data: { tab: 'Compliance', icon: 'scroll-text' },
      },
      {
        path: 'diff',
        loadComponent: () =>
          import('../../components/coverage-diff-panel/coverage-diff-panel.component').then(c => c.CoverageDiffPanelComponent),
        data: { tab: 'Diff', icon: 'git-compare' },
      },
      {
        path: 'timeline',
        loadComponent: () =>
          import('../../components/timeline-panel/timeline-panel.component').then(c => c.TimelinePanelComponent),
        data: { tab: 'Timeline', icon: 'calendar' },
      },
      {
        path: 'target',
        loadComponent: () =>
          import('../../components/target-panel/target-panel.component').then(c => c.TargetPanelComponent),
        data: { tab: 'Target', icon: 'target' },
      },
      {
        path: 'assets',
        loadComponent: () =>
          import('../../components/asset-panel/asset-panel.component').then(c => c.AssetPanelComponent),
        data: { tab: 'Assets', icon: 'monitor' },
      },
    ],
  },
];
