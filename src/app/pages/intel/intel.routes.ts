// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Routes } from '@angular/router';
import { WorkspaceShellComponent } from '../../layout/workspace-shell/workspace-shell.component';

export const INTEL_ROUTES: Routes = [
  {
    path: '',
    component: WorkspaceShellComponent,
    data: { title: 'Threat Intel', icon: 'users' },
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'groups' },
      {
        path: 'groups',
        loadComponent: () =>
          import('../../components/threat-panel/threat-panel.component').then(c => c.ThreatPanelComponent),
        data: { tab: 'Groups', icon: 'users' },
      },
      {
        path: 'actors',
        loadComponent: () =>
          import('../../components/actor-profile-panel/actor-profile-panel.component').then(c => c.ActorProfilePanelComponent),
        data: { tab: 'Actors', icon: 'user-search' },
      },
      {
        path: 'compare',
        loadComponent: () =>
          import('../../components/actor-compare-panel/actor-compare-panel.component').then(c => c.ActorComparePanelComponent),
        data: { tab: 'Compare', icon: 'scale' },
      },
      {
        path: 'scenarios',
        loadComponent: () =>
          import('../../components/scenario-panel/scenario-panel.component').then(c => c.ScenarioPanelComponent),
        data: { tab: 'Scenarios', icon: 'drama', reuse: true },
      },
      {
        path: 'emulation',
        loadComponent: () =>
          import('../../components/emulation-plan-panel/emulation-plan-panel.component').then(c => c.EmulationPlanPanelComponent),
        data: { tab: 'Emulation', icon: 'swords', reuse: true },
      },
      {
        path: 'campaigns',
        loadComponent: () =>
          import('../../components/campaign-timeline-panel/campaign-timeline-panel.component').then(c => c.CampaignTimelinePanelComponent),
        data: { tab: 'Campaigns', icon: 'calendar-range' },
      },
      {
        path: 'software',
        loadComponent: () =>
          import('../../components/software-panel/software-panel.component').then(c => c.SoftwarePanelComponent),
        data: { tab: 'Software', icon: 'package' },
      },
      {
        path: 'feeds',
        loadComponent: () =>
          import('../../components/threat-intelligence-panel/threat-intelligence-panel.component').then(c => c.ThreatIntelligencePanelComponent),
        data: { tab: 'Feeds', icon: 'brain' },
      },
    ],
  },
];
