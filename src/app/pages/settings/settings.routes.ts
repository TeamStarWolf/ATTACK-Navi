// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Routes } from '@angular/router';
import { WorkspaceShellComponent } from '../../layout/workspace-shell/workspace-shell.component';

export const SETTINGS_ROUTES: Routes = [
  {
    path: '',
    component: WorkspaceShellComponent,
    data: { title: 'Settings', icon: 'settings' },
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'preferences' },
      {
        path: 'preferences',
        loadComponent: () =>
          import('../../components/settings-panel/settings-panel.component').then(c => c.SettingsPanelComponent),
        data: { tab: 'Preferences', icon: 'settings' },
      },
      {
        path: 'changelog',
        loadComponent: () =>
          import('../../components/changelog-panel/changelog-panel.component').then(c => c.ChangelogPanelComponent),
        data: { tab: 'Changelog', icon: 'scroll-text' },
      },
    ],
  },
];
