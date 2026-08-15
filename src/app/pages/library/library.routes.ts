// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Routes } from '@angular/router';
import { WorkspaceShellComponent } from '../../layout/workspace-shell/workspace-shell.component';

export const LIBRARY_ROUTES: Routes = [
  {
    path: '',
    component: WorkspaceShellComponent,
    data: { title: 'Library', icon: 'layers' },
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'workbench' },
      {
        path: 'workbench',
        loadComponent: () =>
          import('../../components/library-workbench/library-workbench.component').then(c => c.LibraryWorkbenchComponent),
        data: { tab: 'Workbench', icon: 'layers', reuse: true },
      },
      {
        path: 'layers',
        loadComponent: () =>
          import('../../components/layers-panel/layers-panel.component').then(c => c.LayersPanelComponent),
        data: { tab: 'Layers', icon: 'layers' },
      },
      {
        path: 'collections',
        loadComponent: () =>
          import('../../components/collection-panel/collection-panel.component').then(c => c.CollectionPanelComponent),
        data: { tab: 'Collections', icon: 'box' },
      },
      {
        path: 'comparison',
        loadComponent: () =>
          import('../../components/comparison-panel/comparison-panel.component').then(c => c.ComparisonPanelComponent),
        data: { tab: 'Comparison', icon: 'git-compare' },
      },
      {
        path: 'roadmap',
        loadComponent: () =>
          import('../../components/roadmap-panel/roadmap-panel.component').then(c => c.RoadmapPanelComponent),
        data: { tab: 'Roadmap', icon: 'map' },
      },
      {
        path: 'watchlist',
        loadComponent: () =>
          import('../../components/watchlist-panel/watchlist-panel.component').then(c => c.WatchlistPanelComponent),
        data: { tab: 'Watchlist', icon: 'bookmark' },
      },
      {
        path: 'tags',
        loadComponent: () =>
          import('../../components/tags-panel/tags-panel.component').then(c => c.TagsPanelComponent),
        data: { tab: 'Tags', icon: 'tag' },
      },
    ],
  },
];
