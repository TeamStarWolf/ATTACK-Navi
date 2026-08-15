// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Routes } from '@angular/router';

/**
 * Top-level routes. Each workspace lazy-loads its own route file (loadChildren)
 * so per-workspace code splits into separate chunks. The matrix is the home
 * page and is marked `reuse: true` so the RouteReuseStrategy detaches it on
 * leave instead of destroying it (preserves expansion, selection, scroll).
 */
export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'matrix' },
  {
    path: 'matrix',
    loadComponent: () =>
      import('./pages/matrix/matrix-page.component').then((c) => c.MatrixPageComponent),
    data: { title: 'Matrix', icon: 'grid', reuse: true },
  },
  {
    path: 'detect',
    loadChildren: () => import('./pages/detect/detect.routes').then((m) => m.DETECT_ROUTES),
  },
  {
    path: 'exposure',
    loadChildren: () => import('./pages/exposure/exposure.routes').then((m) => m.EXPOSURE_ROUTES),
  },
  {
    path: 'dashboard',
    loadChildren: () => import('./pages/dashboard/dashboard.routes').then((m) => m.DASHBOARD_ROUTES),
  },
  {
    path: 'intel',
    loadChildren: () => import('./pages/intel/intel.routes').then((m) => m.INTEL_ROUTES),
  },
  {
    path: 'coverage',
    loadChildren: () => import('./pages/coverage/coverage.routes').then((m) => m.COVERAGE_ROUTES),
  },
  { path: '**', redirectTo: 'matrix' },
];
