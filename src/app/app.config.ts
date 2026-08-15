// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ApplicationConfig, provideZoneChangeDetection } from '@angular/core';
import { provideHttpClient } from '@angular/common/http';
import {
  RouteReuseStrategy,
  TitleStrategy,
  provideRouter,
  withComponentInputBinding,
  withHashLocation,
} from '@angular/router';
import { routes } from './app.routes';
import { AppTitleStrategy } from './services/app-title.strategy';
import { AppRouteReuseStrategy } from './services/route-reuse.strategy';

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideHttpClient(),
    // Hash routing: GitHub Pages serves only index.html, and the relative
    // <base href="./"> breaks path-based deep links — the hash keeps every
    // real HTTP request at the app root. Filter state lives in query params
    // inside the hash (see UrlStateService + legacy-hash shim in main.ts).
    provideRouter(routes, withHashLocation(), withComponentInputBinding()),
    { provide: TitleStrategy, useClass: AppTitleStrategy },
    { provide: RouteReuseStrategy, useClass: AppRouteReuseStrategy },
  ],
};
