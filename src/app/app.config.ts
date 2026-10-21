// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ApplicationConfig, provideZoneChangeDetection } from '@angular/core';
import { provideHttpClient, withXhr } from '@angular/common/http';
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
import { THREAT_WEIGHT_PROVIDER } from './models/posture/threat-weight';
import { ThreatProfileService } from './services/threat-profile.service';

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideHttpClient(withXhr()),
    // P2-10: the shared threat profile is the app's threat-weight source, so the
    // posture card's threat-relevant scope and PostureService count the profile's
    // groups (not every ATT&CK group, the E2.1 default in threat-weight.ts).
    { provide: THREAT_WEIGHT_PROVIDER, useExisting: ThreatProfileService },
    // Hash routing: GitHub Pages serves only index.html, and the relative
    // <base href="./"> breaks path-based deep links — the hash keeps every
    // real HTTP request at the app root. Filter state lives in query params
    // inside the hash (see UrlStateService + legacy-hash shim in main.ts).
    provideRouter(routes, withHashLocation(), withComponentInputBinding()),
    { provide: TitleStrategy, useClass: AppTitleStrategy },
    { provide: RouteReuseStrategy, useClass: AppRouteReuseStrategy },
  ],
};
