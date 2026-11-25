// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { bootstrapApplication } from '@angular/platform-browser';
import { isDevMode } from '@angular/core';
import { appConfig } from './app/app.config';
import { AppComponent } from './app/app.component';
import { applyLegacyHashShim } from './app/utils/legacy-hash-shim';

// Rewrite pre-router share links (#tech=T1059, #heat=kev&grp=G0016) into
// routed URLs BEFORE bootstrap so the router's initial navigation sees them.
// migrateViewMode: users who last used the pre-router library view land on
// /library once; the legacy storage key is deleted after migration.
applyLegacyHashShim(true);

bootstrapApplication(AppComponent, appConfig)
  .catch((err) => console.error(err));

function getBaseHref(): string {
  const baseElement = document.querySelector('base');
  const href = baseElement?.getAttribute('href') ?? './';
  return new URL(href, window.location.href).pathname;
}

async function cleanupStaleServiceWorkers(basePath: string): Promise<void> {
  if (!('serviceWorker' in navigator)) return;

  const normalizedBasePath = basePath.endsWith('/') ? basePath : `${basePath}/`;
  const registrations = await navigator.serviceWorker.getRegistrations();

  await Promise.all(
    registrations.map(async (registration) => {
      const scopePath = new URL(registration.scope).pathname;
      if (scopePath === normalizedBasePath) return;
      await registration.unregister();
    })
  );
}

// The ngsw service worker itself is registered by provideServiceWorker in app.config.ts, which
// also wires Angular's SwUpdate so AppUpdateService can prompt a reload when a new build is ready.
// Here we only clear a leftover service worker from an earlier deploy registered at a DIFFERENT
// scope, so it cannot keep serving an old app shell.
if (!isDevMode()) {
  if ('serviceWorker' in navigator) {
    cleanupStaleServiceWorkers(getBaseHref()).catch((err) =>
      console.error('Service worker cleanup failed:', err),
    );
  }
}
