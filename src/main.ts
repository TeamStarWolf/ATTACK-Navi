import { bootstrapApplication } from '@angular/platform-browser';
import { isDevMode } from '@angular/core';
import { appConfig } from './app/app.config';
import { AppComponent } from './app/app.component';

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

// Register service worker for PWA offline support
if (!isDevMode()) {
  if ('serviceWorker' in navigator) {
    const basePath = getBaseHref();
    cleanupStaleServiceWorkers(basePath)
      .catch((err) => console.error('Service worker cleanup failed:', err))
      .finally(() => {
        const workerUrl = new URL('ngsw-worker.js', document.baseURI).toString();
        navigator.serviceWorker.register(workerUrl, { scope: basePath }).catch((err) =>
          console.error('Service worker registration failed:', err)
        );
      });
  }
}
