import { bootstrapApplication } from '@angular/platform-browser';
import { isDevMode } from '@angular/core';
import { appConfig } from './app/app.config';
import { AppComponent } from './app/app.component';

bootstrapApplication(AppComponent, appConfig)
  .catch((err) => console.error(err));

// Register service worker for PWA offline support
if (!isDevMode()) {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/ngsw-worker.js').catch((err) =>
      console.error('Service worker registration failed:', err)
    );
  }
}
