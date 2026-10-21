// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';
import { readPref, writePref } from '../utils/local-pref';

/** localStorage key for the technique drawer's width (one key, px as a string). */
export const DRAWER_WIDTH_KEY = 'technique-drawer-width-v1';
export const DRAWER_MIN_WIDTH = 320;
export const DRAWER_DEFAULT_WIDTH = 460;
/** Absolute ceiling; the live ceiling is also capped at 60% of the viewport. */
export const DRAWER_MAX_WIDTH = 900;
export const DRAWER_MAX_VIEWPORT_FRACTION = 0.6;
export const DRAWER_STEP = 16;
export const DRAWER_BIG_STEP = 64;

/** The widest the drawer may be in a viewport this wide (never below the minimum). */
export function drawerMaxWidth(viewportWidth: number): number {
  const byViewport = Math.floor(viewportWidth * DRAWER_MAX_VIEWPORT_FRACTION);
  return Math.max(DRAWER_MIN_WIDTH, Math.min(DRAWER_MAX_WIDTH, byViewport));
}

/** Clamp a requested width to [320, min(900, 60% of the viewport)], whole px. */
export function clampDrawerWidth(width: number, viewportWidth: number): number {
  const max = drawerMaxWidth(viewportWidth);
  const requested = Number.isFinite(width) ? width : DRAWER_DEFAULT_WIDTH;
  return Math.round(Math.min(max, Math.max(DRAWER_MIN_WIDTH, requested)));
}

/**
 * A stored width, or the default when nothing usable is stored (missing key,
 * blocked storage, garbage, zero or negative). A number outside the absolute
 * bounds is pulled inside them; the viewport cap is applied at render time so a
 * width chosen on a wide screen comes back when the window is wide again.
 */
export function parseStoredDrawerWidth(raw: string | null): number {
  if (raw === null || raw.trim() === '') return DRAWER_DEFAULT_WIDTH;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return DRAWER_DEFAULT_WIDTH;
  return Math.round(Math.min(DRAWER_MAX_WIDTH, Math.max(DRAWER_MIN_WIDTH, n)));
}

/**
 * The separator's keyboard map: ArrowLeft narrows and ArrowRight widens by
 * 16 px (64 px with Shift), Home goes to the minimum and End to the maximum.
 * Returns the new width, or null for a key the handle does not use (so the
 * event keeps its default, and Escape still reaches the global listener).
 */
export function drawerWidthForKey(
  key: string,
  shiftKey: boolean,
  current: number,
  viewportWidth: number,
): number | null {
  const step = shiftKey ? DRAWER_BIG_STEP : DRAWER_STEP;
  switch (key) {
    case 'ArrowLeft':
      return clampDrawerWidth(current - step, viewportWidth);
    case 'ArrowRight':
      return clampDrawerWidth(current + step, viewportWidth);
    case 'Home':
      return DRAWER_MIN_WIDTH;
    case 'End':
      return drawerMaxWidth(viewportWidth);
    default:
      return null;
  }
}

function currentViewportWidth(): number {
  return typeof window === 'undefined' ? 1440 : window.innerWidth;
}

/**
 * Width of the technique drawer (the right-hand overlay opened by clicking a
 * cell). The preference is read synchronously when the service is created, so
 * the drawer's first render already has it (no flash on reload); the rendered
 * width is that preference clamped to the current viewport.
 */
@Injectable({ providedIn: 'root' })
export class DrawerWidthService {
  readonly min = DRAWER_MIN_WIDTH;
  readonly defaultWidth = DRAWER_DEFAULT_WIDTH;

  private readonly preferred = signal(parseStoredDrawerWidth(readPref(DRAWER_WIDTH_KEY)));
  private readonly viewport = signal(currentViewportWidth());

  /** The live maximum for this viewport. */
  readonly max = computed(() => drawerMaxWidth(this.viewport()));
  /** The width the drawer renders at. */
  readonly width = computed(() => clampDrawerWidth(this.preferred(), this.viewport()));

  constructor() {
    if (typeof window === 'undefined') return;
    const onResize = () => this.viewport.set(window.innerWidth);
    window.addEventListener('resize', onResize);
    inject(DestroyRef).onDestroy(() => window.removeEventListener('resize', onResize));
  }

  /** Set the width and persist it. */
  setWidth(px: number): void {
    this.preview(px);
    this.commit();
  }

  /** Set the width without persisting (live pointer drag). */
  preview(px: number): void {
    this.preferred.set(clampDrawerWidth(px, this.viewport()));
  }

  /** Persist the current width (end of a drag). */
  commit(): void {
    writePref(DRAWER_WIDTH_KEY, String(this.width()));
  }

  /** Apply a key from the separator's keyboard map; true when the key was used. */
  handleKey(key: string, shiftKey: boolean): boolean {
    const next = drawerWidthForKey(key, shiftKey, this.width(), this.viewport());
    if (next === null) return false;
    this.setWidth(next);
    return true;
  }

  /** Back to the default width; the stored preference is removed. */
  reset(): void {
    this.preferred.set(DRAWER_DEFAULT_WIDTH);
    writePref(DRAWER_WIDTH_KEY, null);
  }

  /** Re-read the viewport width (the resize listener calls the same thing). */
  syncViewport(width: number = currentViewportWidth()): void {
    this.viewport.set(width);
  }
}
