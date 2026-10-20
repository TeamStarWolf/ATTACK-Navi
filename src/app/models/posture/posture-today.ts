// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// POSTURE_TODAY (Phase 2 design §7, R14): the day proof ages are counted
// from. Day granularity (UTC midnight), refreshed hourly, so a proof window
// can lapse while the app stays open without the posture recomputing on
// every tick. Specs and the lens harness provide a fixed signal (2026-10-01).
import { DestroyRef, InjectionToken, Signal, inject, signal } from '@angular/core';

const HOUR_MS = 3_600_000;

/** UTC midnight of the day `d` falls on. */
export function postureDay(d: Date): Date {
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
}

/**
 * A day signal that starts at today's UTC midnight and moves to the next day
 * on the first hourly check after midnight. It only emits when the day
 * changes. The interval is cleared when the injector that created it is
 * destroyed.
 */
export function createPostureToday(clock: () => Date = () => new Date()): { today: Signal<Date>; refresh(): void } {
  const today = signal(postureDay(clock()));
  const refresh = (): void => {
    const next = postureDay(clock());
    if (next.getTime() !== today().getTime()) today.set(next);
  };
  return { today: today.asReadonly(), refresh };
}

export const POSTURE_TODAY = new InjectionToken<Signal<Date>>('POSTURE_TODAY', {
  providedIn: 'root',
  factory: (): Signal<Date> => {
    const { today, refresh } = createPostureToday();
    const timer = setInterval(refresh, HOUR_MS);
    inject(DestroyRef).onDestroy(() => clearInterval(timer));
    return today;
  },
});
