// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { type ProviderToken } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { DRAWER_BOOT_SERVICES, DRAWER_ON_DEMAND_SERVICES, DrawerWarmupComponent } from './drawer-warmup.component';
import { SidebarComponent } from '../sidebar/sidebar.component';

/**
 * Providers that record the order in which each listed root service is first
 * created. Each stands in with an object whose every property is a no-op
 * function, so the drawer can be constructed (and destroyed) without its data.
 */
function recording(created: ProviderToken<unknown>[]) {
  const inert = () => new Proxy({}, { get: () => () => undefined });
  return [...DRAWER_BOOT_SERVICES, ...DRAWER_ON_DEMAND_SERVICES].map((token) => ({
    provide: token,
    useFactory: () => { created.push(token); return inert(); },
  }));
}

describe('DrawerWarmupComponent', () => {
  it("creates every root service the drawer's construction creates except the on-demand ones, in the drawer's order, and renders nothing", () => {
    // The drawer's own construction (no change detection: its constructor and field initialisers only).
    const byDrawer: ProviderToken<unknown>[] = [];
    TestBed.configureTestingModule({ imports: [SidebarComponent], providers: recording(byDrawer) });
    TestBed.createComponent(SidebarComponent);
    TestBed.resetTestingModule();

    const byWarmup: ProviderToken<unknown>[] = [];
    TestBed.configureTestingModule({ imports: [DrawerWarmupComponent], providers: recording(byWarmup) });
    const fixture = TestBed.createComponent(DrawerWarmupComponent);
    fixture.detectChanges();

    // The drawer still injects the on-demand services; the warmup creates every other
    // service, in the drawer's order, and none of the on-demand ones.
    const onDemand = new Set(DRAWER_ON_DEMAND_SERVICES);
    expect(DRAWER_ON_DEMAND_SERVICES.every((t) => byDrawer.includes(t))).toBeTrue();
    expect(byDrawer.filter((t) => !onDemand.has(t))).toEqual([...DRAWER_BOOT_SERVICES]);
    expect(byWarmup).toEqual([...DRAWER_BOOT_SERVICES]);
    expect(byWarmup.some((t) => onDemand.has(t))).toBeFalse();
    expect((fixture.nativeElement as HTMLElement).childNodes.length).toBe(0);
  });
});
