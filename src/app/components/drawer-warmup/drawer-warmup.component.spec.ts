// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { type ProviderToken } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { DRAWER_BOOT_SERVICES, DrawerWarmupComponent } from './drawer-warmup.component';
import { SidebarComponent } from '../sidebar/sidebar.component';

/**
 * Providers that record the order in which each listed root service is first
 * created. Each stands in with an object whose every property is a no-op
 * function, so the drawer can be constructed (and destroyed) without its data.
 */
function recording(created: ProviderToken<unknown>[]) {
  const inert = () => new Proxy({}, { get: () => () => undefined });
  return DRAWER_BOOT_SERVICES.map((token) => ({
    provide: token,
    useFactory: () => { created.push(token); return inert(); },
  }));
}

describe('DrawerWarmupComponent', () => {
  it("creates every root service the drawer's construction creates, in the drawer's order, and renders nothing", () => {
    // The drawer's own construction (no change detection: its constructor and field initialisers only).
    const byDrawer: ProviderToken<unknown>[] = [];
    TestBed.configureTestingModule({ imports: [SidebarComponent], providers: recording(byDrawer) });
    TestBed.createComponent(SidebarComponent);
    TestBed.resetTestingModule();

    const byWarmup: ProviderToken<unknown>[] = [];
    TestBed.configureTestingModule({ imports: [DrawerWarmupComponent], providers: recording(byWarmup) });
    const fixture = TestBed.createComponent(DrawerWarmupComponent);
    fixture.detectChanges();

    expect(byDrawer).toEqual([...DRAWER_BOOT_SERVICES]);
    expect(byWarmup).toEqual(byDrawer);
    expect((fixture.nativeElement as HTMLElement).childNodes.length).toBe(0);
  });
});
