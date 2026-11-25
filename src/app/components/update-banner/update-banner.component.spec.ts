// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { UpdateBannerComponent } from './update-banner.component';
import { AppUpdateService } from '../../services/app-update.service';

describe('UpdateBannerComponent', () => {
  let fixture: ComponentFixture<UpdateBannerComponent>;
  const update = {
    updateReady: signal(false),
    reloadToUpdate: jasmine.createSpy('reloadToUpdate').and.resolveTo(undefined),
    dismiss: jasmine.createSpy('dismiss'),
  };

  beforeEach(async () => {
    update.updateReady.set(false);
    update.reloadToUpdate.calls.reset();
    update.dismiss.calls.reset();
    await TestBed.configureTestingModule({
      imports: [UpdateBannerComponent],
      providers: [{ provide: AppUpdateService, useValue: update }],
    }).compileComponents();
    fixture = TestBed.createComponent(UpdateBannerComponent);
    fixture.detectChanges();
  });

  it('renders nothing while no update is ready', () => {
    expect(fixture.nativeElement.querySelector('.update-banner')).toBeNull();
  });

  it('shows a labelled status prompt when an update is ready', () => {
    update.updateReady.set(true);
    fixture.detectChanges();
    const banner = fixture.nativeElement.querySelector('.update-banner');
    expect(banner).toBeTruthy();
    expect(banner.getAttribute('role')).toBe('status');
    expect(banner.getAttribute('aria-live')).toBe('polite');
    expect(banner.textContent).toContain('new version');
  });

  it('Reload asks the service to activate and reload; Later dismisses', () => {
    update.updateReady.set(true);
    fixture.detectChanges();
    const reloadBtn: HTMLButtonElement = fixture.nativeElement.querySelector('.update-banner__reload');
    const laterBtn: HTMLButtonElement = fixture.nativeElement.querySelector('.update-banner__dismiss');
    reloadBtn.click();
    expect(update.reloadToUpdate).toHaveBeenCalledTimes(1);
    laterBtn.click();
    expect(update.dismiss).toHaveBeenCalledTimes(1);
  });
});
