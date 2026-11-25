// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { SwUpdate, VersionEvent } from '@angular/service-worker';
import { Subject } from 'rxjs';
import { AppUpdateService } from './app-update.service';

function makeSwUpdate(isEnabled: boolean) {
  const versionUpdates = new Subject<VersionEvent>();
  const unrecoverable = new Subject<{ type: string; reason: string }>();
  return {
    isEnabled,
    versionUpdates: versionUpdates.asObservable(),
    unrecoverable: unrecoverable.asObservable(),
    activateUpdate: jasmine.createSpy('activateUpdate').and.resolveTo(true),
    checkForUpdate: jasmine.createSpy('checkForUpdate').and.resolveTo(false),
    emit: (e: VersionEvent) => versionUpdates.next(e),
    emitUnrecoverable: () => unrecoverable.next({ type: 'UNRECOVERABLE_STATE', reason: 'cache gone' }),
  };
}

function create(sw: ReturnType<typeof makeSwUpdate>): AppUpdateService {
  TestBed.configureTestingModule({
    providers: [AppUpdateService, { provide: SwUpdate, useValue: sw }],
  });
  return TestBed.inject(AppUpdateService);
}

describe('AppUpdateService', () => {
  it('raises updateReady on a VERSION_READY event when the worker is enabled', () => {
    const sw = makeSwUpdate(true);
    const svc = create(sw);
    expect(svc.updateReady()).toBe(false);
    // An unrelated event does not raise it.
    sw.emit({ type: 'VERSION_DETECTED', version: { hash: 'a' } } as VersionEvent);
    expect(svc.updateReady()).toBe(false);
    sw.emit({ type: 'VERSION_READY', currentVersion: { hash: 'a' }, latestVersion: { hash: 'b' } } as VersionEvent);
    expect(svc.updateReady()).toBe(true);
    expect(svc.updateReason()).toBe('ready');
  });

  it('does not subscribe (stays inert) when the worker is disabled', () => {
    const sw = makeSwUpdate(false);
    const svc = create(sw);
    sw.emit({ type: 'VERSION_READY', currentVersion: { hash: 'a' }, latestVersion: { hash: 'b' } } as VersionEvent);
    expect(svc.updateReady()).toBe(false);
  });

  it('offers the same reload when the worker reports an unrecoverable state', () => {
    const sw = makeSwUpdate(true);
    const svc = create(sw);
    expect(svc.updateReady()).toBe(false);
    sw.emitUnrecoverable();
    expect(svc.updateReady()).toBe(true);
    expect(svc.updateReason()).toBe('unrecoverable');
  });

  it('checks for an update on an interval (for a long-open tab)', () => {
    jasmine.clock().install();
    try {
      const sw = makeSwUpdate(true);
      create(sw);
      expect(sw.checkForUpdate).not.toHaveBeenCalled();
      jasmine.clock().tick(6 * 60 * 60 * 1000 + 1);
      expect(sw.checkForUpdate).toHaveBeenCalled();
    } finally {
      jasmine.clock().uninstall();
    }
  });

  it('reloadToUpdate activates the update, then reloads', async () => {
    const sw = makeSwUpdate(true);
    const svc = create(sw);
    const reload = spyOn(svc as unknown as { reload: () => void }, 'reload');
    await svc.reloadToUpdate();
    expect(sw.activateUpdate).toHaveBeenCalledTimes(1);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('still reloads even if activateUpdate rejects', async () => {
    const sw = makeSwUpdate(true);
    sw.activateUpdate.and.rejectWith(new Error('nope'));
    const svc = create(sw);
    const reload = spyOn(svc as unknown as { reload: () => void }, 'reload');
    await svc.reloadToUpdate();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('dismiss clears the prompt', () => {
    const sw = makeSwUpdate(true);
    const svc = create(sw);
    sw.emit({ type: 'VERSION_READY', currentVersion: { hash: 'a' }, latestVersion: { hash: 'b' } } as VersionEvent);
    expect(svc.updateReady()).toBe(true);
    svc.dismiss();
    expect(svc.updateReady()).toBe(false);
  });
});
