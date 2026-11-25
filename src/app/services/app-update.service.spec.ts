// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { SwUpdate, VersionEvent } from '@angular/service-worker';
import { Subject } from 'rxjs';
import { AppUpdateService } from './app-update.service';

function makeSwUpdate(isEnabled: boolean) {
  const versionUpdates = new Subject<VersionEvent>();
  return {
    isEnabled,
    versionUpdates: versionUpdates.asObservable(),
    activateUpdate: jasmine.createSpy('activateUpdate').and.resolveTo(true),
    emit: (e: VersionEvent) => versionUpdates.next(e),
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
  });

  it('does not subscribe (stays inert) when the worker is disabled', () => {
    const sw = makeSwUpdate(false);
    const svc = create(sw);
    sw.emit({ type: 'VERSION_READY', currentVersion: { hash: 'a' }, latestVersion: { hash: 'b' } } as VersionEvent);
    expect(svc.updateReady()).toBe(false);
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
