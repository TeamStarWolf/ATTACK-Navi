// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { LibraryLayerService } from './library-layer.service';

describe('LibraryLayerService', () => {
  let service: LibraryLayerService;
  let httpMock: HttpTestingController;

  const MANIFEST = [
    { file: 'web-application-attacks.json', name: 'TeamStarWolf - Web Application Attacks', description: 'curated' },
    { file: 'cloud-attacks.json', name: 'TeamStarWolf - Cloud Attacks', description: 'curated' },
  ];

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(LibraryLayerService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  function flushManifest(data: unknown = MANIFEST): void {
    httpMock.expectOne('assets/data/library-layers/index.json').flush(data as object);
  }

  it('loads the manifest on construction', () => {
    flushManifest();
    expect(service.manifest.length).toBe(2);
    expect(service.manifest[0].file).toBe('web-application-attacks.json');
  });

  it('is resilient to a missing/failed manifest', () => {
    httpMock.expectOne('assets/data/library-layers/index.json').error(new ProgressEvent('error'));
    expect(service.manifest).toEqual([]);
  });

  it('loads a layer, exposes its scores, and tracks the active file', () => {
    flushManifest();
    service.setActive('web-application-attacks.json');
    expect(service.activeFile).toBe('web-application-attacks.json');
    httpMock.expectOne('assets/data/library-layers/web-application-attacks.json').flush({
      name: 'TeamStarWolf - Web Application Attacks',
      description: 'curated',
      techniques: [
        { techniqueID: 'T1190', tactic: 'initial-access', score: 100 },
        { techniqueID: 'T1059.007', tactic: 'execution', score: 80 },
      ],
    });
    expect(service.getScore('T1190')).toBe(100);
    expect(service.getScore('T1059.007')).toBe(80);
    expect(service.getScore('T9999')).toBe(0);
    expect(service.maxScore()).toBe(100);
    expect(service.activeMeta()?.name).toContain('Web Application Attacks');
  });

  it('keeps the scores of the layer selected last when an earlier request resolves later', () => {
    // Pick a large layer, then immediately a small one: the small file resolves
    // first; the large one must not overwrite the active scores when it lands.
    flushManifest();
    let changes = 0;
    service.changed$.subscribe(() => changes++);
    const before = changes;

    service.setActive('web-application-attacks.json');
    service.setActive('cloud-attacks.json');
    httpMock.expectOne('assets/data/library-layers/cloud-attacks.json').flush({
      name: 'y', description: 'y', techniques: [{ techniqueID: 'T1078', score: 90 }],
    });
    expect(service.getScore('T1078')).toBe(90);
    expect(changes).toBe(before + 1);

    httpMock.expectOne('assets/data/library-layers/web-application-attacks.json').flush({
      name: 'x', description: 'x', techniques: [{ techniqueID: 'T1190', score: 50 }],
    });
    expect(service.activeFile).toBe('cloud-attacks.json');
    expect(service.getScore('T1078')).toBe(90);
    expect(service.getScore('T1190')).toBe(0);
    expect(changes).toBe(before + 1); // the stale response did not re-render

    // ...but it did populate the cache, so re-selecting it costs no request.
    service.setActive('web-application-attacks.json');
    httpMock.expectNone('assets/data/library-layers/web-application-attacks.json');
    expect(service.getScore('T1190')).toBe(50);
  });

  describe('ensureActive', () => {
    it('selects the first manifest layer when none is active', () => {
      flushManifest();
      service.ensureActive();
      expect(service.activeFile).toBe('web-application-attacks.json');
      httpMock.expectOne('assets/data/library-layers/web-application-attacks.json').flush({
        name: 'x', description: 'x', techniques: [{ techniqueID: 'T1190', score: 50 }],
      });
      expect(service.getScore('T1190')).toBe(50);
    });

    it('defers to the manifest when it has not arrived yet, then selects on arrival', () => {
      // A heat=library share link is applied before index.json resolves.
      service.ensureActive();
      expect(service.activeFile).toBeNull();
      expect(service.manifestLoaded).toBe(false);

      flushManifest();
      expect(service.manifestLoaded).toBe(true);
      expect(service.activeFile).toBe('web-application-attacks.json');
      httpMock.expectOne('assets/data/library-layers/web-application-attacks.json').flush({
        name: 'x', description: 'x', techniques: [{ techniqueID: 'T1190', score: 50 }],
      });
      expect(service.getScore('T1190')).toBe(50);
    });

    it('keeps an explicit selection made while the manifest was pending', () => {
      service.ensureActive();
      service.setActive('cloud-attacks.json');
      flushManifest();
      expect(service.activeFile).toBe('cloud-attacks.json');
      httpMock.expectOne('assets/data/library-layers/cloud-attacks.json').flush({ name: 'y', description: 'y', techniques: [] });
      httpMock.expectNone('assets/data/library-layers/web-application-attacks.json');
    });

    it('does nothing once a layer is active, and nothing when the manifest is empty', () => {
      flushManifest();
      service.setActive('cloud-attacks.json');
      httpMock.expectOne('assets/data/library-layers/cloud-attacks.json').flush({ name: 'y', description: 'y', techniques: [] });
      service.ensureActive();
      expect(service.activeFile).toBe('cloud-attacks.json');
      httpMock.expectNone('assets/data/library-layers/web-application-attacks.json');
    });

    it('reports a settled-but-empty manifest so the UI can say so', () => {
      httpMock.expectOne('assets/data/library-layers/index.json').error(new ProgressEvent('error'));
      service.ensureActive();
      expect(service.manifestLoaded).toBe(true);
      expect(service.activeFile).toBeNull();
    });
  });

  it('caches a layer and does not re-request it on re-select', () => {
    flushManifest();
    service.setActive('web-application-attacks.json');
    httpMock.expectOne('assets/data/library-layers/web-application-attacks.json').flush({
      name: 'x', description: 'x', techniques: [{ techniqueID: 'T1190', score: 50 }],
    });
    service.setActive('cloud-attacks.json');
    httpMock.expectOne('assets/data/library-layers/cloud-attacks.json').flush({
      name: 'y', description: 'y', techniques: [{ techniqueID: 'T1078', score: 90 }],
    });
    // Re-selecting the first layer should NOT trigger a new HTTP call (cached).
    service.setActive('web-application-attacks.json');
    httpMock.expectNone('assets/data/library-layers/web-application-attacks.json');
    expect(service.getScore('T1190')).toBe(50);
  });
});
