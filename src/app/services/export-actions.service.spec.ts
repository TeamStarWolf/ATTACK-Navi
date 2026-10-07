// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject } from 'rxjs';
import { Domain } from '../models/domain';
import { AnnotationService } from './annotation.service';
import { BrowserFileService } from './browser-file.service';
import { AttackDomain, DataService } from './data.service';
import { ExportActionsService } from './export-actions.service';
import { FilterService } from './filter.service';
import { ImplementationService } from './implementation.service';
import { NavigatorLayerService } from './navigator-layer.service';
import { USER_LAYER_DB_NAME, UserLayerService } from './user-layer.service';

/**
 * The Navigator-layer import orchestration: pick a file → convert → save to
 * IndexedDB → activate → color the matrix → (same domain only) resolve ids and
 * apply statuses/notes → tell the analyst exactly what happened.
 */
describe('ExportActionsService.importNavigatorLayer', () => {
  let service: ExportActionsService;
  let userLayers: UserLayerService;
  let implService: ImplementationService;
  let annotations: AnnotationService;
  let filterService: jasmine.SpyObj<FilterService>;
  let pickTextFile: jasmine.Spy;
  let dataService: { domain$: BehaviorSubject<Domain | null>; currentDomain$: BehaviorSubject<AttackDomain>; switchDomain: jasmine.Spy };
  let confirmSpy: jasmine.Spy;
  let alertSpy: jasmine.Spy;
  let dbName: string;

  const STORAGE_KEYS = ['mitre-nav-impl-v1', 'mitre-nav-annotations-v1'];

  /** The parts of a loaded Enterprise 19.2 Domain this flow reads. */
  function makeDomain(): Domain {
    return {
      name: 'Enterprise ATT&CK',
      attackVersion: '19.2',
      techniques: [
        { id: 'tech-1059', attackId: 'T1059', tacticShortnames: ['execution'] },
        { id: 'tech-1685-005', attackId: 'T1685.005', tacticShortnames: ['stealth'] },
      ],
      mitigations: [{ id: 'mit-1', attackId: 'M1038' }, { id: 'mit-2', attackId: 'M1049' }],
      mitigationsByTechnique: new Map([
        ['tech-1059', [{ mitigation: { id: 'mit-1', attackId: 'M1038' } }, { mitigation: { id: 'mit-2', attackId: 'M1049' } }]],
      ]),
      supersededBy: new Map([['T1070.001', 'T1685.005']]),
    } as unknown as Domain;
  }

  function layerJson(techniques: object[], domain = 'enterprise-attack', name = 'Vendor Coverage'): string {
    return JSON.stringify({
      name,
      versions: { attack: '19', navigator: '4.9', layer: '4.5' },
      domain,
      techniques,
    });
  }

  function lastAlert(): string {
    expect(alertSpy).toHaveBeenCalledTimes(1);
    return alertSpy.calls.mostRecent().args[0] as string;
  }

  /** UserLayerService closes each connection after its transaction, so a `blocked` event only delays `success`. */
  function deleteDatabase(name: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.deleteDatabase(name);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  beforeEach(() => {
    for (const key of STORAGE_KEYS) localStorage.removeItem(key);
    dbName = `attack-navi-export-actions-spec-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

    dataService = {
      domain$: new BehaviorSubject<Domain | null>(makeDomain()),
      currentDomain$: new BehaviorSubject<AttackDomain>('enterprise'),
      switchDomain: jasmine.createSpy('switchDomain'),
    };
    filterService = jasmine.createSpyObj<FilterService>('FilterService', ['setHeatmapMode', 'getStateSnapshot']);
    pickTextFile = jasmine.createSpy('pickTextFile');

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: DataService, useValue: dataService },
        { provide: FilterService, useValue: filterService },
        { provide: BrowserFileService, useValue: { pickTextFile, downloadText: () => {}, downloadJson: () => {} } },
        { provide: USER_LAYER_DB_NAME, useValue: dbName },
      ],
    });
    service = TestBed.inject(ExportActionsService);
    userLayers = TestBed.inject(UserLayerService);
    implService = TestBed.inject(ImplementationService);
    annotations = TestBed.inject(AnnotationService);
    confirmSpy = spyOn(window, 'confirm').and.returnValue(false);
    alertSpy = spyOn(window, 'alert').and.stub();
  });

  afterEach(async () => {
    for (const key of STORAGE_KEYS) localStorage.removeItem(key);
    await deleteDatabase(dbName);
  });

  it('does nothing when the file picker is cancelled or the file is not a layer', async () => {
    pickTextFile.and.resolveTo(null);
    await service.importNavigatorLayer();
    expect(alertSpy).not.toHaveBeenCalled();
    expect(userLayers.layers.length).toBe(0);

    pickTextFile.and.resolveTo('{"nope":true}');
    await service.importNavigatorLayer();
    expect(lastAlert()).toContain('missing techniques');
    expect(userLayers.layers.length).toBe(0);
    expect(userLayers.activeLayer).toBeNull();
    expect(filterService.setHeatmapMode).not.toHaveBeenCalled();
  });

  it('matching domain: saves, activates, colors the matrix, applies notes and reports honest counts', async () => {
    pickTextFile.and.resolveTo(layerJson([
      { techniqueID: 'T1059', tactic: 'execution', score: 80, comment: 'Observed in the wild' },
    ]));

    await service.importNavigatorLayer();

    // Persisted to IndexedDB and made active.
    expect(userLayers.layers.length).toBe(1);
    const saved = await userLayers.getLayer(userLayers.layers[0].id);
    expect(saved?.name).toBe('Vendor Coverage');
    expect(userLayers.activeLayer?.id).toBe(saved?.id);
    expect(userLayers.getScore('T1059')).toBe(80);
    expect(filterService.setHeatmapMode).toHaveBeenCalledWith('library');
    expect(dataService.switchDomain).not.toHaveBeenCalled();

    // The foreign comment became a note; nothing status-like was in it, so no prompt.
    expect(annotations.getAnnotation('T1059')?.note).toBe('Observed in the wild');
    expect(confirmSpy).not.toHaveBeenCalled();
    expect(implService.getStatusMap().size).toBe(0);

    const text = lastAlert();
    expect(text).toContain('Layer "Vendor Coverage" imported and saved (1 technique entries)');
    expect(text).toContain('1 of 1 technique ids resolved in Enterprise ATT&CK v19.2');
    expect(text).toContain('0 statuses and 1 notes applied');
  });

  it('reports retired and unknown ids instead of claiming every entry was imported', async () => {
    pickTextFile.and.resolveTo(layerJson([
      { techniqueID: 'T1070.001', tactic: 'defense-evasion', comment: 'cleared logs note' },
      { techniqueID: 'T9999', tactic: 'execution', comment: 'typo' },
      { techniqueID: 'T1059', tactic: 'execution', comment: 'shell' },
    ]));

    await service.importNavigatorLayer();

    const text = lastAlert();
    expect(text).toContain('imported and saved (3 technique entries)');
    expect(text).toContain('2 of 3 technique ids resolved in Enterprise ATT&CK v19.2');
    expect(text).toContain('1 retired id(s) mapped to their replacement (T1070.001 -> T1685.005)');
    expect(text).toContain('1 of 3 technique ids do not exist in Enterprise ATT&CK v19.2');
    expect(text).toContain('T9999');
    // The retired entry's note landed on the live replacement, and the cell is colored through the alias.
    expect(annotations.getAnnotation('T1685.005')?.note).toBe('cleared logs note');
    expect(annotations.getAnnotation('T9999')).toBeUndefined();
    expect(userLayers.getEntry('T1685.005')?.comment).toBe('cleared logs note');
  });

  it('a layer whose ids all belong to another matrix is saved but clearly reported as coloring nothing', async () => {
    pickTextFile.and.resolveTo(layerJson([
      { techniqueID: 'AML.T0014', tactic: 'discovery', score: 1 },
      { techniqueID: 'AML.T0040', tactic: 'ai-model-access', score: 1 },
    ], 'atlas', 'Lylat Coverage — ATLAS (AI/ML)'));

    await service.importNavigatorLayer();

    const text = lastAlert();
    expect(text).toContain('Unrecognized layer domain "atlas"');
    expect(text).toContain('None of this layer\'s 2 technique ids exist in Enterprise ATT&CK v19.2');
    expect(text).toContain('0 of 2 technique ids resolved');
    expect(userLayers.layers.length).toBe(1);
    expect(dataService.switchDomain).not.toHaveBeenCalled();
  });

  it('mismatched domain, analyst keeps the loaded one: warns, still saves and applies notes', async () => {
    confirmSpy.and.returnValue(false);
    pickTextFile.and.resolveTo(layerJson([{ techniqueID: 'T1059', comment: 'from an ICS layer' }], 'ics-attack'));

    await service.importNavigatorLayer();

    expect(confirmSpy).toHaveBeenCalledTimes(1);
    expect(confirmSpy.calls.mostRecent().args[0]).toContain('This layer targets ICS ATT&CK');
    expect(dataService.switchDomain).not.toHaveBeenCalled();
    expect(userLayers.layers.length).toBe(1);
    expect(annotations.getAnnotation('T1059')?.note).toBe('from an ICS layer');
    const text = lastAlert();
    expect(text).toContain('Kept ENTERPRISE');
    expect(text).toContain('1 of 1 technique ids resolved');
  });

  it('mismatched domain, analyst switches: switches domain and does NOT apply statuses/notes against the old one', async () => {
    confirmSpy.and.returnValue(true);
    pickTextFile.and.resolveTo(layerJson([{ techniqueID: 'T1059', comment: 'Status: implemented' }], 'ics-attack'));

    await service.importNavigatorLayer();

    expect(dataService.switchDomain).toHaveBeenCalledWith('ics');
    // Only the domain-switch confirm was asked; no status preview against the wrong domain.
    expect(confirmSpy).toHaveBeenCalledTimes(1);
    expect(implService.getStatusMap().size).toBe(0);
    expect(annotations.getAnnotation('T1059')).toBeUndefined();
    expect(userLayers.layers.length).toBe(1);
    expect(userLayers.activeLayer).not.toBeNull();
    expect(filterService.setHeatmapMode).toHaveBeenCalledWith('library');
    const text = lastAlert();
    expect(text).toContain('Switched to ICS ATT&CK');
    expect(text).not.toContain('statuses and');
  });

  it('save failure: the layer is still applied and the alert says it was not saved', async () => {
    spyOn(userLayers, 'saveLayer').and.rejectWith(new Error('QuotaExceededError'));
    pickTextFile.and.resolveTo(layerJson([{ techniqueID: 'T1059', comment: 'note' }]));

    await service.importNavigatorLayer();

    expect(userLayers.activeLayer?.name).toBe('Vendor Coverage');
    expect(userLayers.layers.length).toBe(0);
    expect(filterService.setHeatmapMode).toHaveBeenCalledWith('library');
    expect(annotations.getAnnotation('T1059')?.note).toBe('note');
    expect(lastAlert()).toContain('could not be saved to this browser');
  });

  it('comment-derived statuses are previewed and written only when the analyst confirms', async () => {
    pickTextFile.and.resolveTo(layerJson([{ techniqueID: 'T1059', comment: 'Status: implemented' }]));

    confirmSpy.and.returnValue(false);
    await service.importNavigatorLayer();

    expect(confirmSpy).toHaveBeenCalledTimes(1);
    const preview = confirmSpy.calls.mostRecent().args[0] as string;
    expect(preview).toContain('Set 2 mitigation status(es) on 1 technique(s)');
    expect(preview).toContain('T1059: 2 mitigation(s) -> implemented');
    expect(preview).toContain('"Status: implemented"');
    expect(implService.getStatusMap().size).toBe(0);
    let text = lastAlert();
    expect(text).toContain('0 statuses and 1 notes applied');
    expect(text).toContain('Comment-derived statuses were not applied');

    alertSpy.calls.reset();
    confirmSpy.and.returnValue(true);
    await service.importNavigatorLayer();

    expect(implService.getStatus('mit-1')).toBe('implemented');
    expect(implService.getStatus('mit-2')).toBe('implemented');
    text = lastAlert();
    expect(text).toContain('2 statuses and 0 notes applied');
    expect(text).not.toContain('were not applied');
  });

  it('a negated comment never prompts and never sets a status', async () => {
    pickTextFile.and.resolveTo(layerJson([
      { techniqueID: 'T1059', comment: 'Not implemented - no rule yet' },
    ]));

    await service.importNavigatorLayer();

    expect(confirmSpy).not.toHaveBeenCalled();
    expect(implService.getStatusMap().size).toBe(0);
    expect(annotations.getAnnotation('T1059')?.note).toBe('Not implemented - no rule yet');
    expect(lastAlert()).toContain('0 statuses and 1 notes applied');
  });

  it('an ATTACK-Navi round-trip layer restores exact statuses without a prompt', async () => {
    pickTextFile.and.resolveTo(layerJson([{
      techniqueID: 'T1059',
      comment: 'Status: planned',
      metadata: [{ name: 'attack-navi:mitStatuses', value: 'M1038=implemented;M1049=planned' }],
    }]));

    await service.importNavigatorLayer();

    expect(confirmSpy).not.toHaveBeenCalled();
    expect(implService.getStatus('mit-1')).toBe('implemented');
    expect(implService.getStatus('mit-2')).toBe('planned');
    expect(lastAlert()).toContain('2 statuses and 0 notes applied');
  });

  it('a failure in the status/note leg is reported, not swallowed', async () => {
    spyOn(TestBed.inject(NavigatorLayerService), 'importLayer').and.rejectWith(new Error('boom'));
    pickTextFile.and.resolveTo(layerJson([{ techniqueID: 'T1059', comment: 'x' }]));

    await service.importNavigatorLayer();

    expect(userLayers.layers.length).toBe(1);
    expect(lastAlert()).toContain('Statuses and notes were not applied: boom');
  });
});
