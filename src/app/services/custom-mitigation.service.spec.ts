// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { CustomMitigationService } from './custom-mitigation.service';

describe('CustomMitigationService', () => {
  let service: CustomMitigationService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(CustomMitigationService);
  });

  afterEach(() => localStorage.clear());

  it('starts with an empty list', () => {
    expect(service.all).toEqual([]);
  });

  it('create() returns a CustomMitigation with auto id and timestamps', () => {
    const cm = service.create({
      name: 'EDR Block PowerShell Encoded',
      description: 'Block any pwsh.exe with -enc',
      category: 'EDR',
      techniqueIds: ['T1059.001'],
      implStatus: 'planned',
    });
    expect(cm.id).toMatch(/^CM-/);
    expect(cm.createdAt).toBeTruthy();
    expect(cm.updatedAt).toBeTruthy();
    expect(service.all.length).toBe(1);
  });

  it('update() mutates by id and refreshes updatedAt', (done) => {
    const cm = service.create({
      name: 'Original',
      description: '',
      category: 'EDR',
      techniqueIds: [],
      implStatus: null,
    });
    const originalUpdated = cm.updatedAt;
    setTimeout(() => {
      service.update(cm.id, { name: 'Renamed' });
      const after = service.all.find(c => c.id === cm.id)!;
      expect(after.name).toBe('Renamed');
      expect(after.updatedAt).not.toBe(originalUpdated);
      done();
    }, 10);
  });

  it('delete() removes by id', () => {
    const cm = service.create({
      name: 'doomed', description: '', category: 'EDR', techniqueIds: [], implStatus: null,
    });
    service.delete(cm.id);
    expect(service.all).toEqual([]);
  });

  it('getForTechnique returns mitigations whose techniqueIds includes the query', () => {
    service.create({ name: 'A', description: '', category: 'EDR', techniqueIds: ['T1059.001', 'T1078'], implStatus: null });
    service.create({ name: 'B', description: '', category: 'SIEM', techniqueIds: ['T1003.001'], implStatus: null });
    expect(service.getForTechnique('T1078').length).toBe(1);
    expect(service.getForTechnique('T1003.001').length).toBe(1);
    expect(service.getForTechnique('T9999').length).toBe(0);
  });

  it('persists across service instances via localStorage', () => {
    service.create({ name: 'persistent', description: '', category: 'EDR', techniqueIds: [], implStatus: null });
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({});
    const fresh = TestBed.inject(CustomMitigationService);
    expect(fresh.all.length).toBe(1);
    expect(fresh.all[0].name).toBe('persistent');
  });
});
