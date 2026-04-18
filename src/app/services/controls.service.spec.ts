// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { ControlsService } from './controls.service';

describe('ControlsService', () => {
  let service: ControlsService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(ControlsService);
  });

  afterEach(() => localStorage.clear());

  describe('CRUD lifecycle', () => {
    it('starts with empty controls list', (done) => {
      service.controls$.subscribe(controls => {
        expect(controls).toEqual([]);
        done();
      });
    });

    it('addControl appends a new control with auto-generated id', (done) => {
      service.addControl({
        name: 'EDR Block',
        description: 'Block suspicious binaries',
        framework: 'NIST',
        category: 'EDR',
        status: 'planned',
        techniqueIds: ['T1059'],
      } as any);
      service.controls$.subscribe(controls => {
        expect(controls.length).toBe(1);
        expect(controls[0].name).toBe('EDR Block');
        expect(controls[0].id).toBeTruthy();
        done();
      });
    });

    it('updateControl mutates the matching id', () => {
      service.addControl({ name: 'X', description: '', framework: 'NIST', category: 'EDR', status: 'planned', techniqueIds: [] } as any);
      let saved: any[] = [];
      service.controls$.subscribe(c => (saved = c));
      const id = saved[0].id;
      service.updateControl(id, { name: 'X-renamed' });
      expect(saved.find(c => c.id === id)!.name).toBe('X-renamed');
    });

    it('removeControl deletes the matching id', () => {
      service.addControl({ name: 'doomed', description: '', framework: 'NIST', category: 'EDR', status: 'planned', techniqueIds: [] } as any);
      let saved: any[] = [];
      service.controls$.subscribe(c => (saved = c));
      const id = saved[0].id;
      service.removeControl(id);
      expect(saved.find(c => c.id === id)).toBeUndefined();
    });
  });

  describe('exportJson', () => {
    it('returns valid JSON of the current controls list', () => {
      service.addControl({ name: 'X', description: '', framework: 'NIST', category: 'EDR', status: 'planned', techniqueIds: [] } as any);
      const json = service.exportJson();
      const parsed = JSON.parse(json);
      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed[0].name).toBe('X');
    });
  });
});
