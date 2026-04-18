// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { DocumentationService } from './documentation.service';

describe('DocumentationService', () => {
  let service: DocumentationService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(DocumentationService);
  });

  afterEach(() => localStorage.clear());

  describe('mitigation docs', () => {
    it('getMitDoc returns an empty doc for unknown id', () => {
      const doc = service.getMitDoc('M9999');
      expect(doc).toBeTruthy();
      // Empty doc shape — at minimum no thrown error
    });

    it('setMitDoc + getMitDoc round-trip', () => {
      service.setMitDoc('M1234', { notes: 'note', owner: 'me', dueDate: '', controlRefs: '', evidenceUrl: '' });
      const doc = service.getMitDoc('M1234');
      expect(doc.notes).toBe('note');
      expect(doc.owner).toBe('me');
    });
  });

  describe('technique notes', () => {
    it('getTechNote returns empty string for unknown technique', () => {
      expect(service.getTechNote('T9999')).toBe('');
    });

    it('setTechNote + getTechNote round-trip', () => {
      service.setTechNote('T1059', 'mass-detect via PowerShell ScriptBlock 4104');
      expect(service.getTechNote('T1059')).toContain('PowerShell');
    });
  });

  describe('exportJson', () => {
    it('returns a JSON string of all docs and notes', () => {
      service.setMitDoc('M1', { notes: 'cfg', owner: '', dueDate: '', controlRefs: '', evidenceUrl: '' });
      service.setTechNote('T1', 'note');
      const json = service.exportJson();
      const parsed = JSON.parse(json);
      expect(parsed).toBeTruthy();
    });
  });
});
