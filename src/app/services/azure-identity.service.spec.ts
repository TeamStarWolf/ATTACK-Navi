// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { AzureIdentityService } from './azure-identity.service';

describe('AzureIdentityService', () => {
  let service: AzureIdentityService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(AzureIdentityService);
  });

  describe('getAllAttacks', () => {
    it('returns the bundled Azure AD attack pattern catalogue', () => {
      const all = service.getAllAttacks();
      expect(all.length).toBeGreaterThan(0);
      expect(all[0].name).toBeTruthy();
      expect(all[0].techniqueIds.length).toBeGreaterThan(0);
    });
  });

  describe('getAttacksForTechnique', () => {
    it('returns attacks for a known mapped technique', () => {
      const attacks = service.getAttacksForTechnique('T1528');  // Consent Grant Attack
      expect(attacks.length).toBeGreaterThanOrEqual(1);
      expect(attacks[0].techniqueIds).toContain('T1528');
    });

    it('returns empty for unknown technique', () => {
      expect(service.getAttacksForTechnique('T9999')).toEqual([]);
    });
  });

  describe('getByService', () => {
    it('filters by affected service (substring match)', () => {
      const azureAd = service.getByService('Azure AD');
      // Service may match by substring — every result should mention Azure AD somewhere
      azureAd.forEach(a => {
        const matched = a.affectedServices.some(s => s.includes('Azure AD'));
        expect(matched).toBe(true);
      });
    });

    it('returns empty for unknown service', () => {
      expect(service.getByService('NotARealService')).toEqual([]);
    });
  });
});
