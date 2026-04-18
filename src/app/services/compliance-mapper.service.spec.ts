// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { ComplianceMapperService, ComplianceFramework } from './compliance-mapper.service';
import { ImplementationService } from './implementation.service';

describe('ComplianceMapperService', () => {
  let service: ComplianceMapperService;
  let implMock: jasmine.SpyObj<ImplementationService>;

  beforeEach(() => {
    implMock = jasmine.createSpyObj<ImplementationService>('ImplementationService', ['getStatus']);
    implMock.getStatus.and.returnValue(null);

    TestBed.configureTestingModule({
      providers: [
        ComplianceMapperService,
        { provide: ImplementationService, useValue: implMock },
      ],
    });
    service = TestBed.inject(ComplianceMapperService);
  });

  describe('getFrameworks', () => {
    it('returns all three supported frameworks', () => {
      const fws = service.getFrameworks();
      expect(fws).toEqual(jasmine.arrayContaining<ComplianceFramework>(
        ['SOC 2', 'ISO 27001', 'PCI DSS']
      ));
      expect(fws.length).toBe(3);
    });
  });

  describe('getControlsForTechnique', () => {
    it('returns SOC 2 controls that map to a known technique', () => {
      const controls = service.getControlsForTechnique('T1078', 'SOC 2');
      // T1078 (Valid Accounts) maps to CC6.2 and CC6.3
      const ids = controls.map(c => c.controlId);
      expect(ids).toContain('CC6.2');
      expect(ids).toContain('CC6.3');
      expect(controls[0].description).toBeTruthy();
    });

    it('returns empty array for unknown technique', () => {
      expect(service.getControlsForTechnique('T9999', 'SOC 2')).toEqual([]);
    });

    it('handles each framework independently', () => {
      const soc2 = service.getControlsForTechnique('T1078', 'SOC 2');
      const iso = service.getControlsForTechnique('T1078', 'ISO 27001');
      const pci = service.getControlsForTechnique('T1078', 'PCI DSS');
      expect(soc2.length).toBeGreaterThan(0);
      expect(iso.length).toBeGreaterThan(0);
      expect(pci.length).toBeGreaterThan(0);
    });
  });

  describe('getTechniquesForControl', () => {
    it('returns techniques mapped to a known SOC 2 control', () => {
      const techs = service.getTechniquesForControl('CC6.2', 'SOC 2');
      expect(techs).toContain('T1078');
      expect(techs).toContain('T1021');
    });

    it('returns empty array for unknown control', () => {
      expect(service.getTechniquesForControl('NOT-REAL', 'SOC 2')).toEqual([]);
    });
  });

  describe('getAllControls', () => {
    it('returns the full control set for SOC 2', () => {
      const all = service.getAllControls('SOC 2');
      expect(all.length).toBeGreaterThan(5);
      expect(all[0].controlId).toBeTruthy();
      expect(all[0].description).toBeTruthy();
    });
  });

  describe('generateEvidenceStatement', () => {
    it('produces a statement when the technique has controls', () => {
      const statement = service.generateEvidenceStatement('T1078', 'SOC 2');
      expect(statement).toContain('T1078');
      expect(statement.length).toBeGreaterThan(20);
    });

    it('produces a fallback statement when no controls map', () => {
      const statement = service.generateEvidenceStatement('T9999', 'SOC 2');
      expect(statement).toBeTruthy();
    });
  });
});
