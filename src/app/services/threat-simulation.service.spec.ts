// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { ThreatSimulationService } from './threat-simulation.service';
import { DataService } from './data.service';
import { ImplementationService } from './implementation.service';
import { AttackCveService } from './attack-cve.service';
import { ExploitdbService } from './exploitdb.service';
import { EpssService } from './epss.service';
import { Domain } from '../models/domain';
import { ThreatGroup } from '../models/group';

const STUB_DOMAIN = {
  groups: [
    { id: 'apt-test', attackId: 'G9999', name: 'TestAPT', aliases: [] } as unknown as ThreatGroup,
  ],
  techniquesByGroup: new Map([
    ['apt-test', []],
  ]),
} as unknown as Domain;

describe('ThreatSimulationService', () => {
  let service: ThreatSimulationService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        ThreatSimulationService,
        { provide: DataService, useValue: {} },
        { provide: ImplementationService, useValue: { getStatusMap: () => new Map() } },
        { provide: AttackCveService, useValue: { getCvesForTechnique: () => [], getKevCvesForTechnique: () => [] } },
        { provide: ExploitdbService, useValue: { getExploitsForTechnique: () => [] } },
        { provide: EpssService, useValue: { fetchScores: () => ({ subscribe: () => {} }) } },
      ],
    });
    service = TestBed.inject(ThreatSimulationService);
  });

  describe('simulateActor', () => {
    it('returns an empty-result object for unknown actor', () => {
      const result = service.simulateActor('does-not-exist', STUB_DOMAIN);
      expect(result.techniquesTotal).toBe(0);
      expect(result.techniquesCovered).toBe(0);
      expect(result.gaps).toEqual([]);
    });

    it('returns 0% coverage for actor with no techniques mapped', () => {
      const result = service.simulateActor('apt-test', STUB_DOMAIN);
      expect(result.actor.attackId).toBe('G9999');
      expect(result.coveragePercent).toBe(0);
    });
  });

  describe('simulateMultipleActors', () => {
    it('returns one result per requested actor id', () => {
      const results = service.simulateMultipleActors(['apt-test', 'unknown'], STUB_DOMAIN);
      expect(results.length).toBe(2);
    });
  });
});
