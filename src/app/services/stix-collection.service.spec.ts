import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { StixCollectionService, ImportSummary } from './stix-collection.service';
import { CustomTechniqueService } from './custom-technique.service';
import { CustomGroupService } from './custom-group.service';
import { CustomMitigationService } from './custom-mitigation.service';
import { AnnotationService } from './annotation.service';

describe('StixCollectionService', () => {
  let service: StixCollectionService;
  let techniqueSvc: CustomTechniqueService;
  let groupSvc: CustomGroupService;
  let mitigationSvc: CustomMitigationService;
  let annotationSvc: AnnotationService;

  const TECHNIQUE_KEY = 'mitre-nav-custom-techniques-v1';
  const GROUP_KEY = 'mitre-nav-custom-groups-v1';
  const MITIGATION_KEY = 'mitre-nav-custom-mitigations-v1';
  const ANNOTATION_KEY = 'mitre-nav-annotations-v1';

  beforeEach(() => {
    localStorage.removeItem(TECHNIQUE_KEY);
    localStorage.removeItem(GROUP_KEY);
    localStorage.removeItem(MITIGATION_KEY);
    localStorage.removeItem(ANNOTATION_KEY);

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    });

    service = TestBed.inject(StixCollectionService);
    techniqueSvc = TestBed.inject(CustomTechniqueService);
    groupSvc = TestBed.inject(CustomGroupService);
    mitigationSvc = TestBed.inject(CustomMitigationService);
    annotationSvc = TestBed.inject(AnnotationService);
  });

  afterEach(() => {
    localStorage.removeItem(TECHNIQUE_KEY);
    localStorage.removeItem(GROUP_KEY);
    localStorage.removeItem(MITIGATION_KEY);
    localStorage.removeItem(ANNOTATION_KEY);
  });

  // --- exportCollection() ---

  describe('exportCollection', () => {
    it('should produce a bundle with type "bundle"', () => {
      const bundle = service.exportCollection('Test', 'A test collection');
      expect(bundle['type']).toBe('bundle');
    });

    it('should produce a bundle with id starting with "bundle--"', () => {
      const bundle = service.exportCollection('Test', 'Desc');
      expect((bundle['id'] as string).startsWith('bundle--')).toBeTrue();
    });

    it('should contain an identity object', () => {
      const bundle = service.exportCollection('Test', 'Desc');
      const objects = bundle['objects'] as any[];
      const identities = objects.filter(o => o.type === 'identity');
      expect(identities.length).toBe(1);
    });

    it('should set the identity name and description', () => {
      const bundle = service.exportCollection('MyCollection', 'MyDesc');
      const objects = bundle['objects'] as any[];
      const identity = objects.find(o => o.type === 'identity');
      expect(identity.name).toBe('MyCollection');
      expect(identity.description).toBe('MyDesc');
    });

    it('should contain attack-pattern objects for custom techniques', () => {
      techniqueSvc.create({
        attackId: 'T9001',
        name: 'Custom Tech',
        description: 'desc',
        tacticShortnames: ['execution'],
        platforms: ['Windows'],
        dataSources: [],
        isSubtechnique: false,
        parentId: null,
      });

      const bundle = service.exportCollection('Test', 'Desc');
      const objects = bundle['objects'] as any[];
      const patterns = objects.filter(o => o.type === 'attack-pattern');
      expect(patterns.length).toBe(1);
      expect(patterns[0].name).toBe('Custom Tech');
    });

    it('should contain intrusion-set objects for custom groups', () => {
      groupSvc.create({
        name: 'Test Group',
        aliases: ['TG'],
        description: 'A group',
        techniqueIds: [],
      });

      const bundle = service.exportCollection('Test', 'Desc');
      const objects = bundle['objects'] as any[];
      const sets = objects.filter(o => o.type === 'intrusion-set');
      expect(sets.length).toBe(1);
      expect(sets[0].name).toBe('Test Group');
    });

    it('should contain relationship objects when a group uses a technique', () => {
      techniqueSvc.create({
        attackId: 'T9001',
        name: 'Tech1',
        description: '',
        tacticShortnames: ['execution'],
        platforms: [],
        dataSources: [],
        isSubtechnique: false,
        parentId: null,
      });
      groupSvc.create({
        name: 'Group1',
        aliases: [],
        description: '',
        techniqueIds: ['T9001'],
      });

      const bundle = service.exportCollection('Test', 'Desc');
      const objects = bundle['objects'] as any[];
      const rels = objects.filter(o => o.type === 'relationship');
      expect(rels.length).toBeGreaterThanOrEqual(1);
      expect(rels[0].relationship_type).toBe('uses');
    });

    it('should set spec_version 2.1 on attack-pattern objects', () => {
      techniqueSvc.create({
        attackId: 'T9001',
        name: 'Tech1',
        description: '',
        tacticShortnames: [],
        platforms: [],
        dataSources: [],
        isSubtechnique: false,
        parentId: null,
      });
      const bundle = service.exportCollection('Test', 'Desc');
      const objects = bundle['objects'] as any[];
      const pattern = objects.find(o => o.type === 'attack-pattern');
      expect(pattern.spec_version).toBe('2.1');
    });

    it('should include kill_chain_phases for techniques with tactics', () => {
      techniqueSvc.create({
        attackId: 'T9001',
        name: 'Tech1',
        description: '',
        tacticShortnames: ['persistence', 'execution'],
        platforms: [],
        dataSources: [],
        isSubtechnique: false,
        parentId: null,
      });
      const bundle = service.exportCollection('Test', 'Desc');
      const objects = bundle['objects'] as any[];
      const pattern = objects.find(o => o.type === 'attack-pattern');
      expect(pattern.kill_chain_phases.length).toBe(2);
      expect(pattern.kill_chain_phases[0].kill_chain_name).toBe('mitre-attack');
    });
  });

  // --- importCollection() ---

  describe('importCollection', () => {
    function makeBundle(objects: any[]): Record<string, any> {
      return { type: 'bundle', id: 'bundle--test', objects };
    }

    it('should create custom techniques from attack-pattern objects', () => {
      const bundle = makeBundle([
        {
          type: 'attack-pattern',
          id: 'attack-pattern--abc',
          name: 'Imported Tech',
          description: 'desc',
          external_references: [{ source_name: 'mitre-attack', external_id: 'T9100' }],
          kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }],
          x_mitre_platforms: ['Linux'],
        },
      ]);
      const summary = service.importCollection(bundle);
      expect(summary.techniques).toBe(1);
      expect(techniqueSvc.getAll().length).toBe(1);
      expect(techniqueSvc.getAll()[0].name).toBe('Imported Tech');
    });

    it('should create custom groups from intrusion-set objects', () => {
      const bundle = makeBundle([
        {
          type: 'intrusion-set',
          id: 'intrusion-set--abc',
          name: 'Imported Group',
          description: 'a group',
          aliases: ['IG'],
        },
      ]);
      const summary = service.importCollection(bundle);
      expect(summary.groups).toBe(1);
      expect(groupSvc.getAll().length).toBe(1);
      expect(groupSvc.getAll()[0].name).toBe('Imported Group');
    });

    it('should return correct ImportSummary counts', () => {
      const bundle = makeBundle([
        {
          type: 'attack-pattern',
          id: 'attack-pattern--1',
          name: 'T1',
          external_references: [{ source_name: 'mitre-attack', external_id: 'T9200' }],
        },
        {
          type: 'attack-pattern',
          id: 'attack-pattern--2',
          name: 'T2',
          external_references: [{ source_name: 'mitre-attack', external_id: 'T9201' }],
        },
        {
          type: 'intrusion-set',
          id: 'intrusion-set--1',
          name: 'G1',
          description: '',
        },
      ]);
      const summary = service.importCollection(bundle);
      expect(summary.techniques).toBe(2);
      expect(summary.groups).toBe(1);
    });

    it('should deduplicate when importing the same bundle twice', () => {
      const bundle = makeBundle([
        {
          type: 'attack-pattern',
          id: 'attack-pattern--dup',
          name: 'DupTech',
          external_references: [{ source_name: 'mitre-attack', external_id: 'T9300' }],
        },
        {
          type: 'intrusion-set',
          id: 'intrusion-set--dup',
          name: 'DupGroup',
          description: '',
        },
      ]);

      const first = service.importCollection(bundle);
      const second = service.importCollection(bundle);

      expect(first.techniques).toBe(1);
      expect(second.techniques).toBe(0);
      expect(second.skipped).toBeGreaterThanOrEqual(1);
      expect(techniqueSvc.getAll().length).toBe(1);
    });

    it('should handle an empty bundle gracefully', () => {
      const summary = service.importCollection({ type: 'bundle', id: 'bundle--empty', objects: [] });
      expect(summary.techniques).toBe(0);
      expect(summary.groups).toBe(0);
    });

    it('should handle a bundle with no objects key', () => {
      const summary = service.importCollection({ type: 'bundle', id: 'bundle--none' });
      expect(summary.techniques).toBe(0);
    });
  });
});
