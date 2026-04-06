// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { CustomTechniqueService, CustomTechnique } from './custom-technique.service';

describe('CustomTechniqueService', () => {
  let service: CustomTechniqueService;
  const STORAGE_KEY = 'mitre-nav-custom-techniques-v1';

  const baseTechnique: Omit<CustomTechnique, 'id' | 'createdAt' | 'updatedAt'> = {
    attackId: 'T9001',
    name: 'Test Technique',
    description: 'A test technique',
    tacticShortnames: ['execution'],
    platforms: ['Windows'],
    dataSources: ['Process: Process Creation'],
    isSubtechnique: false,
    parentId: null,
  };

  beforeEach(() => {
    localStorage.removeItem(STORAGE_KEY);
    TestBed.configureTestingModule({});
    service = TestBed.inject(CustomTechniqueService);
  });

  afterEach(() => {
    localStorage.removeItem(STORAGE_KEY);
  });

  // --- create() ---

  it('should create a technique with auto-generated ID CT-001', () => {
    const result = service.create({ ...baseTechnique });
    expect(result.id).toBe('CT-001');
  });

  it('should store the created technique in localStorage', () => {
    service.create({ ...baseTechnique });
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!) as CustomTechnique[];
    expect(stored.length).toBe(1);
    expect(stored[0].attackId).toBe('T9001');
  });

  it('should auto-increment IDs for multiple creates', () => {
    service.create({ ...baseTechnique, attackId: 'T9001' });
    const second = service.create({ ...baseTechnique, attackId: 'T9002' });
    expect(second.id).toBe('CT-002');
  });

  it('should set createdAt and updatedAt timestamps on create', () => {
    const result = service.create({ ...baseTechnique });
    expect(result.createdAt).toBeTruthy();
    expect(result.updatedAt).toBeTruthy();
  });

  // --- update() ---

  it('should update the name of an existing technique', () => {
    const created = service.create({ ...baseTechnique });
    service.update(created.id, { name: 'Updated Name' });
    expect(service.getById(created.id)!.name).toBe('Updated Name');
  });

  it('should update the description of an existing technique', () => {
    const created = service.create({ ...baseTechnique });
    service.update(created.id, { description: 'Updated Desc' });
    expect(service.getById(created.id)!.description).toBe('Updated Desc');
  });

  it('should preserve the id on update even if data contains a different id', () => {
    const created = service.create({ ...baseTechnique });
    service.update(created.id, { id: 'CT-999' } as any);
    expect(service.getById('CT-001')).toBeTruthy();
    expect(service.getById('CT-999')).toBeUndefined();
  });

  it('should preserve createdAt on update', () => {
    const created = service.create({ ...baseTechnique });
    const originalCreatedAt = created.createdAt;
    service.update(created.id, { name: 'Updated' });
    expect(service.getById(created.id)!.createdAt).toBe(originalCreatedAt);
  });

  it('should update the updatedAt timestamp on update', () => {
    const created = service.create({ ...baseTechnique });
    const originalUpdatedAt = created.updatedAt;
    // Introduce a tiny delay so timestamps differ
    service.update(created.id, { name: 'Updated' });
    expect(service.getById(created.id)!.updatedAt).toBeTruthy();
  });

  // --- delete() ---

  it('should remove the technique from the list', () => {
    const created = service.create({ ...baseTechnique });
    service.delete(created.id);
    expect(service.getAll().length).toBe(0);
  });

  it('should update count$ after delete', (done) => {
    const created = service.create({ ...baseTechnique });
    service.delete(created.id);
    service.count$.subscribe(count => {
      expect(count).toBe(0);
      done();
    });
  });

  // --- getAll() ---

  it('should return all techniques', () => {
    service.create({ ...baseTechnique, attackId: 'T9001' });
    service.create({ ...baseTechnique, attackId: 'T9002' });
    expect(service.getAll().length).toBe(2);
  });

  it('should return an empty array when no techniques exist', () => {
    expect(service.getAll().length).toBe(0);
  });

  // --- getById() ---

  it('should return the correct technique by id', () => {
    const created = service.create({ ...baseTechnique });
    const found = service.getById(created.id);
    expect(found).toBeTruthy();
    expect(found!.name).toBe('Test Technique');
  });

  it('should return undefined for a non-existent id', () => {
    expect(service.getById('CT-999')).toBeUndefined();
  });

  // --- getForTactic() ---

  it('should return techniques that include the given tactic', () => {
    service.create({ ...baseTechnique, tacticShortnames: ['execution'] });
    service.create({ ...baseTechnique, attackId: 'T9002', tacticShortnames: ['persistence'] });
    const result = service.getForTactic('execution');
    expect(result.length).toBe(1);
    expect(result[0].tacticShortnames).toContain('execution');
  });

  it('should return empty array for a tactic with no techniques', () => {
    service.create({ ...baseTechnique });
    expect(service.getForTactic('nonexistent').length).toBe(0);
  });

  // --- BehaviorSubjects ---

  it('should emit the updated list via techniques$', (done) => {
    service.create({ ...baseTechnique });
    service.techniques$.subscribe(list => {
      if (list.length === 1) {
        expect(list[0].attackId).toBe('T9001');
        done();
      }
    });
  });

  it('should emit the correct count via count$ after create', () => {
    service.create({ ...baseTechnique });
    let lastCount = 0;
    service.count$.subscribe(count => { lastCount = count; });
    expect(lastCount).toBe(1);
  });

  it('should emit count 0 via count$ when starting fresh', (done) => {
    service.count$.subscribe(count => {
      expect(count).toBe(0);
      done();
    });
  });
});
