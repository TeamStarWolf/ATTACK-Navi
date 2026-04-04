import { TestBed } from '@angular/core/testing';
import { CustomGroupService, CustomGroup } from './custom-group.service';

describe('CustomGroupService', () => {
  let service: CustomGroupService;
  const STORAGE_KEY = 'mitre-nav-custom-groups-v1';

  const baseGroup: Omit<CustomGroup, 'id' | 'createdAt' | 'updatedAt'> = {
    name: 'Test Group',
    aliases: ['TestAlias'],
    description: 'A test threat group',
    techniqueIds: ['T1059', 'T1078'],
  };

  beforeEach(() => {
    localStorage.removeItem(STORAGE_KEY);
    TestBed.configureTestingModule({});
    service = TestBed.inject(CustomGroupService);
  });

  afterEach(() => {
    localStorage.removeItem(STORAGE_KEY);
  });

  // --- create() ---

  it('should create a group with auto-generated ID CG-001', () => {
    const result = service.create({ ...baseGroup });
    expect(result.id).toBe('CG-001');
  });

  it('should store the created group in localStorage', () => {
    service.create({ ...baseGroup });
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!) as CustomGroup[];
    expect(stored.length).toBe(1);
    expect(stored[0].name).toBe('Test Group');
  });

  it('should auto-increment IDs for multiple creates', () => {
    service.create({ ...baseGroup });
    const second = service.create({ ...baseGroup, name: 'Group 2' });
    expect(second.id).toBe('CG-002');
  });

  it('should set createdAt and updatedAt timestamps on create', () => {
    const result = service.create({ ...baseGroup });
    expect(result.createdAt).toBeTruthy();
    expect(result.updatedAt).toBeTruthy();
  });

  // --- update() ---

  it('should update the name of an existing group', () => {
    const created = service.create({ ...baseGroup });
    service.update(created.id, { name: 'Updated Group Name' });
    expect(service.getById(created.id)!.name).toBe('Updated Group Name');
  });

  it('should update the description of an existing group', () => {
    const created = service.create({ ...baseGroup });
    service.update(created.id, { description: 'New description' });
    expect(service.getById(created.id)!.description).toBe('New description');
  });

  it('should preserve the id on update', () => {
    const created = service.create({ ...baseGroup });
    service.update(created.id, { id: 'CG-999' } as any);
    expect(service.getById('CG-001')).toBeTruthy();
    expect(service.getById('CG-999')).toBeUndefined();
  });

  it('should preserve createdAt on update', () => {
    const created = service.create({ ...baseGroup });
    const originalCreatedAt = created.createdAt;
    service.update(created.id, { name: 'Updated' });
    expect(service.getById(created.id)!.createdAt).toBe(originalCreatedAt);
  });

  // --- delete() ---

  it('should remove the group from the list', () => {
    const created = service.create({ ...baseGroup });
    service.delete(created.id);
    expect(service.getAll().length).toBe(0);
  });

  it('should update count$ after delete', (done) => {
    const created = service.create({ ...baseGroup });
    service.delete(created.id);
    service.count$.subscribe(count => {
      expect(count).toBe(0);
      done();
    });
  });

  it('should remove from localStorage after delete', () => {
    const created = service.create({ ...baseGroup });
    service.delete(created.id);
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!) as CustomGroup[];
    expect(stored.length).toBe(0);
  });

  // --- getAll() ---

  it('should return all groups', () => {
    service.create({ ...baseGroup });
    service.create({ ...baseGroup, name: 'Group 2' });
    expect(service.getAll().length).toBe(2);
  });

  it('should return empty array when no groups exist', () => {
    expect(service.getAll().length).toBe(0);
  });

  // --- getById() ---

  it('should return the correct group by id', () => {
    const created = service.create({ ...baseGroup });
    const found = service.getById(created.id);
    expect(found).toBeTruthy();
    expect(found!.name).toBe('Test Group');
  });

  it('should return undefined for a non-existent id', () => {
    expect(service.getById('CG-999')).toBeUndefined();
  });

  // --- BehaviorSubjects ---

  it('should emit the updated list via groups$', (done) => {
    service.create({ ...baseGroup });
    service.groups$.subscribe(list => {
      if (list.length === 1) {
        expect(list[0].name).toBe('Test Group');
        done();
      }
    });
  });

  it('should emit the correct count via count$ after create', () => {
    service.create({ ...baseGroup });
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
