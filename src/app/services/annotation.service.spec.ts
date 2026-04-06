// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { AnnotationService, TechniqueAnnotation } from './annotation.service';

const STORAGE_KEY = 'mitre-nav-annotations-v1';

describe('AnnotationService', () => {
  let service: AnnotationService;

  beforeEach(() => {
    localStorage.removeItem(STORAGE_KEY);

    TestBed.configureTestingModule({});
    service = TestBed.inject(AnnotationService);
  });

  afterEach(() => {
    localStorage.removeItem(STORAGE_KEY);
  });

  // --- setAnnotation() ---

  it('should create an annotation for a technique', () => {
    service.setAnnotation('T1059', 'PowerShell abuse');
    const annotation = service.getAnnotation('T1059');

    expect(annotation).toBeDefined();
    expect(annotation!.note).toBe('PowerShell abuse');
    expect(annotation!.techniqueId).toBe('T1059');
  });

  it('should update an existing annotation', () => {
    service.setAnnotation('T1059', 'First note');
    service.setAnnotation('T1059', 'Updated note');

    const annotation = service.getAnnotation('T1059');
    expect(annotation!.note).toBe('Updated note');
  });

  it('should set default color when none specified', () => {
    service.setAnnotation('T1059', 'Test note');
    const annotation = service.getAnnotation('T1059');
    expect(annotation!.color).toBe('default');
  });

  it('should set valid color when specified', () => {
    service.setAnnotation('T1059', 'Red alert', 'red');
    expect(service.getAnnotation('T1059')!.color).toBe('red');

    service.setAnnotation('T1078', 'Yellow caution', 'yellow');
    expect(service.getAnnotation('T1078')!.color).toBe('yellow');

    service.setAnnotation('T1190', 'Green good', 'green');
    expect(service.getAnnotation('T1190')!.color).toBe('green');

    service.setAnnotation('T1203', 'Blue info', 'blue');
    expect(service.getAnnotation('T1203')!.color).toBe('blue');
  });

  it('should fallback to default for invalid color', () => {
    service.setAnnotation('T1059', 'Test', 'purple');
    expect(service.getAnnotation('T1059')!.color).toBe('default');
  });

  it('should set isPinned when specified', () => {
    service.setAnnotation('T1059', 'Pinned note', 'default', true);
    expect(service.getAnnotation('T1059')!.isPinned).toBeTrue();
  });

  it('should default isPinned to false', () => {
    service.setAnnotation('T1059', 'Not pinned');
    expect(service.getAnnotation('T1059')!.isPinned).toBeFalse();
  });

  it('should set updatedAt timestamp', () => {
    const before = new Date().toISOString();
    service.setAnnotation('T1059', 'Timed note');
    const after = new Date().toISOString();

    const annotation = service.getAnnotation('T1059');
    expect(annotation!.updatedAt).toBeDefined();
    expect(annotation!.updatedAt >= before).toBeTrue();
    expect(annotation!.updatedAt <= after).toBeTrue();
  });

  // --- getAnnotation() ---

  it('should return undefined for a technique without annotations', () => {
    expect(service.getAnnotation('T9999')).toBeUndefined();
  });

  // --- deleteAnnotation() ---

  it('should remove an annotation', () => {
    service.setAnnotation('T1059', 'Will be deleted');
    expect(service.getAnnotation('T1059')).toBeDefined();

    service.deleteAnnotation('T1059');
    expect(service.getAnnotation('T1059')).toBeUndefined();
  });

  it('should not throw when deleting a non-existent annotation', () => {
    expect(() => service.deleteAnnotation('T9999')).not.toThrow();
  });

  // --- hasAnnotation() ---

  it('should return true when an annotation exists', () => {
    service.setAnnotation('T1059', 'Exists');
    expect(service.hasAnnotation('T1059')).toBeTrue();
  });

  it('should return false when no annotation exists', () => {
    expect(service.hasAnnotation('T9999')).toBeFalse();
  });

  it('should return false after deletion', () => {
    service.setAnnotation('T1059', 'Exists');
    service.deleteAnnotation('T1059');
    expect(service.hasAnnotation('T1059')).toBeFalse();
  });

  // --- annotations$ observable ---

  it('should emit updated map via annotations$', () => {
    let emittedMap: Map<string, TechniqueAnnotation> = new Map();
    service.annotations$.subscribe(val => { emittedMap = val; });

    service.setAnnotation('T1059', 'Observable test');
    expect(emittedMap.has('T1059')).toBeTrue();

    service.deleteAnnotation('T1059');
    expect(emittedMap.has('T1059')).toBeFalse();
  });

  // --- all getter ---

  it('should return the current map via all getter', () => {
    service.setAnnotation('T1059', 'Note A');
    service.setAnnotation('T1078', 'Note B');

    const all = service.all;
    expect(all.size).toBe(2);
    expect(all.get('T1059')?.note).toBe('Note A');
  });

  // --- localStorage persistence ---

  it('should persist annotations to localStorage', () => {
    service.setAnnotation('T1059', 'Persisted', 'red', true);

    const raw = localStorage.getItem(STORAGE_KEY);
    expect(raw).toBeTruthy();
    const parsed = JSON.parse(raw!) as TechniqueAnnotation[];
    expect(parsed.length).toBe(1);
    expect(parsed[0].techniqueId).toBe('T1059');
    expect(parsed[0].color).toBe('red');
    expect(parsed[0].isPinned).toBeTrue();
  });

  it('should restore annotations from localStorage on construction', () => {
    // Save an annotation via the service
    service.setAnnotation('T1059', 'Survived reload', 'green');

    // Create a new instance (simulating app reload)
    const service2 = new AnnotationService();
    const annotation = service2.getAnnotation('T1059');
    expect(annotation).toBeDefined();
    expect(annotation!.note).toBe('Survived reload');
    expect(annotation!.color).toBe('green');
  });

  it('should persist deletion to localStorage', () => {
    service.setAnnotation('T1059', 'Will be removed');
    service.deleteAnnotation('T1059');

    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = JSON.parse(raw!) as TechniqueAnnotation[];
    expect(parsed.length).toBe(0);
  });

  it('should handle corrupted localStorage gracefully', () => {
    localStorage.setItem(STORAGE_KEY, 'not-valid-json');

    const service2 = new AnnotationService();
    expect(service2.all.size).toBe(0);
  });
});
