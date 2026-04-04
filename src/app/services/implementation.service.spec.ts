import { TestBed } from '@angular/core/testing';
import {
  ImplementationService,
  ImplStatus,
  IMPL_STATUS_LABELS,
  IMPL_STATUS_COLORS,
} from './implementation.service';

const STORAGE_KEY = 'mitre-nav-impl-v1';

describe('ImplementationService', () => {
  let service: ImplementationService;

  beforeEach(() => {
    localStorage.removeItem(STORAGE_KEY);

    TestBed.configureTestingModule({});
    service = TestBed.inject(ImplementationService);
  });

  afterEach(() => {
    localStorage.removeItem(STORAGE_KEY);
  });

  // --- Status labels and colors constants ---

  it('should define labels for all status values', () => {
    const statuses: ImplStatus[] = ['implemented', 'in-progress', 'planned', 'not-started'];
    for (const s of statuses) {
      expect(IMPL_STATUS_LABELS[s]).toBeTruthy();
    }
  });

  it('should define colors for all status values', () => {
    const statuses: ImplStatus[] = ['implemented', 'in-progress', 'planned', 'not-started'];
    for (const s of statuses) {
      expect(IMPL_STATUS_COLORS[s]).toMatch(/^#[0-9a-f]{6}$/i);
    }
  });

  // --- setStatus() ---

  it('should set a status for a mitigation', () => {
    service.setStatus('M1036', 'implemented');
    expect(service.getStatus('M1036')).toBe('implemented');
  });

  it('should update an existing status', () => {
    service.setStatus('M1036', 'planned');
    service.setStatus('M1036', 'implemented');
    expect(service.getStatus('M1036')).toBe('implemented');
  });

  it('should remove a status when set to null', () => {
    service.setStatus('M1036', 'implemented');
    service.setStatus('M1036', null);
    expect(service.getStatus('M1036')).toBeNull();
  });

  // --- getStatus() ---

  it('should return null for an untracked mitigation', () => {
    expect(service.getStatus('M9999')).toBeNull();
  });

  // --- clearStatus (set to null) ---

  it('should clear a status via setStatus(null)', () => {
    service.setStatus('M1036', 'in-progress');
    expect(service.getStatus('M1036')).toBe('in-progress');

    service.setStatus('M1036', null);
    expect(service.getStatus('M1036')).toBeNull();
  });

  // --- getStatusMap() ---

  it('should return the full status map', () => {
    service.setStatus('M1036', 'implemented');
    service.setStatus('M1050', 'planned');

    const map = service.getStatusMap();
    expect(map.size).toBe(2);
    expect(map.get('M1036')).toBe('implemented');
    expect(map.get('M1050')).toBe('planned');
  });

  // --- getImplementedIds() ---

  it('should return only implemented mitigation IDs', () => {
    service.setStatus('M1036', 'implemented');
    service.setStatus('M1050', 'planned');
    service.setStatus('M1049', 'implemented');

    const ids = service.getImplementedIds();
    expect(ids.size).toBe(2);
    expect(ids.has('M1036')).toBeTrue();
    expect(ids.has('M1049')).toBeTrue();
    expect(ids.has('M1050')).toBeFalse();
  });

  // --- summarize() ---

  it('should return correct counts by status', () => {
    service.setStatus('M1036', 'implemented');
    service.setStatus('M1050', 'planned');
    service.setStatus('M1049', 'implemented');
    service.setStatus('M1048', 'in-progress');
    service.setStatus('M1047', 'not-started');

    const summary = service.summarize();
    expect(summary['implemented']).toBe(2);
    expect(summary['planned']).toBe(1);
    expect(summary['in-progress']).toBe(1);
    expect(summary['not-started']).toBe(1);
  });

  // --- exportJson() / importJson() ---

  it('should export and re-import status data', () => {
    service.setStatus('M1036', 'implemented');
    service.setStatus('M1050', 'planned');

    const json = service.exportJson();
    service.resetAll();
    expect(service.getStatus('M1036')).toBeNull();

    service.importJson(json);
    expect(service.getStatus('M1036')).toBe('implemented');
    expect(service.getStatus('M1050')).toBe('planned');
  });

  it('should throw on invalid import data', () => {
    expect(() => service.importJson('not-json')).toThrow();
  });

  it('should throw on non-array import data', () => {
    expect(() => service.importJson('{"a": 1}')).toThrow();
  });

  it('should filter invalid status values during import', () => {
    const data = JSON.stringify([
      ['M1036', 'implemented'],
      ['M1050', 'invalid-status'],
    ]);
    service.importJson(data);
    expect(service.getStatus('M1036')).toBe('implemented');
    expect(service.getStatus('M1050')).toBeNull();
  });

  // --- resetAll() ---

  it('should clear all statuses', () => {
    service.setStatus('M1036', 'implemented');
    service.setStatus('M1050', 'planned');

    service.resetAll();

    expect(service.getStatus('M1036')).toBeNull();
    expect(service.getStatus('M1050')).toBeNull();
    expect(service.getStatusMap().size).toBe(0);
  });

  it('should remove localStorage on resetAll', () => {
    service.setStatus('M1036', 'implemented');
    expect(localStorage.getItem(STORAGE_KEY)).toBeTruthy();

    service.resetAll();
    expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  // --- status$ observable ---

  it('should emit updated map via status$', () => {
    let emittedMap: Map<string, ImplStatus> = new Map();
    service.status$.subscribe(val => { emittedMap = val; });

    service.setStatus('M1036', 'implemented');
    expect(emittedMap.get('M1036')).toBe('implemented');

    service.setStatus('M1036', null);
    expect(emittedMap.has('M1036')).toBeFalse();
  });

  // --- localStorage persistence ---

  it('should persist statuses to localStorage', () => {
    service.setStatus('M1036', 'implemented');

    const raw = localStorage.getItem(STORAGE_KEY);
    expect(raw).toBeTruthy();
    const parsed = JSON.parse(raw!);
    expect(parsed).toEqual([['M1036', 'implemented']]);
  });

  it('should restore statuses from localStorage on construction', () => {
    service.setStatus('M1036', 'implemented');
    service.setStatus('M1050', 'in-progress');

    // Create new instance (simulating app reload)
    const service2 = new ImplementationService();
    expect(service2.getStatus('M1036')).toBe('implemented');
    expect(service2.getStatus('M1050')).toBe('in-progress');
  });

  it('should handle corrupted localStorage gracefully', () => {
    localStorage.setItem(STORAGE_KEY, 'not-valid-json');

    const service2 = new ImplementationService();
    expect(service2.getStatusMap().size).toBe(0);
  });

  it('should handle non-array localStorage gracefully', () => {
    localStorage.setItem(STORAGE_KEY, '"just-a-string"');

    const service2 = new ImplementationService();
    expect(service2.getStatusMap().size).toBe(0);
  });
});
