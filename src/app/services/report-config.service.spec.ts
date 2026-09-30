// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { ReportConfigService, ReportSection } from './report-config.service';

const STORAGE_KEY = 'mitre-nav-report-config-v1';

describe('ReportConfigService', () => {
  let service: ReportConfigService;

  beforeEach(() => {
    localStorage.removeItem(STORAGE_KEY);

    TestBed.configureTestingModule({});
    service = TestBed.inject(ReportConfigService);
  });

  afterEach(() => {
    localStorage.removeItem(STORAGE_KEY);
  });

  // --- getSections() ---

  it('should return default sections on first load', () => {
    const sections = service.getSections();
    expect(sections.length).toBe(6);
    expect(sections[0].id).toBe('exec-summary');
  });

  it('should include all default section IDs', () => {
    const ids = service.getSections().map(s => s.id);
    expect(ids).toContain('exec-summary');
    expect(ids).toContain('impl-status');
    expect(ids).toContain('coverage-by-tactic');
    expect(ids).toContain('exposure-gaps');
    expect(ids).toContain('control-docs');
    expect(ids).toContain('recommended-mits');
  });

  it('should expose the current config via the getter', () => {
    expect(service.current.sections.length).toBe(6);
  });

  // --- orderedVisibleSections() ---

  it('should return only visible sections sorted by order', () => {
    const visible = service.orderedVisibleSections();
    // All are visible by default
    expect(visible.length).toBe(6);

    // Verify sorted by order
    for (let i = 1; i < visible.length; i++) {
      expect(visible[i].order).toBeGreaterThanOrEqual(visible[i - 1].order);
    }
  });

  // --- toggleSection() ---

  it('should hide a visible section', () => {
    const before = service.orderedVisibleSections().map(s => s.id);
    expect(before).toContain('exec-summary');

    service.toggleSection('exec-summary');

    const after = service.orderedVisibleSections().map(s => s.id);
    expect(after).not.toContain('exec-summary');
  });

  it('should show a hidden section again', () => {
    service.toggleSection('exec-summary');
    expect(service.orderedVisibleSections().map(s => s.id)).not.toContain('exec-summary');

    service.toggleSection('exec-summary');
    expect(service.orderedVisibleSections().map(s => s.id)).toContain('exec-summary');
  });

  it('should emit updated config via config$', () => {
    let emitted: ReportSection[] = [];
    service.config$.subscribe(cfg => { emitted = cfg.sections; });

    service.toggleSection('exec-summary');

    const toggled = emitted.find(s => s.id === 'exec-summary');
    expect(toggled?.visible).toBeFalse();
  });

  // --- moveSection() ---

  it('should swap order when moving a section down', () => {
    const before = service.getSections();
    const first = before.find(s => s.order === 0)!;
    const second = before.find(s => s.order === 1)!;

    service.moveSection(first.id, 'down');

    const after = service.getSections();
    const movedFirst = after.find(s => s.id === first.id)!;
    const movedSecond = after.find(s => s.id === second.id)!;
    expect(movedFirst.order).toBe(1);
    expect(movedSecond.order).toBe(0);
  });

  it('should swap order when moving a section up', () => {
    const before = service.getSections();
    const first = before.find(s => s.order === 0)!;
    const second = before.find(s => s.order === 1)!;

    service.moveSection(second.id, 'up');

    const after = service.getSections();
    const movedSecond = after.find(s => s.id === second.id)!;
    const movedFirst = after.find(s => s.id === first.id)!;
    expect(movedSecond.order).toBe(0);
    expect(movedFirst.order).toBe(1);
  });

  it('should not change order when moving the first section up', () => {
    const first = service.getSections().find(s => s.order === 0)!;

    service.moveSection(first.id, 'up');

    const same = service.getSections().find(s => s.id === first.id)!;
    expect(same.order).toBe(0);
  });

  it('should not change order when moving the last section down', () => {
    const before = service.getSections();
    const maxOrder = Math.max(...before.map(s => s.order));
    const last = before.find(s => s.order === maxOrder)!;

    service.moveSection(last.id, 'down');

    const same = service.getSections().find(s => s.id === last.id)!;
    expect(same.order).toBe(maxOrder);
  });

  it('should do nothing for an unknown section id', () => {
    const before = JSON.stringify(service.getSections());
    service.moveSection('nonexistent', 'up');
    const after = JSON.stringify(service.getSections());
    expect(after).toEqual(before);
  });

  // --- resetDefaults() ---

  it('should restore default configuration', () => {
    service.toggleSection('exec-summary');
    service.moveSection('coverage-by-tactic', 'up');

    service.resetDefaults();

    const exec = service.getSections().find(s => s.id === 'exec-summary')!;
    expect(exec.visible).toBeTrue();
    expect(exec.order).toBe(0);
  });

  // --- localStorage persistence ---

  it('should persist changes to localStorage', () => {
    service.toggleSection('exec-summary');

    const raw = localStorage.getItem(STORAGE_KEY);
    expect(raw).toBeTruthy();
    const parsed = JSON.parse(raw!) as { sections: ReportSection[] };
    const exec = parsed.sections.find(s => s.id === 'exec-summary');
    expect(exec?.visible).toBeFalse();
  });

  it('should restore from localStorage on construction', () => {
    service.toggleSection('exec-summary');

    const service2 = new ReportConfigService();
    const exec = service2.getSections().find(s => s.id === 'exec-summary');
    expect(exec?.visible).toBeFalse();
  });

  it('should merge new default sections with an older saved blob', () => {
    // Simulate an older saved config that predates the 'recommended-mits' section.
    const oldBlob = {
      sections: [
        { id: 'exec-summary',       label: 'Executive Summary',               visible: false, order: 0 },
        { id: 'impl-status',        label: 'Implementation Status Breakdown', visible: true,  order: 1 },
        { id: 'coverage-by-tactic', label: 'Coverage by Tactic',              visible: true,  order: 2 },
        { id: 'exposure-gaps',      label: 'Highest Exposure Gaps',           visible: true,  order: 3 },
        { id: 'control-docs',       label: 'Security Control Documentation',  visible: true,  order: 4 },
      ],
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(oldBlob));

    const service2 = new ReportConfigService();
    const ids = service2.getSections().map(s => s.id);

    // The newly added section is still present after the merge...
    expect(ids).toContain('recommended-mits');
    // ...and the saved visibility of an existing section is preserved.
    const exec = service2.getSections().find(s => s.id === 'exec-summary')!;
    expect(exec.visible).toBeFalse();
    expect(service2.getSections().length).toBe(6);
  });

  it('should handle corrupted localStorage gracefully', () => {
    localStorage.setItem(STORAGE_KEY, 'not-valid-json');

    const service2 = new ReportConfigService();
    const sections = service2.getSections();
    expect(sections.length).toBe(6);
    expect(sections[0].id).toBe('exec-summary');
  });
});
