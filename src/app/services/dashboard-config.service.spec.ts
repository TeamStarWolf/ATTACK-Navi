import { TestBed } from '@angular/core/testing';
import { DashboardConfigService, DashboardWidget } from './dashboard-config.service';

const STORAGE_KEY = 'mitre-nav-dashboard-config-v1';

describe('DashboardConfigService', () => {
  let service: DashboardConfigService;

  beforeEach(() => {
    localStorage.removeItem(STORAGE_KEY);

    TestBed.configureTestingModule({});
    service = TestBed.inject(DashboardConfigService);
  });

  afterEach(() => {
    localStorage.removeItem(STORAGE_KEY);
  });

  // --- getWidgets() ---

  it('should return default widgets on first load', () => {
    const widgets = service.getWidgets();
    expect(widgets.length).toBeGreaterThan(0);
    expect(widgets[0].id).toBe('coverage-summary');
  });

  it('should include all default widget IDs', () => {
    const ids = service.getWidgets().map(w => w.id);
    expect(ids).toContain('coverage-summary');
    expect(ids).toContain('tactic-breakdown');
    expect(ids).toContain('radar-chart');
    expect(ids).toContain('gap-summary');
    expect(ids).toContain('data-health');
    expect(ids).toContain('quick-actions');
  });

  // --- getVisibleWidgets() ---

  it('should return only visible widgets sorted by order', () => {
    const visible = service.getVisibleWidgets();
    // 'quick-actions' is hidden by default
    const ids = visible.map(w => w.id);
    expect(ids).not.toContain('quick-actions');
    // All others should be visible
    expect(ids).toContain('coverage-summary');

    // Verify sorted by order
    for (let i = 1; i < visible.length; i++) {
      expect(visible[i].order).toBeGreaterThanOrEqual(visible[i - 1].order);
    }
  });

  // --- toggleWidget() ---

  it('should hide a visible widget', () => {
    const before = service.getVisibleWidgets().map(w => w.id);
    expect(before).toContain('coverage-summary');

    service.toggleWidget('coverage-summary');

    const after = service.getVisibleWidgets().map(w => w.id);
    expect(after).not.toContain('coverage-summary');
  });

  it('should show a hidden widget', () => {
    // quick-actions is hidden by default
    const before = service.getVisibleWidgets().map(w => w.id);
    expect(before).not.toContain('quick-actions');

    service.toggleWidget('quick-actions');

    const after = service.getVisibleWidgets().map(w => w.id);
    expect(after).toContain('quick-actions');
  });

  it('should emit updated widgets via widgets$', () => {
    let emitted: DashboardWidget[] = [];
    service.widgets$.subscribe(val => { emitted = val; });

    service.toggleWidget('coverage-summary');

    const toggled = emitted.find(w => w.id === 'coverage-summary');
    expect(toggled?.visible).toBeFalse();
  });

  // --- moveWidget() ---

  it('should swap order when moving a widget down', () => {
    const before = service.getWidgets();
    const first = before.find(w => w.order === 0)!;
    const second = before.find(w => w.order === 1)!;

    service.moveWidget(first.id, 'down');

    const after = service.getWidgets();
    const movedFirst = after.find(w => w.id === first.id)!;
    const movedSecond = after.find(w => w.id === second.id)!;
    expect(movedFirst.order).toBe(1);
    expect(movedSecond.order).toBe(0);
  });

  it('should swap order when moving a widget up', () => {
    const before = service.getWidgets();
    const second = before.find(w => w.order === 1)!;
    const first = before.find(w => w.order === 0)!;

    service.moveWidget(second.id, 'up');

    const after = service.getWidgets();
    const movedSecond = after.find(w => w.id === second.id)!;
    const movedFirst = after.find(w => w.id === first.id)!;
    expect(movedSecond.order).toBe(0);
    expect(movedFirst.order).toBe(1);
  });

  it('should not change order when moving the first widget up', () => {
    const before = service.getWidgets();
    const first = before.find(w => w.order === 0)!;

    service.moveWidget(first.id, 'up');

    const after = service.getWidgets();
    const same = after.find(w => w.id === first.id)!;
    expect(same.order).toBe(0);
  });

  it('should not change order when moving the last widget down', () => {
    const before = service.getWidgets();
    const maxOrder = Math.max(...before.map(w => w.order));
    const last = before.find(w => w.order === maxOrder)!;

    service.moveWidget(last.id, 'down');

    const after = service.getWidgets();
    const same = after.find(w => w.id === last.id)!;
    expect(same.order).toBe(maxOrder);
  });

  it('should do nothing for an unknown widget id', () => {
    const before = JSON.stringify(service.getWidgets());
    service.moveWidget('nonexistent', 'up');
    const after = JSON.stringify(service.getWidgets());
    expect(after).toEqual(before);
  });

  // --- resetDefaults() ---

  it('should restore default configuration', () => {
    // Make some changes
    service.toggleWidget('coverage-summary');
    service.moveWidget('tactic-breakdown', 'up');

    service.resetDefaults();

    const widgets = service.getWidgets();
    const cs = widgets.find(w => w.id === 'coverage-summary')!;
    expect(cs.visible).toBeTrue();
    expect(cs.order).toBe(0);
  });

  // --- localStorage persistence ---

  it('should persist changes to localStorage', () => {
    service.toggleWidget('coverage-summary');

    const raw = localStorage.getItem(STORAGE_KEY);
    expect(raw).toBeTruthy();
    const parsed = JSON.parse(raw!) as DashboardWidget[];
    const cs = parsed.find((w: DashboardWidget) => w.id === 'coverage-summary');
    expect(cs?.visible).toBeFalse();
  });

  it('should restore from localStorage on construction', () => {
    // Toggle to save state
    service.toggleWidget('coverage-summary');

    // Create a new instance (simulating app reload)
    const service2 = new DashboardConfigService();
    const cs = service2.getWidgets().find(w => w.id === 'coverage-summary');
    expect(cs?.visible).toBeFalse();
  });

  it('should merge new default widgets with saved config', () => {
    // Save config
    service.toggleWidget('radar-chart');

    // Verify the saved state has radar-chart hidden
    const service2 = new DashboardConfigService();
    const rc = service2.getWidgets().find(w => w.id === 'radar-chart');
    expect(rc?.visible).toBeFalse();

    // All default widget IDs should still be present
    const ids = service2.getWidgets().map(w => w.id);
    expect(ids).toContain('coverage-summary');
    expect(ids).toContain('radar-chart');
  });

  it('should handle corrupted localStorage gracefully', () => {
    localStorage.setItem(STORAGE_KEY, 'not-valid-json');

    const service2 = new DashboardConfigService();
    // Should fall back to defaults
    const widgets = service2.getWidgets();
    expect(widgets.length).toBeGreaterThan(0);
    expect(widgets[0].id).toBe('coverage-summary');
  });
});
