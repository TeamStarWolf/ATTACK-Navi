// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Behavioural specs for SettingsPanelComponent against its real template and the
// real SettingsService (browser storage is cleared around every spec).
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';

import { SettingsPanelComponent } from './settings-panel.component';
import { Domain } from '../../models/domain';
import { DataService } from '../../services/data.service';
import { SettingsService } from '../../services/settings.service';
import { parseFixtureDomain, resetBrowserState } from '../../testing/lens-harness';

describe('SettingsPanelComponent (rendered)', () => {
  let fixture: ComponentFixture<SettingsPanelComponent>;
  let host: HTMLElement;
  let settings: SettingsService;
  let domain: Domain;

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      imports: [SettingsPanelComponent],
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    settings = TestBed.inject(SettingsService);
    fixture = TestBed.createComponent(SettingsPanelComponent);
    fixture.detectChanges();
    host = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => resetBrowserState());

  const text = (sel: string) => host.querySelector(sel)!.textContent!.replace(/\s+/g, ' ').trim();
  const tab = (label: string) => {
    ([...host.querySelectorAll('.tab-btn')].find(b => b.textContent!.trim() === label) as HTMLButtonElement).click();
    fixture.detectChanges();
  };

  // E1.5: the Scoring Weights tab is retired (plan 4.1: no Coverage Score, no
  // grades on reference data). The panel opens on Display, which now carries
  // the 'Reset All to Defaults' button that used to sit on the weights tab.
  it('opens on Display, with no Scoring Weights tab and the reset button in place', () => {
    const tabs = [...host.querySelectorAll('.tab-btn')].map(b => b.textContent!.trim());
    expect(tabs).toEqual(['Display', 'Organization', 'Data', 'Integrations']);
    expect(text('.tab-btn.active')).toBe('Display');
    expect(host.querySelector('.weights-total, .weight-row, .preview-score-val')).toBeNull();
    expect(host.textContent).not.toMatch(/scoring weights?/i);
    settings.update({ matrixCellSize: 'large' });
    (host.querySelector('.section-actions .btn-reset') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(settings.current.matrixCellSize).toBe('normal');
  });

  // Post-Phase-1 QA (R9d): the cell size already applies to the matrix
  // (matrix.component.spec.ts), so no note says it will apply later.
  it('offers the three cell sizes with no "will apply later" note', () => {
    tab('Display');
    const sizes = [...host.querySelectorAll('.cell-size-name')].map(e => e.textContent!.trim());
    expect(sizes).toEqual(['Compact', 'Normal', 'Large']);
    expect(host.querySelector('.cell-size-note')).toBeNull();
    expect(host.textContent).not.toMatch(/will apply when/i);
  });

  it('choosing a colour theme applies it to the coverage ramp the matrix reads', () => {
    tab('Display');
    const swatch = [...host.querySelectorAll('.theme-swatch')].find(b => b.querySelector('.swatch-label')!.textContent!.trim() === 'Monochrome') as HTMLButtonElement;
    swatch.click();
    fixture.detectChanges();
    expect(swatch.classList).toContain('selected');
    expect(settings.current.heatmapColorTheme).toBe('monochrome');
    expect(settings.getCoverageColors()).toEqual(['#111827', '#374151', '#6b7280', '#9ca3af', '#e5e7eb']);
  });

  it('the Default swatch preview equals the ramp the matrix applies (no drift)', () => {
    // The panel now reads its swatch colours from SettingsService.COLOR_THEMES,
    // the same source the matrix uses, so the preview cannot diverge from the
    // applied ramp. (It used to: the preview showed #e65100 while #b45309 applied.)
    tab('Display');
    const swatch = [...host.querySelectorAll('.theme-swatch')].find(b => b.querySelector('.swatch-label')!.textContent!.trim() === 'Default')!;
    const preview = [...swatch.querySelectorAll('.swatch-dot')].map(d => (d as HTMLElement).style.background);
    const toRgb = (hex: string) => {
      const n = parseInt(hex.slice(1), 16);
      return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`;
    };
    expect(preview).toEqual(settings.getCoverageColors().map(toRgb));
  });

  it('the colorblind-safe toggle switches the coverage ramp to the safe palette', () => {
    tab('Display');
    const before = settings.getCoverageColors();
    const box = [...host.querySelectorAll('label.checkbox-item')]
      .find(l => l.querySelector('.checkbox-label')!.textContent!.trim() === 'Colorblind-safe heatmaps')!
      .querySelector('input') as HTMLInputElement;
    box.click();
    fixture.detectChanges();
    expect(settings.current.colorblindSafe).toBeTrue();
    expect(settings.getCoverageColors()).not.toEqual(before);
  });

  it('the Data tab reports the loaded domain\'s mitigation count', () => {
    tab('Data');
    const values = [...host.querySelectorAll('.data-info-value')].map(v => v.textContent!.trim());
    expect(values).toContain(`${domain.mitigations.length} mitigations`);
    expect(domain.mitigations.length).toBe(34);
  });
});
