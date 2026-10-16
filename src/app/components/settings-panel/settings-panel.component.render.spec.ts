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

  it('opens on Scoring Weights with the default weights summing to 100 and the sample score', () => {
    expect(text('.tab-btn.active')).toBe('Scoring Weights');
    expect(text('.weights-total')).toBe('Total: 100 / 100 ✓');
    expect(host.querySelector('.weights-total')!.classList).toContain('weights-ok');
    // 20/20/20/20/20: mitigations 3/5 of 20 = 12, CAR 20, Atomic 20, D3FEND 0, NIST 20 -> 72%.
    expect(text('.preview-score-val')).toBe('72%');
    expect(host.querySelector('.preview-score-val')!.classList).toContain('score-orange');
  });

  it('moving a weight slider persists the weight and flags a total that is not 100', () => {
    const slider = host.querySelector('.weight-row .slider-input') as HTMLInputElement; // Mitigations
    slider.value = '60';
    slider.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(settings.current.scoringWeights.mitigations).toBe(60);
    expect(text('.weights-total')).toBe('Total: 140 / 100 ⚠');
    expect(host.querySelector('.weights-total')!.classList).toContain('weights-bad');
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

  it('characterizes a known drift: the Default swatch preview is not the ramp that is applied', () => {
    // The panel's preview list and SettingsService.COLOR_THEMES are separate copies;
    // they have diverged for 'default' (and 'blueorange'). Pinned so a fix is a
    // deliberate, visible change.
    tab('Display');
    const swatch = [...host.querySelectorAll('.theme-swatch')].find(b => b.querySelector('.swatch-label')!.textContent!.trim() === 'Default')!;
    const preview = [...swatch.querySelectorAll('.swatch-dot')].map(d => (d as HTMLElement).style.background);
    expect(preview[1]).toBe('rgb(230, 81, 0)');          // #e65100 shown
    expect(settings.getCoverageColors()[1]).toBe('#b45309'); // #b45309 applied
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
