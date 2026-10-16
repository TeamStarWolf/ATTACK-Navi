// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';

import { SettingsPanelComponent } from './settings-panel.component';
import { DEFAULT_SETTINGS, SettingsService } from '../../services/settings.service';
import { DataService } from '../../services/data.service';
import { TimelineService } from '../../services/timeline.service';
import { OpenCtiService } from '../../services/opencti.service';
import { MispService } from '../../services/misp.service';
import { TaxiiService } from '../../services/taxii.service';

describe('SettingsPanelComponent', () => {
  let fixture: ComponentFixture<SettingsPanelComponent>;
  let component: SettingsPanelComponent;
  let settingsService: SettingsService;
  let domain$: BehaviorSubject<unknown>;

  beforeEach(() => {
    localStorage.removeItem('mitre-nav-settings-v1');
    domain$ = new BehaviorSubject<unknown>(null);
    TestBed.configureTestingModule({
      imports: [SettingsPanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$, getCurrentAttackDomain: () => 'enterprise' } },
        { provide: TimelineService, useValue: { snapshots$: new BehaviorSubject([]), getStorageSizeKb: () => 0 } },
        { provide: OpenCtiService, useValue: {
            connected$: new BehaviorSubject(false),
            error$: new BehaviorSubject<string | null>(null),
            loading$: new BehaviorSubject(false),
            getConfig: () => ({ url: '', token: '', mode: 'direct', proxyUrl: '', connected: false }),
        } },
        { provide: MispService, useValue: {
            connected$: new BehaviorSubject(false),
            serverError$: new BehaviorSubject<string | null>(null),
            serverLoading$: new BehaviorSubject(false),
            getConfig: () => ({ url: '', apiKey: '', orgId: '', mode: 'direct', proxyUrl: '', connected: false }),
        } },
        { provide: TaxiiService, useValue: { servers$: new BehaviorSubject([]) } },
      ],
    });
    settingsService = TestBed.inject(SettingsService);
    settingsService.reset();
    fixture = TestBed.createComponent(SettingsPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  afterEach(() => {
    settingsService.reset();
    localStorage.removeItem('mitre-nav-settings-v1');
  });

  it('starts from the saved settings on the scoring tab with nothing dirty', () => {
    expect(component.activeTab).toBe('scoring');
    expect(component.settings.scoringWeights).toEqual(DEFAULT_SETTINGS.scoringWeights);
    expect(component.weightsTotal).toBe(100);
    expect(component.isDirty).toBeFalse();
  });

  it('autoNormalize rescales the weights to sum to 100 and persists them', () => {
    component.settings.scoringWeights = { mitigations: 30, car: 10, atomic: 5, d3fend: 5, nist: 0 };
    component.autoNormalize();

    const w = component.settings.scoringWeights;
    expect(w.mitigations + w.car + w.atomic + w.d3fend + w.nist).toBe(100);
    expect(w).toEqual({ mitigations: 60, car: 20, atomic: 10, d3fend: 10, nist: 0 });
    expect(settingsService.current.scoringWeights).toEqual(w);
    expect(component.isDirty).toBeFalse();
  });

  it('onWeightChange clamps each weight into its allowed range before saving', () => {
    component.settings.scoringWeights = { mitigations: 99, car: -5, atomic: 31, d3fend: 30, nist: 25 };
    component.onWeightChange();

    expect(component.settings.scoringWeights).toEqual({ mitigations: 60, car: 0, atomic: 30, d3fend: 30, nist: 20 });
    expect(settingsService.current.scoringWeights).toEqual(component.settings.scoringWeights);
  });

  it('isDirty tracks an unsaved edit and clears once applied', () => {
    component.settings.orgName = 'Blue Team';
    expect(component.isDirty).toBeTrue();

    component.applySettings();
    expect(settingsService.current.orgName).toBe('Blue Team');
    expect(component.isDirty).toBeFalse();
  });

  it('resetToDefaults restores the shipped defaults', () => {
    component.setColorTheme('monochrome');
    expect(settingsService.current.heatmapColorTheme).toBe('monochrome');

    component.resetToDefaults();
    expect(component.settings.heatmapColorTheme).toBe('default');
    expect(settingsService.current.heatmapColorTheme).toBe('default');
  });

  it('sampleCoverageScore follows the weights', () => {
    // Everything on mitigations: the sample has 3 of 5, so 60.
    component.settings.scoringWeights = { mitigations: 100, car: 0, atomic: 0, d3fend: 0, nist: 0 };
    expect(component.sampleCoverageScore).toBe(60);
    // Everything on D3FEND (absent in the sample): 0.
    component.settings.scoringWeights = { mitigations: 0, car: 0, atomic: 0, d3fend: 100, nist: 0 };
    expect(component.sampleCoverageScore).toBe(0);
    component.settings.scoringWeights = { mitigations: 0, car: 0, atomic: 0, d3fend: 0, nist: 0 };
    expect(component.sampleCoverageScore).toBe(0);
  });

  it('reflects the loaded ATT&CK release on the data tab', () => {
    domain$.next({ attackVersion: '19.2', mitigations: [{}, {}, {}] });
    fixture.detectChanges();

    expect(component.attackVersion).toBe('19.2');
    expect(component.mitigationCount).toBe(3);
    expect(settingsService.current.attackVersion).toBe('19.2');
  });
});
