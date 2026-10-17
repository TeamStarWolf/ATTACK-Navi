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

  it('E1.4 (D2): the Data tab persists the ATT&CK data mode, pinned bundle by default', async () => {
    const dataFixture = TestBed.createComponent(SettingsPanelComponent);
    dataFixture.componentInstance.activeTab = 'data';
    dataFixture.detectChanges();
    await dataFixture.whenStable();
    const select = dataFixture.nativeElement.querySelector('select#attack-data-mode') as HTMLSelectElement;
    expect(select).toBeTruthy();
    expect(select.value).toBe('bundled');
    expect(settingsService.current.attackDataMode).toBe('bundled');
    expect(dataFixture.nativeElement.textContent).not.toContain('Live (GitHub STIX bundle)');

    select.value = 'live';
    select.dispatchEvent(new Event('change'));
    dataFixture.detectChanges();
    expect(settingsService.current.attackDataMode).toBe('live');
    expect(JSON.parse(localStorage.getItem('mitre-nav-settings-v1')!).attackDataMode).toBe('live');
    expect(new SettingsService().current.attackDataMode).withContext('after a reload').toBe('live');
  });

  describe('third-party notices (Data tab)', () => {
    // Reuses the suite-level TestBed set up above (its DataService stub and
    // service stubs); a second configureTestingModule here would throw because
    // the outer beforeEach has already instantiated the module.

    // The component is OnPush, so the tab is chosen before the first change
    // detection pass rather than flipped on a rendered fixture.
    function render(tab: SettingsPanelComponent['activeTab']): ComponentFixture<SettingsPanelComponent> {
      const fixture = TestBed.createComponent(SettingsPanelComponent);
      fixture.componentInstance.activeTab = tab;
      fixture.detectChanges();
      return fixture;
    }

    it('links to the shipped notices file with a relative URL that works under any base href', () => {
      const fixture = render('data');
      const link = fixture.nativeElement.querySelector('a.third-party-notices-link') as HTMLAnchorElement;
      expect(link).toBeTruthy();
      // Relative to the document base (`<base href="./">`), so it resolves on
      // GitHub Pages (/ATTACK-Navi/assets/...) and in the Docker image (/assets/...).
      expect(link.getAttribute('href')).toBe('assets/THIRD_PARTY_NOTICES.md');
      expect(link.getAttribute('target')).toBe('_blank');
      expect(link.getAttribute('rel')).toContain('noopener');
    });

    it('shows the MITRE ATT&CK redistribution statement that the ATT&CK license requires', () => {
      const fixture = render('data');
      const text = (fixture.nativeElement.querySelector('.third-party-notice--mitre') as HTMLElement).textContent ?? '';
      expect(text).toContain('© 2026 The MITRE Corporation');
      expect(text).toContain('reproduced and distributed with the permission of The MITRE Corporation');
    });

    it('shows the NVD API attribution notice that the NVD terms of use ask for', () => {
      const fixture = render('data');
      const text = (fixture.nativeElement.querySelector('.third-party-notice--nvd') as HTMLElement).textContent ?? '';
      expect(text).toContain('This product uses the NVD API but is not endorsed or certified by the NVD.');
    });

    it('keeps the notices on the Data tab only', () => {
      const fixture = render('scoring');
      expect(fixture.nativeElement.querySelector('a.third-party-notices-link')).toBeNull();
      expect(fixture.nativeElement.querySelector('.third-party-notice--mitre')).toBeNull();
    });
  });
});
