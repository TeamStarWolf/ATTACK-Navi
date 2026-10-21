// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';

import { SettingsPanelComponent } from './settings-panel.component';
import { SettingsService } from '../../services/settings.service';
import { DataService } from '../../services/data.service';
import { TimelineService } from '../../services/timeline.service';
import { OpenCtiService } from '../../services/opencti.service';
import { MispService } from '../../services/misp.service';
import { TaxiiService } from '../../services/taxii.service';
import { lensLabel } from '../../models/posture/posture-vocabulary';

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

  // E1.5: the Scoring Weights tab and its setting are retired (plan 4.1 bans
  // the Coverage Score and grades on reference data); Display is the first tab.
  it('starts from the saved settings on the Display tab with nothing dirty', () => {
    expect(component.activeTab).toBe('display');
    expect('scoringWeights' in component.settings).toBeFalse();
    expect(component.isDirty).toBeFalse();
  });

  it('has no scoring-weight controls left', () => {
    const c = component as unknown as Record<string, unknown>;
    for (const gone of ['weightsTotal', 'sampleCoverageScore', 'onWeightChange', 'autoNormalize']) {
      expect(c[gone]).withContext(gone).toBeUndefined();
    }
  });

  it('isDirty tracks an unsaved edit and clears once applied', () => {
    component.settings.orgName = 'Blue Team';
    expect(component.isDirty).toBeTrue();

    component.applySettings();
    expect(settingsService.current.orgName).toBe('Blue Team');
    expect(component.isDirty).toBeFalse();
  });

  it('each theme swatch equals the ramp the matrix applies for that theme', () => {
    settingsService.update({ colorblindSafe: false });
    for (const theme of component.themes) {
      settingsService.update({ heatmapColorTheme: theme.id as never });
      // getCoverageColors() is exactly what the matrix cell/legend use.
      expect(settingsService.getCoverageColors())
        .withContext(`swatch vs applied ramp for "${theme.label}"`)
        .toEqual(theme.colors);
    }
  });

  // P2-14 round 2: SAFE_STATUS / SAFE_CONTROLS are gone, so the toggle no longer
  // swaps the status lens to Okabe-Ito; its description must say which lenses keep
  // their own ramps instead of claiming every mode changes.
  it('the colorblind-safe description names the lenses that keep their own ramps', () => {
    const labels = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('.checkbox-item'));
    const item = labels.find(l => l.querySelector('.checkbox-label')?.textContent?.trim() === 'Colorblind-safe heatmaps');
    expect(item).withContext('colorblind-safe toggle').toBeDefined();
    const desc = item!.querySelector('.checkbox-desc')!.textContent ?? '';
    expect(desc).toContain('Sequential heatmap modes use viridis');
    expect(desc).not.toContain('All heatmap modes');
    expect(desc).not.toContain('Okabe-Ito (status)');
    for (const name of ['Status', 'Controls', lensLabel('covered'), lensLabel('proven'), lensLabel('posture')]) {
      expect(desc).withContext(name).toContain(name);
    }
  });

  it('resetToDefaults restores the shipped defaults', () => {
    component.setColorTheme('monochrome');
    expect(settingsService.current.heatmapColorTheme).toBe('monochrome');

    component.resetToDefaults();
    expect(component.settings.heatmapColorTheme).toBe('default');
    expect(settingsService.current.heatmapColorTheme).toBe('default');
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
      const fixture = render('display');
      expect(fixture.nativeElement.querySelector('a.third-party-notices-link')).toBeNull();
      expect(fixture.nativeElement.querySelector('.third-party-notice--mitre')).toBeNull();
    });
  });

  // Phase 2 design P2-05 (§6, §7): Settings > Data > "Posture rules", next to
  // "Bulk Import Status": the D16 threshold (integer 1-500) and the three D10
  // windows. A change is saved at once; PostureService recomputes from it.
  describe('Posture rules (P2-05)', () => {
    // OnPush: the tab is chosen before the first change detection pass.
    let pf: ComponentFixture<SettingsPanelComponent>;
    const el = () => pf.nativeElement as HTMLElement;
    const input = (id: string) => el().querySelector(`[data-testid="${id}"]`) as HTMLInputElement;
    const copy = () => el().querySelector('[data-testid="posture-rules-copy"]')!.textContent!.trim().replace(/\s+/g, ' ');
    const change = (id: string, value: string) => {
      const i = input(id);
      i.value = value;
      i.dispatchEvent(new Event('change'));
      pf.detectChanges();
    };

    beforeEach(() => {
      pf = TestBed.createComponent(SettingsPanelComponent);
      pf.componentInstance.activeTab = 'data';
      pf.detectChanges();
    });

    it('shows threshold 15 and windows 90 / 180 / 90 on a fresh profile, after Bulk Import Status', () => {
      const headers = Array.from(el().querySelectorAll('.data-section-header')).map(h => h.textContent!.trim());
      expect(headers).toContain('Posture rules');
      expect(headers.indexOf('Posture rules')).toBe(headers.indexOf('Bulk Import Status') + 1);
      expect(input('posture-threshold').value).toBe('15');
      expect(input('posture-window-range').value).toBe('90');
      expect(input('posture-window-production').value).toBe('180');
      expect(input('posture-window-own-run').value).toBe('90');
      expect(copy()).toBe('A mitigation mapped to more than 15 techniques counts as partial until you confirm it per technique.');
    });

    it('saves a valid threshold and window, and refuses an out-of-range one', () => {
      change('posture-threshold', '20');
      expect(settingsService.current.posture.mitigationBreadthThreshold).toBe(20);
      expect(copy()).toContain('more than 20 techniques');
      change('posture-window-own-run', '30');
      expect(settingsService.current.posture.decayDays).toEqual({ range: 90, production: 180, 'own-run': 30 });
      change('posture-threshold', '501');
      expect(settingsService.current.posture.mitigationBreadthThreshold).toBe(20);
      expect(input('posture-threshold').value).toBe('20');
      change('posture-window-range', '2.5');
      expect(settingsService.current.posture.decayDays.range).toBe(90);
    });
  });
});
