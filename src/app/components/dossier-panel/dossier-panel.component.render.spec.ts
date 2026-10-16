// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Behavioural specs for DossierPanelComponent against its real template: the
// lookup form, input validation, and rendering of a bundled (generated) dossier
// served through the real DossierService. Network requests other than the
// dossier asset itself are left pending, so nothing leaves the browser.
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import CVE_2019_0708 from '../../../assets/data/dossiers/CVE-2019-0708.json';
import { DossierPanelComponent } from './dossier-panel.component';
import { resetBrowserState } from '../../testing/lens-harness';

describe('DossierPanelComponent (rendered)', () => {
  let fixture: ComponentFixture<DossierPanelComponent>;
  let host: HTMLElement;
  let http: HttpTestingController;

  beforeEach(() => {
    resetBrowserState();
    TestBed.configureTestingModule({
      imports: [DossierPanelComponent],
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])],
    });
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(DossierPanelComponent);
    fixture.detectChanges();
    host = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => resetBrowserState());

  function lookUp(text: string): void {
    // View -> model is synchronous for ngModel, so no whenStable() is needed (and the
    // panel's pending background requests would keep the zone from ever settling).
    const input = host.querySelector('section.lookup input[type="search"]') as HTMLInputElement;
    input.value = text;
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    (host.querySelector('section.lookup .btn-primary') as HTMLButtonElement).click();
    fixture.detectChanges();
  }

  it('starts with the lookup form and no dossier', () => {
    expect(host.querySelector('h2')!.textContent!.trim()).toBe('CVE dossier');
    expect(host.querySelector('section.lookup .btn-primary')!.textContent!.trim()).toBe('Build dossier');
    expect(host.querySelector('article.dossier')).toBeNull();
  });

  it('rejects input that is not a CVE id with a visible notice and no request', () => {
    lookUp('log4shell');
    expect(host.querySelector('.notice')!.textContent!.trim()).toBe('Enter a CVE identifier, for example CVE-2021-44228.');
    // (The dossier index is requested at start-up; no per-CVE asset may be.)
    expect(http.match(r => /assets\/data\/dossiers\/(CVE-|LOG4SHELL)/i.test(r.url)).length).toBe(0);
    expect(host.querySelector('article.dossier')).toBeNull();
  });

  it('renders a bundled dossier: identity, facts and the technique tiers', () => {
    lookUp('cve-2019-0708');
    http.expectOne('assets/data/dossiers/CVE-2019-0708.json').flush(CVE_2019_0708);
    fixture.detectChanges();

    const title = host.querySelector('article.dossier .identity h3')!.textContent!.replace(/\s+/g, ' ').trim();
    expect(title).toBe('CVE-2019-0708 generated dossier');
    const facts = [...host.querySelectorAll('.identity .facts .fact')].map(f => f.textContent!.replace(/\s+/g, ' ').trim());
    expect(facts).toContain(`CVSS ${CVE_2019_0708.cvssScore} ${CVE_2019_0708.severity}`);
    expect(facts).toContain('KEV yes');

    const tiers = [...host.querySelectorAll('.tier')].map(t => [
      t.querySelector('.tier-name')!.textContent!.trim(),
      t.querySelector('.tier-count')!.textContent!.trim(),
    ]);
    // One tier per distinct technique tier in the asset, each holding one technique.
    expect(tiers.length).toBe(new Set(CVE_2019_0708.techniques.map(t => t.tier)).size);
    expect(tiers.every(([, n]) => n === '1')).toBeTrue();
  });
});
