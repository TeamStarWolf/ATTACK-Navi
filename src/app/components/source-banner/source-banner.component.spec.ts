// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { BehaviorSubject } from 'rxjs';
import { SourceBannerComponent, missingSources } from './source-banner.component';
import { SourceRegistryService } from '../../services/source-registry.service';
import { DataService } from '../../services/data.service';

@Component({ selector: 'app-blank', standalone: true, template: '' })
class BlankComponent {}

describe('SourceBannerComponent: view banner naming a missing source (E1.3)', () => {
  let fixture: ComponentFixture<SourceBannerComponent>;
  let registry: SourceRegistryService;
  let router: Router;
  let domain$: BehaviorSubject<string>;

  const banner = (): HTMLElement | null => fixture.nativeElement.querySelector('[data-testid="source-banner"]');

  async function go(url: string): Promise<void> {
    await fixture.ngZone!.run(() => router.navigateByUrl(url));
    fixture.detectChanges();
  }

  beforeEach(async () => {
    domain$ = new BehaviorSubject<string>('enterprise');
    await TestBed.configureTestingModule({
      imports: [SourceBannerComponent],
      providers: [
        provideRouter([
          { path: 'matrix', component: BlankComponent },
          { path: 'exposure/cve', component: BlankComponent },
          { path: 'coverage/compliance', component: BlankComponent },
          { path: 'settings/changelog', component: BlankComponent },
          { path: 'status', component: BlankComponent },
        ]),
        { provide: DataService, useValue: { currentDomain$: domain$ } },
      ],
    }).compileComponents();
    registry = TestBed.inject(SourceRegistryService);
    router = TestBed.inject(Router);
    fixture = TestBed.createComponent(SourceBannerComponent);
    fixture.detectChanges();
  });

  it('renders nothing while the route\'s sources are loaded, loading or not requested', async () => {
    await go('/exposure/cve');
    registry.begin('cisa-kev');
    registry.succeed('epss', null);
    fixture.detectChanges();
    expect(banner()).toBeNull();
  });

  it('names a failed source the route reads, with its reason, and links to data health', async () => {
    await go('/exposure/cve');
    registry.fail('nvd', 'HTTP 403 Forbidden from https://services.nvd.nist.gov/rest/json/cves/2.0');
    fixture.detectChanges();
    const el = banner()!;
    expect(el).not.toBeNull();
    expect(el.getAttribute('role')).toBe('status');
    expect(el.textContent).toContain('NIST NVD CVE API (failed)');
    const source = el.querySelector('[data-source-id="nvd"]')!;
    expect(source.getAttribute('title')).toContain('HTTP 403');
    expect(el.querySelector('a')!.getAttribute('href')).toBe('/status');
  });

  it('names an empty source too, and counts every missing source', async () => {
    await go('/coverage/compliance');
    registry.succeed('ctid-csa-ccm', 0);
    registry.fail('ctid-aws', 'network error');
    fixture.detectChanges();
    expect(banner()!.textContent).toContain('2 sources this view reads did not load');
    expect(banner()!.textContent).toContain('CTID CSA CCM mapping (empty)');
    expect(banner()!.textContent).toContain('CTID AWS mapping (failed)');
    // Names are separated by a comma and a space, and the list ends with a full stop.
    expect(banner()!.textContent).toContain('CTID CSA CCM mapping (empty), CTID AWS mapping (failed). ');
  });

  it('does not show a source another route reads', async () => {
    registry.fail('attack-releases', 'network error');
    await go('/exposure/cve');
    expect(banner()).toBeNull();
    await go('/settings/changelog');
    expect(banner()!.textContent).toContain('ATT&CK release list (GitHub API) (failed)');
  });

  it('clears when a Retry brings the source back', async () => {
    await go('/settings/changelog');
    registry.fail('attack-releases', 'network error');
    fixture.detectChanges();
    expect(banner()).not.toBeNull();
    registry.begin('attack-releases');
    fixture.detectChanges();
    expect(banner()).toBeNull();
  });

  it('on the matrix, names the active domain\'s ATT&CK source only', async () => {
    await go('/matrix');
    registry.fail('attack-live-ics', 'network error');
    fixture.detectChanges();
    expect(banner()).toBeNull();
    domain$.next('ics');
    fixture.detectChanges();
    expect(banner()!.textContent).toContain('ATT&CK for ICS (live) (failed)');
  });

  it('missingSources keeps the route order and skips unknown ids', () => {
    registry.fail('capec', 'x');
    registry.succeed('engage', 0);
    const out = missingSources(['engage', 'nope', 'capec', 'atomic-layer'], registry.all());
    expect(out.map(m => [m.id, m.status])).toEqual([['engage', 'empty'], ['capec', 'failed']]);
  });
});
