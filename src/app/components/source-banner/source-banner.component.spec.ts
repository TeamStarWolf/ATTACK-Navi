// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { BehaviorSubject } from 'rxjs';
import { SourceBannerComponent, missingSources } from './source-banner.component';
import { EMPTY_SOURCE_DETAIL, TREE_LISTING_EMPTY_DETAIL } from '../../models/briefing';
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
  const group = (kind: 'failed' | 'empty'): HTMLElement | null =>
    fixture.nativeElement.querySelector(`[data-testid="source-banner-${kind}"]`);
  /** Text with runs of whitespace collapsed, as a reader sees it. */
  const text = (el: Element | null): string => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();

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
          { path: 'dashboard/overview', component: BlankComponent },
          { path: 'exposure/cve', component: BlankComponent },
          { path: 'exposure/ssvc', component: BlankComponent },
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
    expect(text(el)).toContain('A source this view reads did not load: NIST NVD CVE API (failed): '
      + 'HTTP 403 Forbidden from https://services.nvd.nist.gov/rest/json/cves/2.0.');
    const source = el.querySelector('[data-source-id="nvd"]')!;
    expect(source.getAttribute('title')).toContain('HTTP 403');
    expect(el.querySelector('a')!.getAttribute('href')).toBe('/status');
    expect(text(el.querySelector('a'))).toBe('Data health and Retry');
    expect(group('empty')).toBeNull();
  });

  it('names the stand-in in use when a failed source has one (the bundled KEV snapshot)', async () => {
    await go('/exposure/ssvc');
    registry.fail('cisa-kev', 'network error (no response)');
    registry.succeed('cisa-kev-snapshot', 1748, { version: 'snapshot of 2026-10-16, catalogVersion 2026.10.16' });
    fixture.detectChanges();
    const kev = banner()!.querySelector('[data-source-id="cisa-kev"]')!;
    expect(kev.textContent).toContain('CISA Known Exploited Vulnerabilities (failed)');
    expect(kev.textContent).toContain('using CISA KEV snapshot (bundled), snapshot of 2026-10-16');
    expect(banner()!.querySelector('[data-source-id="cisa-kev-snapshot"]')).toBeNull();
  });

  it('lists the stand-in as missing too when it did not load either', async () => {
    await go('/exposure/ssvc');
    registry.fail('cisa-kev', 'network error (no response)');
    registry.fail('cisa-kev-snapshot', 'HTTP 404 Not Found');
    fixture.detectChanges();
    expect(text(banner())).toContain(
      'CISA Known Exploited Vulnerabilities (failed): network error (no response) | CISA KEV snapshot (bundled) (failed): HTTP 404 Not Found.');
    expect(banner()!.textContent).not.toContain('using');
  });

  it('mixed: a failed source did not load (with its reason and Retry); an empty one is incomplete data, apart', async () => {
    await go('/coverage/compliance');
    registry.succeed('ctid-csa-ccm', 0);
    registry.fail('ctid-aws', 'network error');
    fixture.detectChanges();
    // One banner, one live region, two groups.
    expect(fixture.nativeElement.querySelectorAll('[data-testid="source-banner"]').length).toBe(1);
    expect(fixture.nativeElement.querySelectorAll('[role="status"]').length).toBe(1);
    const failed = group('failed')!;
    const empty = group('empty')!;
    expect(text(failed)).toContain('Missing data');
    expect(text(failed)).toContain('A source this view reads did not load: CTID AWS mapping (failed): network error.');
    expect(text(failed)).not.toContain('CTID CSA CCM');
    expect(text(failed.querySelector('a'))).toBe('Data health and Retry');
    expect(text(empty)).toContain('Incomplete data');
    expect(text(empty)).toContain(`A source this view reads ${EMPTY_SOURCE_DETAIL}: CTID CSA CCM mapping.`);
    expect(text(empty)).not.toMatch(/did not load|failed|retry|\(empty\)/i);
    // The Retry link is the failed group's; the empty group has none of its own.
    expect(empty.querySelector('a')).toBeNull();
    expect(empty.querySelector('[data-source-id="ctid-csa-ccm"]')!.getAttribute('title')).toBe(EMPTY_SOURCE_DETAIL);
    expect(empty.querySelector('[data-source-id="ctid-csa-ccm"]')!.getAttribute('data-status')).toBe('empty');
  });

  it('an empty source that is not a tree listing (KEV, EPSS) gets the generic wording, never a technique-id claim', async () => {
    await go('/exposure/cve');
    registry.succeed('cisa-kev', 0);
    registry.succeed('epss', 0);
    fixture.detectChanges();
    const empty = group('empty')!;
    expect(text(empty)).toContain(`Each of these 2 sources this view reads ${EMPTY_SOURCE_DETAIL}: `);
    expect(text(empty)).toContain('answered, but nothing usable could be read from it');
    expect(text(banner())).not.toContain('technique ids');
    expect(empty.querySelector('[data-source-id="cisa-kev"]')!.getAttribute('title')).toBe(EMPTY_SOURCE_DETAIL);
  });

  it("a tree listing and another empty source together: the generic lead, and the tree listing marked '(no technique ids)'", async () => {
    await go('/dashboard/overview');
    registry.succeed('misp-galaxy', 0);
    registry.succeed('elastic-tree', 0);
    fixture.detectChanges();
    const empty = group('empty')!;
    expect(text(empty)).toContain(`Each of these 2 sources this view reads ${EMPTY_SOURCE_DETAIL}: `);
    expect(text(empty.querySelector('[data-source-id="elastic-tree"]'))).toBe('Elastic detection-rules (tree listing) (no technique ids).');
    expect(text(empty.querySelector('[data-source-id="misp-galaxy"]'))).not.toContain('technique ids');
    expect(empty.querySelector('[data-source-id="elastic-tree"]')!.getAttribute('title')).toBe(TREE_LISTING_EMPTY_DETAIL);
  });

  it("empty only: 'Incomplete data', the 'no technique ids' wording for tree listings, and no 'did not load' or Retry anywhere", async () => {
    await go('/dashboard/overview');
    registry.succeed('elastic-tree', 0);
    registry.succeed('splunk-tree', 0);
    fixture.detectChanges();
    const el = banner()!;
    expect(group('failed')).toBeNull();
    expect(text(el)).toContain('Incomplete data');
    expect(text(el)).toContain('Each of these 2 sources this view reads answered, but no technique ids could be read from it: '
      + 'Elastic detection-rules (tree listing), Splunk security_content (tree listing).');
    expect(text(el)).not.toMatch(/did not load|missing data|retry/i);
    const links = el.querySelectorAll('a');
    expect(links.length).toBe(1);
    expect(text(links[0])).toBe('Data health');
    expect(links[0].getAttribute('href')).toBe('/status');
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
    expect(out.map(m => m.detail)).toEqual([EMPTY_SOURCE_DETAIL, 'x']);
    registry.succeed('sentinel-attack-tree', 0);
    expect(missingSources(['sentinel-attack-tree', 'engage'], registry.all()).map(m => m.detail))
      .toEqual([TREE_LISTING_EMPTY_DETAIL, EMPTY_SOURCE_DETAIL]);
  });
});
