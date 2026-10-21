// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Characterization of which technique-sidebar sections render for five
// representative techniques of the fixed fixture domain. The sidebar uses the
// REAL services here (their bundled seed data, no network: requests stay
// pending), so this pins the ATT&CK-derived sections and the seed-backed ones.
// A section appearing or disappearing for these techniques fails a spec. The Rule
// sources section renders for every technique (its snapshot request stays pending here).
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { Router, provideRouter } from '@angular/router';
import { provideLocationMocks } from '@angular/common/testing';

import { SidebarComponent } from '../components/sidebar/sidebar.component';
import { Domain } from '../models/domain';
import { DataService } from '../services/data.service';
import { FilterService } from '../services/filter.service';
import { parseFixtureDomain, resetBrowserState } from './lens-harness';

/**
 * Expected `#sb-sec-*` section headers per technique, in document order.
 * T1003 rich parent with sub-techniques; T1003.001 its first sub-technique;
 * T1082 an unmitigated parent; T1078 a multi-tactic parent; T1485 an Impact parent.
 */
const EXPECTED: Record<string, string[]> = {
  T1003: ['annotation', 'subtechniques', 'datacomponents', 'procedures', 'tags', 'notes', 'threats', 'software',
    'car', 'rule-sources', 'siem', 'c2', 'offensive-tools', 'mitigations', 'relgraph'],
  'T1003.001': ['annotation', 'datacomponents', 'procedures', 'tags', 'notes', 'threats', 'software', 'campaigns',
    'car', 'rule-sources', 'siem', 'logging', 'bloodhound', 'c2', 'offensive-tools', 'mitigations', 'relgraph'],
  T1082: ['annotation', 'datacomponents', 'procedures', 'tags', 'notes', 'threats', 'software', 'campaigns',
    'rule-sources', 'siem', 'c2', 'mitigations', 'relgraph'],
  T1078: ['annotation', 'subtechniques', 'datacomponents', 'procedures', 'tags', 'notes', 'threats', 'software',
    'campaigns', 'd3fend', 'car', 'rule-sources', 'siem', 'logging', 'offensive-tools', 'wazuh-xdr', 'mitigations', 'relgraph'],
  T1485: ['annotation', 'subtechniques', 'datacomponents', 'procedures', 'tags', 'notes', 'threats', 'software',
    'campaigns', 'rule-sources', 'siem', 'wazuh-xdr', 'mitigations', 'relgraph'],
};

describe('Sidebar section presence (fixture domain, 5 techniques)', () => {
  let domain: Domain;
  let fixture: ComponentFixture<SidebarComponent>;
  let filter: FilterService;

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      imports: [SidebarComponent],
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]), provideLocationMocks()],
    });
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    filter = TestBed.inject(FilterService);
    fixture = TestBed.createComponent(SidebarComponent);
    fixture.detectChanges();
  });

  afterEach(() => resetBrowserState());

  function sectionsFor(attackId: string): string[] {
    const tech = domain.techniques.find(t => t.attackId === attackId)!;
    filter.selectTechnique(tech);
    fixture.detectChanges();
    const host = fixture.nativeElement as HTMLElement;
    return [...host.querySelectorAll('[id^="sb-sec-"]')].map(e => e.id.replace('sb-sec-', ''));
  }

  for (const attackId of Object.keys(EXPECTED)) {
    it(`${attackId}: renders the expected sections`, () => {
      expect(sectionsFor(attackId)).toEqual(EXPECTED[attackId]);
    });
  }

  it('ATT&CK-derived sections follow the domain relationships', () => {
    for (const attackId of Object.keys(EXPECTED)) {
      const tech = domain.techniques.find(t => t.attackId === attackId)!;
      const has = new Set(sectionsFor(attackId));
      expect(has.has('subtechniques')).withContext(`${attackId} subtechniques`).toBe(tech.subtechniques.length > 0);
      expect(has.has('threats')).withContext(`${attackId} threats`).toBe((domain.groupsByTechnique.get(tech.id)?.length ?? 0) > 0);
      expect(has.has('software')).withContext(`${attackId} software`).toBe((domain.softwareByTechnique.get(tech.id)?.length ?? 0) > 0);
      expect(has.has('campaigns')).withContext(`${attackId} campaigns`).toBe((domain.campaignsByTechnique.get(tech.id)?.length ?? 0) > 0);
      // The mitigations section renders even when there are none (T1082 has no mitigation).
      expect(has.has('mitigations')).withContext(`${attackId} mitigations`).toBeTrue();
    }
  });

  // P2-18: the evidence card opens the drawer body, below the header and before
  // the Library cross-ref; it is not a #sb-sec-* section, so the lists above hold.
  it('the evidence card is first in the body: below the header, before the Library cross-ref', () => {
    sectionsFor('T1078');
    const host = fixture.nativeElement as HTMLElement;
    const body = host.querySelector('.sidebar-body')!;
    const card = body.querySelector('app-technique-evidence-card')!;
    expect(card).not.toBeNull();
    expect(body.firstElementChild).toBe(card);
    const following = (a: Element, b: Element) => !!(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
    expect(following(host.querySelector('.sidebar-header')!, card)).toBeTrue();
    expect(following(card, body.querySelector('app-library-cross-ref')!)).toBeTrue();
    expect(following(card, body.querySelector('app-validation-status-pill')!)).toBeTrue();
    expect(card.querySelector('[data-testid="ev-why"]')!.textContent).toContain('Why this colour:');
    // The header's "Full page" link opens the technique page.
    expect(host.querySelector('[data-testid="drawer-full-page"]')!.getAttribute('href')).toBe('/technique/enterprise/T1078');
  });

  // P2-18 round 1: the page link keeps the current query, so a copied "Full page" link reopens the same lens.
  it('the "Full page" link carries the current lens (heat=) and the rest of the query', async () => {
    await TestBed.inject(Router).navigateByUrl('/?heat=coverage&dom=enterprise&tech=T1078');
    // The navigation has ended before the drawer renders its link (no whenStable: the seed requests stay pending).
    sectionsFor('T1078');
    const href = (fixture.nativeElement as HTMLElement).querySelector('[data-testid="drawer-full-page"]')!.getAttribute('href')!;
    expect(href.split('?')[0]).toBe('/technique/enterprise/T1078');
    expect(new URLSearchParams(href.split('?')[1] ?? '').get('heat')).toBe('coverage');
  });

  it('renders nothing until a technique is selected', () => {
    const host = fixture.nativeElement as HTMLElement;
    expect(host.querySelectorAll('[id^="sb-sec-"]').length).toBe(0);
  });
});
