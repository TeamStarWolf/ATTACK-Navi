// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Uniformity of the technique drawer: every section renders through the one section
// primitive and every row through the one row primitive, so every header has the same
// element and classes (and computes the same type), every card the same box, and every
// row of a kind the same classes and box. The drawer is mounted with the REAL services
// on the fixture domain (T1078: groups, software, campaigns, D3FEND, CAR, SIEM, logging,
// tools, Wazuh, mitigations); the sections the fixture has no data for are given a
// minimal row each, so all 48 sections render at once.
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { provideLocationMocks } from '@angular/common/testing';

import { SidebarComponent } from '../components/sidebar/sidebar.component';
import { Domain } from '../models/domain';
import { DataService } from '../services/data.service';
import { FilterService } from '../services/filter.service';
import { parseFixtureDomain, resetBrowserState } from './lens-harness';

/** Every section id the drawer can render (the jump index's 48). */
const ALL_SECTIONS = [
  'imported-layer', 'annotation', 'datasources', 'subtechniques', 'detection', 'datacomponents', 'procedures',
  'cve', 'nist', 'cloud', 'veris', 'csa-ccm', 'm365-controls', 'cri', 'capec', 'exploitdb', 'nuclei', 'kill-chain',
  'poc-exploits', 'tags', 'notes', 'threats', 'software', 'campaigns', 'd3fend', 'engage', 'car', 'atomic',
  'rule-sources', 'anthropic-skills', 'threathunter-playbook', 'evtx-samples', 'm365', 'siem', 'misp', 'opencti',
  'payloads', 'logging', 'bloodhound', 'c2', 'ioc-feed', 'azure-identity', 'offensive-tools', 'wazuh-xdr',
  'threat-hunting', 'custom', 'mitigations', 'relgraph',
];

/** Cast a fixture literal to the field's type. */
const as = <T>(v: unknown): T => v as T;

describe('Drawer uniformity: one section pattern and one row pattern', () => {
  let domain: Domain;
  let fixture: ComponentFixture<SidebarComponent>;
  let cmp: SidebarComponent;
  const host = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      imports: [SidebarComponent],
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]), provideLocationMocks()],
    });
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    fixture = TestBed.createComponent(SidebarComponent);
    cmp = fixture.componentInstance;
    fixture.detectChanges();

    const base = domain.techniques.find(t => t.attackId === 'T1078')!;
    TestBed.inject(FilterService).selectTechnique({
      ...base,
      detectionText: 'Monitor for <code>logon</code> events.',
      dataSources: ['Logon Session: Logon Session Creation', 'User Account: User Account Authentication'],
    });
    fixture.detectChanges();
    fill(cmp);
    cmp.collapsedSections.clear();
    (cmp as unknown as { cdr: { markForCheck(): void } }).cdr.markForCheck();
    fixture.detectChanges();
  });

  afterEach(() => resetBrowserState());

  /** One minimal row for every section the fixture domain has no data for. */
  function fill(c: SidebarComponent): void {
    c.activeUserLayer = as({ name: 'Imported layer' });
    c.userLayerEntry = as({ score: 90, color: '#ff0000', enabled: true, comment: 'note', metadata: [{ name: 'k', value: 'v' }], links: [] });
    c.annotation = as({ note: 'n', color: 'default' });
    c.cveExposures = as([
      { cveId: 'CVE-2020-15132', source: 'ctid-csv', capabilityGroup: '', exploitationTechnique: [], primaryImpact: ['x'], secondaryImpact: [], description: 'A CVE description.' },
      { cveId: 'CVE-2021-44228', source: 'ctid-kev', capabilityGroup: '', exploitationTechnique: ['x'], primaryImpact: [], secondaryImpact: [], description: '' },
    ]);
    c.nistControls = as([{ id: 'AC-2', family: 'AC', description: 'Account Management' }, { id: 'IA-2', family: 'IA', description: 'Identification' }]);
    c.cisControls = as([{ id: 'CIS-5.1', description: 'Account inventory', mappingType: 'protect' }]);
    c.cloudControls = as([{ id: 'aws_network_firewall', description: 'AWS Network Firewall', provider: 'aws', mappingType: 'protect' }]);
    c.verisActions = as([{ id: 'v1', category: 'hacking', label: 'Use of stolen creds' }]);
    c.csaCcmControls = as([{ controlId: 'IAM-01', scoreCategory: 'protect', scoreValue: 'significant', description: 'Identity policy' }]);
    c.m365Controls = as([{ controlId: 'M365-1', url: 'https://example.org/m', group: 'Entra', description: 'Conditional access', scoreValue: 'partial', scoreCategory: 'protect' }]);
    c.criControls = as([{ id: 'PR.AA-01', url: 'https://example.org/c', function: 'PR', functionLabel: 'Protect', description: 'Identities' }]);
    c.capecEntries = as([{ id: 'CAPEC-560', url: 'https://capec.mitre.org/data/definitions/560.html', likelihood: 'High', severity: 'High', cweIds: [], name: 'Use of Known Domain Credentials', description: 'An adversary...' }]);
    c.exploitCount = 2;
    c.nucleiCount = 1;
    c.killChainEntries = as([{ cveId: 'CVE-2020-15132', cwes: ['CWE-1'], capecs: ['CAPEC-1'], defenses: ['D3-X'] }]);
    c.pocCount = 3;
    c.engageActivities = as([{ id: 'EAC0001', url: 'https://engage.mitre.org/x', category: 'Expose', name: 'API Monitoring', definition: 'Monitor.' }]);
    c.atomicLiveTests = as([{ guid: 'g', name: 'Test one', description: 'Does a thing.', executorName: 'powershell', platforms: ['windows'] }]);
    c.atomicLiveCount = 1;
    c.anthropicSkillCount = 2;
    c.playbookCount = 1;
    c.playbookUrl = 'https://example.org/p';
    c.evtxSamples = as([{ url: 'https://example.org/e.evtx', filename: 'logon.evtx', tactic: 'Persistence' }]);
    c.m365Queries = as([{ path: 'p', url: 'https://example.org/q', title: 'Hunting query', tactic: 'Persistence' }]);
    c.mispCluster = as({ value: 'Valid Accounts', description: 'Adversaries may obtain...', mitrePlatforms: ['Windows'], synonyms: [] });
    c.openctiIndicators = as([{ id: 'i1', patternType: 'stix', confidence: 80, name: 'Indicator', description: 'd', labels: ['l'], pattern: '[x]' }]);
    c.payloadRefs = as([{ url: 'https://example.org/pa', category: 'Methodology', title: 'Payloads' }]);
    c.adAttackPaths = as([{ attackPath: 'GenericAll', description: 'Full control.', tools: ['BloodHound'], mitigations: ['Tiering'], detectionHints: ['4662'] }]);
    c.iocs = as([{ type: 'ip', value: '192.0.2.1' }]);
    c.azureAttacks = as([{ name: 'Password spray', description: 'Spray.', affectedServices: ['Entra ID'], detectionQuery: 'SigninLogs', mitigations: ['MFA'] }]);
    c.huntingQueries = as([{ url: 'https://example.org/h', title: 'Hunt', platform: 'Splunk', tactic: 'Persistence', source: 'x' }]);
    c.customMitigations = as([{ id: 'CM-1', category: 'EDR', name: 'Custom control', implStatus: 'implemented', description: 'Ours.' }]);
    if (c.c2Capabilities.length === 0) c.c2Capabilities = as([{ framework: 'Sliver', capability: 'Token', description: 'd', techniqueIds: ['T1078'] }]);
    if (c.siemQueries.length === 0) c.siemQueries = as([{ platform: 'splunk', platformLabel: 'Splunk', confidence: 'high', title: 'q', query: 'index=x' }]);
  }

  const headers = () => [...host().querySelectorAll<HTMLElement>('[id^="sb-sec-"]')];

  it('renders all 48 sections, each header inside an app-drawer-section card', () => {
    const ids = headers().map(h => h.id.replace('sb-sec-', ''));
    expect([...ids].sort()).toEqual([...ALL_SECTIONS].sort());
    for (const h of headers()) {
      expect(h.parentElement!.tagName).withContext(h.id).toBe('APP-DRAWER-SECTION');
      expect(h.parentElement!.classList).withContext(h.id).toContain('sb-section');
    }
  });

  it('every section header is the same element with the same classes', () => {
    const shape = (h: HTMLElement) => `${h.tagName} ${[...h.classList].filter(c => c !== 'sb-head--curated').sort().join(' ')} role=${h.getAttribute('role')}`;
    const shapes = new Set(headers().map(shape));
    expect([...shapes]).toEqual(['H3 collapsible-title sb-head section-title upgrade-section-title role=button']);
    for (const h of headers()) {
      expect(h.getAttribute('aria-expanded')).withContext(h.id).toBe('true');
      // Slots: chevron first, then the optional icon, then the title.
      const first = h.firstElementChild!;
      expect(first.classList).withContext(h.id).toContain('sb-chevron');
      expect(h.querySelector('.sb-title')).withContext(h.id).not.toBeNull();
      // No inline style anywhere in a header (no per-section colours).
      expect(h.querySelector('[style]')).withContext(h.id).toBeNull();
    }
  });

  it('every count pill is the same element with the same classes, whatever the section', () => {
    const pills = [...host().querySelectorAll<HTMLElement>('[id^="sb-sec-"] .sb-count')];
    expect(pills.length).toBeGreaterThan(30);
    const shapes = new Set(pills.map(p => `${p.tagName} ${[...p.classList].sort().join(' ')}`));
    expect([...shapes]).toEqual(['SPAN count-badge sb-count upgrade-section-count']);
    // The legacy per-section count classes are gone.
    expect(host().querySelector('.section-count, .proc-badge, .toggle-arrow, .section-heading, .section-label')).toBeNull();
  });

  it('every header and every card computes the same style', () => {
    const hs = headers();
    const hk = (h: HTMLElement) => {
      const s = getComputedStyle(h);
      return [s.fontSize, s.fontWeight, s.letterSpacing, s.textTransform, s.paddingTop, s.paddingLeft, s.borderBottomWidth,
        s.backgroundColor, s.color, s.marginBottom].join('|');
    };
    expect(new Set(hs.map(hk)).size).withContext(hs.map(h => `${h.id}: ${hk(h)}`).join('\n')).toBe(1);
    const cards = hs.map(h => h.parentElement as HTMLElement);
    const ck = (c: HTMLElement) => {
      const s = getComputedStyle(c);
      return [s.borderTopWidth, s.borderRightWidth, s.borderBottomWidth, s.borderLeftWidth, s.borderTopColor, s.borderBottomColor,
        s.borderLeftColor, s.borderTopLeftRadius, s.paddingTop, s.paddingRight, s.paddingBottom, s.paddingLeft, s.backgroundColor].join('|');
    };
    expect(new Set(cards.map(ck)).size).withContext(cards.map(c => `${c.querySelector('h3')!.id}: ${ck(c)}`).join('\n')).toBe(1);
    const pills = [...host().querySelectorAll<HTMLElement>('[id^="sb-sec-"] .sb-count')];
    const pk = (p: HTMLElement) => {
      const s = getComputedStyle(p);
      return [s.fontSize, s.fontWeight, s.paddingTop, s.paddingLeft, s.borderTopLeftRadius, s.backgroundColor, s.color, s.borderTopColor].join('|');
    };
    expect(new Set(pills.map(pk)).size).toBe(1);
  });

  it('every row of a kind has the same classes and box, and every entity id is the monospace chip', () => {
    const rows = [...host().querySelectorAll<HTMLElement>('app-drawer-row')];
    expect(rows.length).toBeGreaterThan(40);
    for (const kind of ['entity', 'detail', 'plain']) {
      const ofKind = rows.filter(r => r.getAttribute('data-row-kind') === kind);
      expect(ofKind.length).withContext(kind).toBeGreaterThan(2);
      for (const r of ofKind) {
        const own = [...r.classList].filter(c => c.startsWith('sb-row') && c !== 'sb-row--clickable').sort().join(' ');
        expect(own).withContext(`${kind}: ${r.className}`).toBe(`sb-row sb-row--${kind}`);
      }
      const box = (r: HTMLElement) => {
        const s = getComputedStyle(r);
        return [s.paddingTop, s.paddingRight, s.paddingBottom, s.paddingLeft, s.minHeight, s.fontFamily, s.fontSize].join('|');
      };
      expect(new Set(ofKind.map(box)).size).withContext(kind).toBe(1);
    }
    const ids = [...host().querySelectorAll<HTMLElement>('app-drawer-row .sb-id')];
    expect(ids.length).toBeGreaterThan(20);
    const idk = (e: HTMLElement) => {
      const s = getComputedStyle(e);
      return [s.fontFamily, s.fontSize, s.fontWeight, s.paddingLeft, s.borderTopLeftRadius, s.color, s.backgroundColor].join('|');
    };
    expect(new Set(ids.map(idk)).size).toBe(1);
    expect(getComputedStyle(ids[0]).fontFamily).toContain('IBM Plex Mono');
  });

  it('show-more controls and source footers share one style', () => {
    const more = [...host().querySelectorAll<HTMLElement>('.show-more-btn')];
    for (const m of more) expect(m.classList).toContain('sb-more');
    const sources = [...host().querySelectorAll<HTMLElement>('.framework-link, .ctid-attribution, .nist-attribution')];
    expect(sources.length).toBeGreaterThan(10);
    const sk = (e: HTMLElement) => {
      const s = getComputedStyle(e);
      return [s.fontSize, s.color, s.marginTop].join('|');
    };
    expect(new Set(sources.map(sk)).size).withContext(sources.map(e => `${e.className}: ${sk(e)}`).join('\n')).toBe(1);
  });

  it('no section keeps inline colours in its rows', () => {
    const body = host().querySelector('.sidebar-body')!;
    // The data-driven colours stay (EPSS, capability group, the imported-layer swatch, the impl status buttons);
    // nothing else in a section body carries a style attribute.
    const inline = [...body.querySelectorAll<HTMLElement>('app-drawer-section [style]')]
      .filter(e => !e.matches('.cve-tag, .cve-cap-group, .il-swatch, .impl-chip, .bulk-status-btn, .leg-dot'));
    expect(inline.map(e => e.className)).toEqual([]);
  });
});
