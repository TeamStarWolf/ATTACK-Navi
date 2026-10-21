// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BehaviorSubject, of } from 'rxjs';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { provideLocationMocks } from '@angular/common/testing';
import { SidebarComponent } from './sidebar.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { RULE_COVERAGE_SNAPSHOT_URL } from '../../services/rule-coverage-snapshot.service';
import { RULE_SOURCE_EMPTY } from '../rule-source-list/rule-source-list.component';
import type { Domain } from '../../models/domain';
import type { Technique } from '../../models/technique';
import { RULE_COVERAGE_FIXTURE } from '../../testing/rule-coverage-fixture';
import { parseFixtureDomain, resetBrowserState } from '../../testing/lens-harness';

const noopBSet = () => new BehaviorSubject(new Set());
const noopBMap = () => new BehaviorSubject(new Map());
const noopBArr = () => new BehaviorSubject([]);
const noopBNull = () => new BehaviorSubject(null);
const noopBStr = () => new BehaviorSubject('');
const noopBBool = () => new BehaviorSubject(false);

describe('SidebarComponent', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [SidebarComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: FilterService, useValue: {
            selectedTechnique$: noopBNull(),
            activePanel$: noopBNull(),
            activeMitigationFilters$: noopBArr(),
            activeThreatGroupIds$: noopBSet(),
            heatmapMode$: new BehaviorSubject('coverage'),
            techniqueSearch$: noopBStr(),
            techniqueQuery$: noopBStr(),
            sortMode$: new BehaviorSubject('alpha'),
            dimUncovered$: noopBBool(),
            platformFilter$: noopBNull(),
            implStatusFilter$: noopBNull(),
            searchScope$: new BehaviorSubject('name'),
            searchFilterMode$: noopBBool(),
            hiddenTacticIds$: noopBSet(),
            cveTechniqueIds$: noopBSet(),
            setSelectedTechnique: () => {},
            setActivePanel: () => {},
            selectTechnique: () => {},
            toggleThreatGroup: () => {},
            getActivePanel: () => null,
        }},
        { provide: DataService, useValue: { domain$: noopBNull(), loading$: noopBBool() }},
      ],
    });
  });

  it('TestBed compiles the component (creation deferred — heavy template deps)', () => {
    expect(SidebarComponent).toBeTruthy();
  });
});

// The Rule sources section: Elastic detection-rules, Splunk security_content and
// mdecrevoisier SIGMA, read from the bundled rule-coverage snapshot (here the small
// fixture copied from the real file at its pins). The drawer is mounted with the REAL
// services on the fixture domain; the fixture domain has no T1059 or T1114, so those two
// are a fixture technique under the snapshot's ids (the section reads attackId only).
describe('SidebarComponent: Rule sources (Elastic, Splunk, mdecrevoisier SIGMA at pinned commits)', () => {
  let domain: Domain;
  let fixture: ComponentFixture<SidebarComponent>;
  let filter: FilterService;
  let http: HttpTestingController;

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      imports: [SidebarComponent],
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]), provideLocationMocks()],
    });
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    filter = TestBed.inject(FilterService);
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(SidebarComponent);
    fixture.detectChanges();
  });

  afterEach(() => resetBrowserState());

  const host = () => fixture.nativeElement as HTMLElement;

  /** A fixture-domain technique under another ATT&CK id (the snapshot's), or the fixture one itself. */
  function technique(attackId: string): Technique {
    const own = domain.techniques.find(t => t.attackId === attackId);
    if (own) return own;
    const base = domain.techniques.find(t => t.attackId === 'T1082')!;
    return { ...base, attackId };
  }

  /** Every request for the snapshot file so far (the services share one). */
  const snapshotRequests = () => http.match(r => r.url === RULE_COVERAGE_SNAPSHOT_URL);

  function flushSnapshot(): void {
    const requests = snapshotRequests();
    expect(requests.length).withContext('one shared snapshot request').toBe(1);
    requests[0].flush(RULE_COVERAGE_FIXTURE);
  }

  /** Open a technique and expand the Rule sources section from its header. */
  function open(attackId: string): void {
    filter.selectTechnique(technique(attackId));
    fixture.detectChanges();
    const header = host().querySelector<HTMLElement>('#sb-sec-rule-sources')!;
    expect(header).withContext('Rule sources header').not.toBeNull();
    if (header.getAttribute('aria-expanded') !== 'true') header.click();
    fixture.detectChanges();
  }

  const sources = () => [...host().querySelectorAll<HTMLElement>('app-rule-source-list [data-testid="rule-source"]')];
  const bySource = (key: string) => host().querySelector<HTMLElement>(`[data-testid="rule-source"][data-source="${key}"]`)!;
  const text = (el: Element | null) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();

  it('renders the three sources in order, with each count from the snapshot', () => {
    flushSnapshot();
    open('T1059');
    expect(sources().map(s => s.getAttribute('data-source'))).toEqual(['elastic', 'splunk', 'mdecrevoisier']);
    expect(sources().map(s => text(s.querySelector('.rs-label')))).toEqual(
      ['Elastic detection-rules', 'Splunk security_content', 'mdecrevoisier SIGMA']);
    expect(text(bySource('elastic').querySelector('[data-testid="rule-source-count"]'))).toBe('323 rules');
    expect(text(bySource('splunk').querySelector('[data-testid="rule-source-count"]'))).toBe('165 rules');
    expect(text(bySource('mdecrevoisier').querySelector('[data-testid="rule-source-count"]'))).toBe('7 rules');
    // The section badge adds the three counts up.
    expect(text(host().querySelector('#sb-sec-rule-sources .count-badge'))).toBe(String(323 + 165 + 7));
    // Two names are listed of each count; the note says so.
    expect(text(bySource('elastic'))).toContain('2 of 323 listed by name');
  });

  it('links every rule name to its file at the pinned commit, path segments encoded (one per source checked against the fixture)', () => {
    flushSnapshot();
    open('T1059');
    const links = (key: string) => [...bySource(key).querySelectorAll<HTMLAnchorElement>('a.rs-rule')];
    expect(links('elastic').map(a => text(a))).toEqual([
      'AWS Batch Job Submitted with Container Override by Unusual Identity',
      'AWS Bedrock High Risk Filesystem or Execution Tool Invocation',
    ]);
    expect(links('elastic')[0].getAttribute('href')).toBe(
      'https://github.com/elastic/detection-rules/blob/7115bb0ab06c11c7994486ffe2bc0dc801ad8502/'
      + 'rules/integrations/aws/execution_batch_job_submitted_container_override_unusual_identity.toml');
    expect(links('splunk')[0].getAttribute('href')).toBe(
      'https://github.com/splunk/security_content/blob/678e76c5f36f6fadd93a1eaa0d82c1dbe273c486/'
      + 'detections/endpoint/cmd_carry_out_string_command_parameter.yml');
    expect(text(links('splunk')[0])).toBe('CMD Carry Out String Command Parameter');
    // mdecrevoisier paths hold spaces: each segment is encoded, the slashes kept.
    expect(links('mdecrevoisier')[0].getAttribute('href')).toBe(
      'https://github.com/mdecrevoisier/SIGMA-detection-rules/blob/d61408af8769c74c96296b7ccc92d4bc3abb15af/'
      + 'windows-os/win-os-payload%20encoded%20PowerShell%20deployed%20(PowerShell).yaml');
    expect(text(links('mdecrevoisier')[0])).toBe('Encoded PowerShell payload deployed (PowerShell)');
    for (const a of host().querySelectorAll<HTMLAnchorElement>('a.rs-rule')) {
      expect(a.getAttribute('target')).toBe('_blank');
      expect(a.getAttribute('rel')).toBe('noopener');
    }
  });

  it('shows the pinned SHA, the commit date and the snapshot date in each provenance line', () => {
    flushSnapshot();
    open('T1059');
    const prov = (key: string) => bySource(key).querySelector('[data-testid="rule-source-provenance"]')!;
    expect(text(prov('elastic'))).toBe('Pinned elastic/detection-rules@7115bb0, commit 2026-10-21; snapshot 2026-10-21');
    expect(text(prov('splunk'))).toBe('Pinned splunk/security_content@678e76c, commit 2026-10-20; snapshot 2026-10-21');
    expect(text(prov('mdecrevoisier'))).toBe('Pinned mdecrevoisier/SIGMA-detection-rules@d61408a, commit 2026-05-20; snapshot 2026-10-21');
    const repoLink = prov('mdecrevoisier').querySelector('a')!;
    expect(repoLink.getAttribute('href')).toBe(
      'https://github.com/mdecrevoisier/SIGMA-detection-rules/tree/d61408af8769c74c96296b7ccc92d4bc3abb15af');
    expect(repoLink.getAttribute('title')).toBe('d61408af8769c74c96296b7ccc92d4bc3abb15af');
  });

  it('says so honestly when a source has no rule for the technique (count 0)', () => {
    flushSnapshot();
    open('T1114'); // Elastic 11 in the fixture; Splunk and mdecrevoisier none
    expect(text(bySource('elastic').querySelector('[data-testid="rule-source-count"]'))).toBe('11 rules');
    expect(bySource('elastic').querySelector('[data-testid="rule-source-empty"]')).toBeNull();
    for (const key of ['splunk', 'mdecrevoisier']) {
      expect(text(bySource(key).querySelector('[data-testid="rule-source-count"]'))).withContext(key).toBe('0 rules');
      expect(text(bySource(key).querySelector('[data-testid="rule-source-empty"]'))).withContext(key).toBe(RULE_SOURCE_EMPTY);
      expect(bySource(key).querySelectorAll('a.rs-rule').length).withContext(key).toBe(0);
      // The provenance line still says which commit was searched.
      expect(bySource(key).querySelector('[data-testid="rule-source-provenance"]')).withContext(key).not.toBeNull();
    }
    expect(RULE_SOURCE_EMPTY).toBe('no rules reference this technique at the pinned commit');
    // A technique none of the three names: three empty states, badge 0.
    open('T1082');
    expect(host().querySelectorAll('[data-testid="rule-source-empty"]').length).toBe(3);
    expect(text(host().querySelector('#sb-sec-rule-sources .count-badge'))).toBe('0');
  });

  it('reads the shared snapshot: no request of its own at drawer open or on a second technique', () => {
    open('T1059');
    // Pending: the section says it is reading and lists nothing yet.
    expect(text(host().querySelector('[data-testid="rule-sources"]'))).toContain('Reading the bundled rule snapshot');
    expect(sources().length).toBe(0);
    flushSnapshot();
    fixture.detectChanges();
    expect(sources().length).toBe(3);
    open('T1114');
    open('T1059');
    expect(snapshotRequests().length).withContext('no further snapshot request').toBe(0);
    expect(sources().length).toBe(3);
  });

  it('a snapshot that does not load shows the reason in every source, never an empty state', () => {
    open('T1059');
    const requests = snapshotRequests();
    expect(requests.length).withContext('the drawer shares the one pending request').toBe(1);
    requests[0].flush('missing', { status: 404, statusText: 'Not Found' });
    fixture.detectChanges();
    expect(sources().length).toBe(3);
    for (const s of sources()) {
      expect(text(s.querySelector('[data-testid="rule-source-error"]'))).toContain('bundled snapshot missing');
      expect(s.querySelector('[data-testid="rule-source-empty"]')).toBeNull();
      expect(s.querySelector('[data-testid="rule-source-provenance"]')).toBeNull();
    }
    // The header badge says the snapshot did not load; it never reads 0 ("no rule names it").
    const badge = () => host().querySelector('#sb-sec-rule-sources .count-badge');
    expect(text(badge())).toBe('not loaded');
    expect(badge()!.getAttribute('data-state')).toBe('not-loaded');
    // "Expand sections with data" keeps a failed section open, so its reason stays in view.
    const cmp = fixture.componentInstance;
    cmp.expandRelevant();
    fixture.detectChanges();
    expect(host().querySelector('#sb-sec-rule-sources')!.getAttribute('aria-expanded')).toBe('true');
    expect(host().querySelectorAll('[data-testid="rule-source-error"]').length).toBe(3);
    // After a failed load the next technique opened asks again (shareReplay resets on error),
    // and a load that now succeeds shows the counts.
    open('T1114');
    flushSnapshot();
    fixture.detectChanges();
    expect(host().querySelectorAll('[data-testid="rule-source-error"]').length).toBe(0);
    expect(text(badge())).toBe('11');
    expect(badge()!.getAttribute('data-state')).toBeNull();
  });

  it('a partly malformed snapshot: the badge totals the sources that loaded and says one did not', () => {
    const doc = JSON.parse(JSON.stringify(RULE_COVERAGE_FIXTURE));
    delete doc.sources.splunk.sha;
    snapshotRequests()[0].flush(doc);
    open('T1059');
    expect(text(bySource('splunk').querySelector('[data-testid="rule-source-error"]')))
      .toBe("Not loaded: bundled snapshot missing or malformed: 'splunk' names no repository or commit");
    expect(bySource('splunk').querySelector('[data-testid="rule-source-count"]')).toBeNull();
    expect(text(bySource('elastic').querySelector('[data-testid="rule-source-count"]'))).toBe('323 rules');
    expect(text(bySource('mdecrevoisier').querySelector('[data-testid="rule-source-count"]'))).toBe('7 rules');
    const badge = host().querySelector('#sb-sec-rule-sources .count-badge')!;
    // Elastic + mdecrevoisier only, and the badge says the total leaves Splunk out.
    expect(text(badge)).toBe(`${323 + 7}, 1 of 3 not loaded`);
    expect(badge.getAttribute('data-state')).toBe('partial');
    expect(badge.getAttribute('title')).toBe('Total of the sources that loaded; 1 of 3 did not load');
    // A technique the loaded sources do not name: total 0, yet the section stays open on expand.
    open('T1082');
    expect(text(host().querySelector('#sb-sec-rule-sources .count-badge'))).toBe('0, 1 of 3 not loaded');
    const cmp = fixture.componentInstance;
    cmp.expandRelevant();
    fixture.detectChanges();
    expect(host().querySelector('#sb-sec-rule-sources')!.getAttribute('aria-expanded')).toBe('true');
  });

  it('"Expand sections with data" collapses the section only when every source loaded and none names the technique', () => {
    flushSnapshot();
    open('T1082');
    expect(text(host().querySelector('#sb-sec-rule-sources .count-badge'))).toBe('0');
    const cmp = fixture.componentInstance;
    cmp.expandRelevant();
    fixture.detectChanges();
    expect(host().querySelector('#sb-sec-rule-sources')!.getAttribute('aria-expanded')).toBe('false');
    open('T1059');
    cmp.expandRelevant();
    fixture.detectChanges();
    expect(host().querySelector('#sb-sec-rule-sources')!.getAttribute('aria-expanded')).toBe('true');
  });

  it('has no Sentinel section, jump chip or text, and the Rule sources chip opens its section', () => {
    flushSnapshot();
    open('T1059');
    const cmp = fixture.componentInstance;
    const ids = cmp.sectionIndex.flatMap(g => g.sections.map(s => s.id));
    expect(ids).toContain('rule-sources');
    expect(ids).not.toContain('sentinel-rules');
    expect(ids).not.toContain('sigma');
    expect(ids.length).toBe(48);
    expect(host().querySelector('#sb-sec-sentinel-rules')).toBeNull();
    expect(host().querySelector('.sentinel-section')).toBeNull();
    expect(host().textContent).not.toMatch(/sentinel/i);
    // The chip: collapse the section, then jump to it.
    cmp.toggleSection('rule-sources');
    fixture.detectChanges();
    expect(sources().length).toBe(0);
    host().querySelector<HTMLButtonElement>('.jump-index-toggle')!.click();
    fixture.detectChanges();
    const chip = [...host().querySelectorAll<HTMLButtonElement>('.jump-chip')].find(b => text(b) === 'Rule sources')!;
    expect(chip).withContext('Rule sources chip').toBeDefined();
    expect([...host().querySelectorAll('.jump-chip')].some(b => /sentinel/i.test(text(b)))).toBeFalse();
    chip.click();
    fixture.detectChanges();
    expect(sources().length).toBe(3);
  });
});
