// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Behavioural specs for CompliancePanelComponent against its real template, on
// the fixed fixture domain. The control-framework services are stubs whose
// per-technique control lists come from the deterministic harness signal, so
// every expected row and score is recomputed here independently.
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject } from 'rxjs';

import { CompliancePanelComponent } from './compliance-panel.component';
import { Domain } from '../../models/domain';
import { Technique } from '../../models/technique';
import { DataService } from '../../services/data.service';
import { CisControlsService } from '../../services/cis-controls.service';
import { CloudControlsService } from '../../services/cloud-controls.service';
import { NistMappingService } from '../../services/nist-mapping.service';
import { CriProfileService } from '../../services/cri-profile.service';
import { CsaCcmService } from '../../services/csa-ccm.service';
import { M365ControlsService } from '../../services/m365-controls.service';
import { parseFixtureDomain, resetBrowserState, signal } from '../../testing/lens-harness';
import { COMPLIANCE_TABS, COMPLIANCE_TAB_META } from './compliance-mapping-meta';

/** `n` fake controls for one technique, ids prefixed by framework so pills are recognisable. */
const controls = (prefix: string, source: string, attackId: string) =>
  Array.from({ length: signal(source, attackId) }, (_, i) => ({ id: `${prefix}-${attackId}-${i + 1}`, name: `${prefix} control ${i + 1}` }));

function frameworkStub(prefix: string, source: string) {
  return {
    loaded$: new BehaviorSubject(true),
    total$: new BehaviorSubject(100),
    getControlsForTechnique: (attackId: string) => controls(prefix, source, attackId),
  };
}

describe('CompliancePanelComponent (rendered, fixture domain)', () => {
  let domain: Domain;
  let parents: Technique[];
  let fixture: ComponentFixture<CompliancePanelComponent>;
  let host: HTMLElement;

  beforeEach(() => {
    resetBrowserState();
    domain = parseFixtureDomain();
    parents = domain.techniques.filter(t => !t.isSubtechnique);
    TestBed.configureTestingModule({
      imports: [CompliancePanelComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: CisControlsService, useValue: frameworkStub('CIS', 'cis') },
        { provide: NistMappingService, useValue: frameworkStub('NIST', 'nist') },
        { provide: CriProfileService, useValue: frameworkStub('CRI', 'cri') },
        { provide: CsaCcmService, useValue: frameworkStub('CCM', 'csa') },
        { provide: M365ControlsService, useValue: frameworkStub('M365', 'm365-ctl') },
        { provide: CloudControlsService, useValue: {
          loaded$: new BehaviorSubject(true),
          total$: new BehaviorSubject(100),
          getControlsForTechnique: (attackId: string, provider: string) => controls(provider.toUpperCase(), `cloud-${provider}`, attackId),
          getProviderTotal: () => 100,
          isProviderLoaded: () => true,
        } },
      ],
    });
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    fixture = TestBed.createComponent(CompliancePanelComponent);
    fixture.detectChanges();
    host = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => resetBrowserState());

  const rows = () => [...host.querySelectorAll('tr.comp-row')] as HTMLElement[];
  const rowIds = () => rows().map(r => r.querySelector('.tech-id a')!.textContent!.trim());

  it('NIST tab lists only parent techniques with a NIST mapping, most-mapped first', () => {
    const mapped = parents.filter(t => signal('nist', t.attackId) > 0);
    expect(rows().length).toBe(mapped.length);
    expect([...rowIds()].sort()).toEqual(mapped.map(t => t.attackId).sort());
    const counts = rows().map(r => Number(r.querySelector('.count-badge')!.textContent));
    expect(counts).toEqual([...counts].sort((a, b) => b - a));
    // Each row's count and pills come from that technique's own control list.
    const first = rows()[0];
    const id = first.querySelector('.tech-id a')!.textContent!.trim();
    expect(counts[0]).toBe(signal('nist', id));
    const pills = [...first.querySelectorAll('.ctrl-pill')].map(p => p.textContent!.trim());
    expect(pills).toEqual([`NIST-${id}-1`, `NIST-${id}-2`].slice(0, Math.min(2, counts[0])));
  });

  it('score cards show technique coverage per framework (covered / parent techniques)', () => {
    const card = (label: string) => [...host.querySelectorAll('.score-card')]
      .find(c => c.querySelector('.score-label')!.textContent!.trim() === label) as HTMLElement;
    for (const [label, source] of [['NIST 800-53', 'nist'], ['CRI Profile', 'cri'], ['AWS', 'cloud-aws']]) {
      const covered = parents.filter(t => signal(source, t.attackId) > 0).length;
      const c = card(label);
      expect(c.querySelector('.score-meta')!.textContent!.trim()).withContext(label).toBe(`${covered}/${parents.length}`);
      expect(c.querySelector('.score-value')!.textContent!.trim()).withContext(label)
        .toBe(`${Math.round((covered / parents.length) * 100)}%`);
    }
    // CIS is withdrawn upstream (E1.6): no score card, even though its stub reports controls.
    expect(card('CIS v8')).toBeUndefined();
  });

  // Post-Phase-1 QA (R9c): the percentages are Known data (technique tabs) or
  // self-attested implementation (SOC 2, ISO 27001, PCI DSS), never a
  // 'compliance score' or 'coverage'.
  it('names the score cards a control mapping and says what each header count counts', () => {
    const subtitle = () => host.querySelector('.header-subtitle')!.textContent!.replace(/\s+/g, ' ').trim();
    expect(host.querySelector('.score-dashboard-head h3')!.textContent!.trim()).toBe('Control mapping by framework');
    expect(host.querySelector('.score-dashboard-note')!.textContent).toContain('at least one control mapped');
    const nist = parents.filter(t => signal('nist', t.attackId) > 0).length;
    expect(subtitle()).toBe(`${nist} techniques with NIST 800-53 controls mapped`);

    const tabs = [...host.querySelectorAll('.tab-bar .tab-btn')] as HTMLButtonElement[];
    tabs[COMPLIANCE_TABS.indexOf('pci')].click();
    fixture.detectChanges();
    expect(subtitle()).toMatch(/^\d+ of \d+ PCI DSS v4\.0 controls with every mapped mitigation implemented \(self-attested\)$/);

    tabs[COMPLIANCE_TABS.indexOf('m365-ctrl')].click();
    fixture.detectChanges();
    expect(subtitle()).toBe(`${parents.filter(t => signal('m365-ctl', t.attackId) > 0).length} techniques with M365 controls mapped`);
    expect(host.textContent).not.toMatch(/Compliance Score|\bcoverage\b/);
  });

  it('switching tab and searching re-renders the table', () => {
    (host.querySelector('.tab-btn:nth-child(2)') as HTMLButtonElement).click(); // AWS (CIS, the first tab, is withdrawn)
    fixture.detectChanges();
    expect(rows().length).toBe(parents.filter(t => signal('cloud-aws', t.attackId) > 0).length);

    const target = rowIds()[0];
    const input = host.querySelector('.search-input') as HTMLInputElement;
    input.value = target;
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(rowIds()).toEqual([target]);
  });

  it('"Technique" sort shows every parent technique, mapped or not', () => {
    const btn = [...host.querySelectorAll('.sort-btn')].find(b => b.textContent!.trim() === 'Technique') as HTMLButtonElement;
    btn.click();
    fixture.detectChanges();
    expect(rows().length).toBe(parents.length);
  });

  // Plan P1 row E1.6, acceptance "every compliance tab shows its mapping version".
  it('every compliance tab shows its mapping version', () => {
    const tabs = [...host.querySelectorAll('.tab-bar .tab-btn')] as HTMLButtonElement[];
    expect(tabs.length).toBe(COMPLIANCE_TABS.length);
    tabs.forEach((btn, i) => {
      btn.click();
      fixture.detectChanges();
      const tab = COMPLIANCE_TABS[i];
      const meta = COMPLIANCE_TAB_META[tab];
      const stamp = host.querySelector('[data-testid="mapping-stamp"]') as HTMLElement;
      expect(stamp.getAttribute('data-tab')).withContext(btn.textContent!.trim()).toBe(tab);
      expect(stamp.textContent!.trim()).withContext(tab).toBe(meta.stamp);
      expect(btn.title).withContext(tab).toContain(meta.stamp);
      if (meta.mappedVs) expect(stamp.textContent).withContext(tab).toMatch(/mapped vs ATT&CK 1[67].1/);
    });
    const versions = COMPLIANCE_TABS.map(t => COMPLIANCE_TAB_META[t].mappedVs).filter(Boolean);
    expect(new Set(versions)).toEqual(new Set(['16.1', '17.1']));
  });

  it("shows CIS as 'source withdrawn upstream' with no table, even when its service reports controls", () => {
    const cisBtn = host.querySelector('.tab-bar .tab-btn') as HTMLButtonElement;
    expect(cisBtn.querySelector('.tab-badge-withdrawn')?.textContent?.trim()).toBe('withdrawn');
    cisBtn.click();
    fixture.detectChanges();
    expect(host.querySelector('[data-testid="mapping-withdrawn"]')?.textContent).toContain('Source withdrawn upstream.');
    expect(host.querySelector('[data-testid="mapping-stamp"]')!.textContent).toMatch(/^Source withdrawn upstream: /);
    expect(host.querySelector('.header-subtitle')!.textContent!.trim()).toBe('CIS Controls: source withdrawn upstream');
    expect(host.querySelector('table.comp-table')).toBeNull();
    expect(rows().length).toBe(0);
  });
});
