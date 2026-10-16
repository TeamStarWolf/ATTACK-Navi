// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Behavioural specs for SiemExportComponent against its real template, the real
// CARService (bundled CAR analytics) and the fixed fixture domain.
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';

import { SiemExportComponent } from './siem-export.component';
import { Domain } from '../../models/domain';
import { CARService } from '../../services/car.service';
import { DataService } from '../../services/data.service';
import { parseFixtureDomain, resetBrowserState } from '../../testing/lens-harness';

describe('SiemExportComponent (rendered, fixture domain)', () => {
  let fixture: ComponentFixture<SiemExportComponent>;
  let host: HTMLElement;
  let car: CARService;

  beforeEach(() => {
    resetBrowserState();
    const domain: Domain = parseFixtureDomain();
    TestBed.configureTestingModule({
      imports: [SiemExportComponent],
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    car = TestBed.inject(CARService);
    fixture = TestBed.createComponent(SiemExportComponent);
    fixture.detectChanges();
    host = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => resetBrowserState());

  const text = (sel: string) => host.querySelector(sel)!.textContent!.replace(/\s+/g, ' ').trim();
  const preview = () => (host.querySelector('textarea.code-preview') as HTMLTextAreaElement).value;
  const platform = (label: string) => {
    ([...host.querySelectorAll('.platform-tab')].find(b => b.textContent!.includes(label)) as HTMLButtonElement).click();
    fixture.detectChanges();
  };

  it('defaults to Splunk SPL over every bundled CAR analytic', () => {
    const all = car.getAll();
    expect(all.length).toBeGreaterThan(0);
    expect(text('.platform-tab.active')).toContain('Splunk SPL');
    expect(text('.mode-count-badge')).toBe(String(all.length));
    expect(text('.summary-badge.blue')).toBe(String(all.length));
    expect(text('.file-ext')).toBe('→ .spl');
    const body = preview();
    expect(body.startsWith('| =====')).toBeTrue();
    expect(body).toContain(`| Analytics: ${all.length}  |  Platform: Splunk SPL`);
    for (const a of all) expect(body).toContain(`| ===== ${a.id}: ${a.name} =====`);
  });

  it('switching platform regenerates the preview in that query language', () => {
    platform('Sentinel KQL');
    expect(text('.file-ext')).toBe('→ .kql');
    expect(preview().startsWith('//')).toBeTrue();
    platform('Elastic EQL');
    expect(text('.file-ext')).toBe('→ .eql');
  });

  it('the filter narrows the export to matching analytics', () => {
    const target = car.getAll()[0];
    const input = host.querySelector('.siem-filter-input') as HTMLInputElement;
    input.value = target.id;
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    const matching = car.getAll().filter(a =>
      a.id.toLowerCase().includes(target.id.toLowerCase()) ||
      a.name.toLowerCase().includes(target.id.toLowerCase()) ||
      a.attackIds.some(id => id.toLowerCase().includes(target.id.toLowerCase())));
    expect(text('.summary-badge.blue')).toBe(String(matching.length));
    expect(preview()).toContain(`| ===== ${target.id}: ${target.name} =====`);
    for (const other of car.getAll().filter(a => !matching.includes(a))) {
      expect(preview()).not.toContain(`| ===== ${other.id}: `);
    }
  });

  it('a filter that matches nothing renders the empty-export comment', () => {
    const input = host.querySelector('.siem-filter-input') as HTMLInputElement;
    input.value = 'zzzz-no-such-analytic';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(text('.summary-badge.blue')).toBe('0');
    expect(preview()).toBe('| * No CAR analytics matched the current filter *');
  });
});
