// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { SourceHealthComponent } from './source-health.component';
import { SourceRegistryService } from '../../services/source-registry.service';
import { SourceRetryService } from '../../services/source-retry.service';
import { SOURCE_DEFINITIONS } from '../../services/source-inventory';

describe('SourceHealthComponent: the data-health view (E1.3)', () => {
  let fixture: ComponentFixture<SourceHealthComponent>;
  let registry: SourceRegistryService;
  let retrySpy: jasmine.Spy;
  let reasonSpy: jasmine.Spy;

  const row = (id: string): HTMLElement => fixture.nativeElement.querySelector(`tr[data-source-id="${id}"]`);
  const status = (id: string): string => row(id).querySelector('.sh-status')!.textContent!.trim();

  beforeEach(async () => {
    const retry = { retry: () => true, unavailableReason: (_: string): string | null => null };
    retrySpy = spyOn(retry, 'retry').and.callThrough();
    reasonSpy = spyOn(retry, 'unavailableReason').and.callFake((id: string) =>
      id === 'wazuh-rules' ? 'compiled into the app' : null);
    await TestBed.configureTestingModule({
      imports: [SourceHealthComponent],
      providers: [{ provide: SourceRetryService, useValue: retry }],
    }).compileComponents();
    registry = TestBed.inject(SourceRegistryService);
    fixture = TestBed.createComponent(SourceHealthComponent);
    fixture.detectChanges();
  });

  it('shows one row per SourceRecord', () => {
    expect(fixture.nativeElement.querySelectorAll('tbody tr').length).toBe(SOURCE_DEFINITIONS.length);
  });

  it('shows each status by name: loaded, failed, empty, stale and archived-upstream', () => {
    registry.succeed('capec', 900);
    registry.fail('engage', 'activities.json: network error (no response)');
    registry.succeed('elastic-tree', 0);
    fixture.detectChanges();
    expect(status('capec')).toBe('loaded');
    expect(status('engage')).toBe('failed');
    expect(status('elastic-tree')).toBe('empty');
    expect(status('d3fend-seed')).toBe('stale');
    expect(status('cis-controls')).toBe('archived-upstream');
    expect(status('nvd')).toBe('not requested');
    expect(row('engage').textContent).toContain('activities.json: network error');
    expect(row('capec').querySelector('.sh-rows')!.textContent!.trim()).toBe('900');
  });

  it('offers a Retry per source that runs that source\'s loader', () => {
    registry.fail('capec', 'HTTP 503');
    fixture.detectChanges();
    const button = row('capec').querySelector('button.sh-retry') as HTMLButtonElement;
    expect(button.textContent!.trim()).toBe('Retry');
    expect(button.getAttribute('aria-label')).toBe('Retry: CAPEC STIX (mitre/cti)');
    button.click();
    expect(retrySpy).toHaveBeenCalledOnceWith('capec');
  });

  it('labels the first attempt for a source not requested yet "Load now"', () => {
    expect((row('nvd').querySelector('button.sh-retry') as HTMLElement).textContent!.trim()).toBe('Load now');
  });

  it('says why a source has no Retry instead of showing a button', () => {
    expect(row('wazuh-rules').querySelector('button')).toBeNull();
    expect(row('wazuh-rules').querySelector('.sh-noretry')!.textContent).toContain('compiled into the app');
    expect(reasonSpy).toHaveBeenCalled();
  });

  it('shows the version or the reviewed date', () => {
    expect(row('epss').textContent).toContain('API v1 (current scores)');
    expect(row('wazuh-rules').textContent).toContain('reviewed 2026-10-16');
  });

  it('can narrow the table to failed or empty sources, and counts each status', () => {
    registry.fail('capec', 'x');
    registry.succeed('elastic-tree', 0);
    fixture.detectChanges();
    (fixture.nativeElement.querySelector('.sh-filter input') as HTMLInputElement).click();
    fixture.detectChanges();
    const ids = [...fixture.nativeElement.querySelectorAll('tbody tr')].map((r: Element) => r.getAttribute('data-source-id'));
    expect(ids.sort()).toEqual(['capec', 'elastic-tree']);
    const summary = fixture.nativeElement.querySelector('[data-testid="source-health-summary"]').textContent;
    expect(summary).toContain('1 failed');
    expect(summary).toContain('1 empty');
  });
});
