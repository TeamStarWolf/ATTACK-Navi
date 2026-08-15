// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { BehaviorSubject } from 'rxjs';
import { UniversalSearchComponent } from './universal-search.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { D3fendService } from '../../services/d3fend.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { EngageService } from '../../services/engage.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { ExportActionsService } from '../../services/export-actions.service';
import { CommandPaletteService } from '../../services/command-palette.service';

describe('UniversalSearchComponent', () => {
  let component: UniversalSearchComponent;
  let fixture: ComponentFixture<UniversalSearchComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [UniversalSearchComponent],
      providers: [
        provideRouter([]),
        { provide: FilterService, useValue: {
            selectTechnique: jasmine.createSpy(),
            filterByMitigation: jasmine.createSpy(),
            toggleThreatGroup: jasmine.createSpy(),
            toggleCampaign: jasmine.createSpy(),
            clearAll: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: D3fendService, useValue: { getAllTechniques: () => [] } },
        { provide: CARService, useValue: { getAll: () => [] } },
        { provide: AtomicService, useValue: { getAll: () => [] } },
        { provide: EngageService, useValue: { byAttackId: new Map() } },
        { provide: AttackCveService, useValue: { searchCves: () => [] } },
        { provide: ExportActionsService, useValue: {
            exportCsv: jasmine.createSpy(),
            exportXlsxWorkbook: jasmine.createSpy(),
            exportNavigatorLayer: jasmine.createSpy(),
            openInNavigator: jasmine.createSpy(),
        }},
      ],
    });
    fixture = TestBed.createComponent(UniversalSearchComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts closed', () => {
    expect(component).toBeTruthy();
    expect(component.open).toBe(false);
  });

  it('opens and closes through CommandPaletteService', () => {
    const palette = TestBed.inject(CommandPaletteService);
    palette.open();
    expect(component.open).toBe(true);
    palette.close();
    expect(component.open).toBe(false);
  });

  it('surfaces navigation commands for destination names', () => {
    (component as any).runSearch('gap analysis');
    const nav = component.results.filter(r => r.kind === 'nav');
    expect(nav.length).toBeGreaterThan(0);
    expect(nav[0].name).toBe('Gap Analysis');
  });

  it('surfaces action commands', () => {
    (component as any).runSearch('theme');
    const actions = component.results.filter(r => r.kind === 'action');
    expect(actions.some(a => a.id === 'toggle-theme')).toBe(true);
  });

  it('selecting an export action invokes ExportActionsService', () => {
    const exports = TestBed.inject(ExportActionsService) as any;
    component.selectResult({ kind: 'action', id: 'export-csv', name: '', score: 0 } as any);
    expect(exports.exportCsv).toHaveBeenCalled();
  });
});
