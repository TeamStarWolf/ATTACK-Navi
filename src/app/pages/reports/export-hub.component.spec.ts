// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { ExportHubComponent } from './export-hub.component';
import { ExportActionsService } from '../../services/export-actions.service';

describe('ExportHubComponent', () => {
  let component: ExportHubComponent;
  let fixture: ComponentFixture<ExportHubComponent>;
  let mockExport: jasmine.SpyObj<ExportActionsService>;

  beforeEach(() => {
    mockExport = jasmine.createSpyObj('ExportActionsService', [
      'exportCsv', 'exportTacticCsv', 'exportImplPlanCsv', 'exportFullReport',
      'exportMatrixPng', 'exportHtmlCoverageReport', 'exportPdf', 'exportXlsxWorkbook',
      'exportNavigatorLayer', 'openInNavigator', 'importNavigatorLayer',
      'exportStateJson', 'importStateJson',
    ]);
    TestBed.configureTestingModule({
      imports: [ExportHubComponent],
      providers: [{ provide: ExportActionsService, useValue: mockExport }],
    });
    fixture = TestBed.createComponent(ExportHubComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  it('renders 16 export cards across 5 sections (incl. workspace backup)', () => {
    const cards = fixture.nativeElement.querySelectorAll('.export-card');
    expect(cards.length).toBe(16);
    const sections = fixture.nativeElement.querySelectorAll('.hub-section');
    expect(sections.length).toBe(5);
  });

  it('clicking a card invokes its export action', () => {
    const firstCard = fixture.nativeElement.querySelector('.export-card');
    firstCard.click();
    expect(mockExport.exportCsv).toHaveBeenCalled();
  });
});
