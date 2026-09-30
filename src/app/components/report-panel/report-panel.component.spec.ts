// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ReportPanelComponent } from './report-panel.component';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { DocumentationService } from '../../services/documentation.service';
import { ReportConfigService } from '../../services/report-config.service';

describe('ReportPanelComponent', () => {
  let component: ReportPanelComponent;
  let fixture: ComponentFixture<ReportPanelComponent>;

  beforeEach(() => {
    localStorage.removeItem('mitre-nav-report-config-v1');

    TestBed.configureTestingModule({
      imports: [ReportPanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
        { provide: DocumentationService, useValue: {
            mitDocs$: new BehaviorSubject(new Map()),
            getMitDoc: () => ({ notes: '', owner: '', dueDate: '', controlRefs: '', evidenceUrl: '' }),
            getTechNote: () => '',
        }},
        ReportConfigService,
      ],
    });
    fixture = TestBed.createComponent(ReportPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  afterEach(() => {
    localStorage.removeItem('mitre-nav-report-config-v1');
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
