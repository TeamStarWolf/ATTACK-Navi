// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ReportPanelComponent } from './report-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { DocumentationService } from '../../services/documentation.service';

describe('ReportPanelComponent', () => {
  let component: ReportPanelComponent;
  let fixture: ComponentFixture<ReportPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ReportPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
        { provide: DocumentationService, useValue: {
            getMitDoc: () => ({ notes: '', owner: '', dueDate: '', controlRefs: '', evidenceUrl: '' }),
            getTechNote: () => '',
        }},
      ],
    });
    fixture = TestBed.createComponent(ReportPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts hidden', () => {
    expect(component).toBeTruthy();
    expect(component.visible).toBe(false);
  });
});
