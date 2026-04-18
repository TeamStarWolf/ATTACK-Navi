// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { SigmaExportComponent } from './sigma-export.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { SigmaService } from '../../services/sigma.service';

describe('SigmaExportComponent', () => {
  let component: SigmaExportComponent;
  let fixture: ComponentFixture<SigmaExportComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [SigmaExportComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy('setActivePanel'),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: {
            status$: new BehaviorSubject(new Map()),
        }},
        { provide: SigmaService, useValue: { getCachedRules: () => [], getRuleCount: () => 0 } },
      ],
    });
    fixture = TestBed.createComponent(SigmaExportComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts closed', () => {
    expect(component).toBeTruthy();
    expect(component.open).toBe(false);
  });

  it('selectedMode starts at "current"', () => {
    expect(component.selectedMode).toBe('current');
  });

  it('previewYaml starts empty', () => {
    expect(component.previewYaml).toBe('');
  });
});
