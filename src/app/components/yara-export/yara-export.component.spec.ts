// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { YaraExportComponent } from './yara-export.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { YaraService } from '../../services/yara.service';

describe('YaraExportComponent', () => {
  let component: YaraExportComponent;
  let fixture: ComponentFixture<YaraExportComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [YaraExportComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy('setActivePanel'),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
        { provide: YaraService, useValue: { getAllPatterns: () => [], hasPattern: () => false } },
      ],
    });
    fixture = TestBed.createComponent(YaraExportComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts closed', () => {
    expect(component).toBeTruthy();
    expect(component.open).toBe(false);
  });
});
