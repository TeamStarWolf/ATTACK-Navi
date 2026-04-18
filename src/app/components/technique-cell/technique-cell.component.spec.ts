// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { TechniqueCellComponent } from './technique-cell.component';
import { SettingsService } from '../../services/settings.service';
import { Technique } from '../../models/technique';

const STUB_TECH = {
  id: 'attack-pattern--abc',
  attackId: 'T1059',
  name: 'Command and Scripting Interpreter',
  isSubtechnique: false,
  mitigationCount: 3,
} as unknown as Technique;

describe('TechniqueCellComponent', () => {
  let component: TechniqueCellComponent;
  let fixture: ComponentFixture<TechniqueCellComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [TechniqueCellComponent],
      providers: [
        { provide: SettingsService, useValue: {
            settings$: new BehaviorSubject({
              matrixCellSize: 'normal',
              showTechniqueIds: true,
              showTechniqueName: true,
              showMitigationCount: true,
              showSubtechniqueCount: true,
            }),
        }},
      ],
    });
    fixture = TestBed.createComponent(TechniqueCellComponent);
    component = fixture.componentInstance;
    component.technique = STUB_TECH;
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  it('exposes a "selected" output emitter', () => {
    expect(component.selected).toBeTruthy();
    expect(typeof component.selected.emit).toBe('function');
  });
});
