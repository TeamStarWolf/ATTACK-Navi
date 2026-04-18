// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { TacticSummaryComponent } from './tactic-summary.component';
import { ImplementationService } from '../../services/implementation.service';

describe('TacticSummaryComponent', () => {
  let component: TacticSummaryComponent;
  let fixture: ComponentFixture<TacticSummaryComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [TacticSummaryComponent],
      providers: [
        { provide: ImplementationService, useValue: {
            status$: new BehaviorSubject(new Map()),
        }},
      ],
    });
    fixture = TestBed.createComponent(TacticSummaryComponent);
    component = fixture.componentInstance;
  });

  it('starts hidden', () => {
    expect(component.visible).toBe(false);
    expect(component.data).toBeNull();
  });

  it('position defaults to 0,0', () => {
    expect(component.position).toEqual({ top: 0, left: 0 });
  });
});
