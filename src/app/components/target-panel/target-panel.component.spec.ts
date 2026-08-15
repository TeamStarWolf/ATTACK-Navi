// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { TargetPanelComponent } from './target-panel.component';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';

describe('TargetPanelComponent', () => {
  let component: TargetPanelComponent;
  let fixture: ComponentFixture<TargetPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [TargetPanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) } },
      ],
    });
    fixture = TestBed.createComponent(TargetPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
