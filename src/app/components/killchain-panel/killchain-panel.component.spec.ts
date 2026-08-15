// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { KillchainPanelComponent } from './killchain-panel.component';
import { DataService } from '../../services/data.service';

describe('KillchainPanelComponent', () => {
  let component: KillchainPanelComponent;
  let fixture: ComponentFixture<KillchainPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [KillchainPanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(KillchainPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  it('selectedTacticId starts null', () => {
    expect(component.selectedTacticId).toBeNull();
  });
});
