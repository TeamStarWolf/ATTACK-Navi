// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { LayersPanelComponent } from './layers-panel.component';
import { LayersService } from '../../services/layers.service';
import { FilterService } from '../../services/filter.service';
import { ImplementationService } from '../../services/implementation.service';
import { DocumentationService } from '../../services/documentation.service';

describe('LayersPanelComponent', () => {
  let component: LayersPanelComponent;
  let fixture: ComponentFixture<LayersPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [LayersPanelComponent],
      providers: [
        { provide: LayersService, useValue: { layers$: new BehaviorSubject([]) }},
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy('setActivePanel'),
        }},
        { provide: ImplementationService, useValue: {} },
        { provide: DocumentationService, useValue: {} },
      ],
    });
    fixture = TestBed.createComponent(LayersPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts closed', () => {
    expect(component).toBeTruthy();
    expect(component.open).toBe(false);
  });

  it('newLayerName starts empty', () => {
    expect(component.newLayerName).toBe('');
    expect(component.newLayerDesc).toBe('');
  });
});
