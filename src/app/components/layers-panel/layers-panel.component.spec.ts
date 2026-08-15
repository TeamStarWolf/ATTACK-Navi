// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
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
        provideRouter([]),
        { provide: LayersService, useValue: { layers$: new BehaviorSubject([]) }},
        { provide: FilterService, useValue: {} },
        { provide: ImplementationService, useValue: {} },
        { provide: DocumentationService, useValue: {} },
      ],
    });
    fixture = TestBed.createComponent(LayersPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  it('newLayerName starts empty', () => {
    expect(component.newLayerName).toBe('');
    expect(component.newLayerDesc).toBe('');
  });
});
