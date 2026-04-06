// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { LegendComponent } from './legend.component';
import { FilterService, HeatmapMode } from '../../services/filter.service';

describe('LegendComponent', () => {
  let component: LegendComponent;
  let fixture: ComponentFixture<LegendComponent>;
  let heatmapMode$: BehaviorSubject<HeatmapMode>;

  beforeEach(async () => {
    heatmapMode$ = new BehaviorSubject<HeatmapMode>('coverage');

    const mockFilterService = {
      heatmapMode$: heatmapMode$.asObservable(),
    };

    await TestBed.configureTestingModule({
      imports: [LegendComponent],
      providers: [
        { provide: FilterService, useValue: mockFilterService },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(LegendComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should render correct color stops for coverage mode', () => {
    const stops = fixture.nativeElement.querySelectorAll('.legend-stop');
    expect(stops.length).toBe(5);

    const labels = Array.from(stops).map((el: any) =>
      el.querySelector('.stop-label').textContent.trim()
    );
    expect(labels).toEqual(['0', '1', '2', '3', '4+']);
  });

  it('should show the mode label', () => {
    const label = fixture.nativeElement.querySelector('.legend-label');
    expect(label).toBeTruthy();
    expect(label.textContent.trim()).toBe('Mitigations');
  });

  it('should update stops when heatmap mode changes to exposure', () => {
    heatmapMode$.next('exposure');
    fixture.detectChanges();

    const label = fixture.nativeElement.querySelector('.legend-label');
    expect(label.textContent.trim()).toBe('Exposure');

    const stops = fixture.nativeElement.querySelectorAll('.legend-stop');
    expect(stops.length).toBe(5);
    const stopLabels = Array.from(stops).map((el: any) =>
      el.querySelector('.stop-label').textContent.trim()
    );
    expect(stopLabels).toEqual(['0', 'low', 'med', 'high', 'critical']);
  });

  it('should show scale arrow for non-categorical modes', () => {
    const arrow = fixture.nativeElement.querySelector('.scale-arrow');
    expect(arrow).toBeTruthy();
  });

  it('should not show scale arrow for categorical mode (status)', () => {
    heatmapMode$.next('status');
    fixture.detectChanges();
    const arrow = fixture.nativeElement.querySelector('.scale-arrow');
    expect(arrow).toBeFalsy();
  });

  it('should render swatches with correct colors for coverage mode', () => {
    const swatches = fixture.nativeElement.querySelectorAll('.swatch');
    expect(swatches.length).toBe(5);
    expect(swatches[0].style.background).toContain('rgb(211, 47, 47)');
    expect(swatches[4].style.background).toContain('rgb(76, 175, 80)');
  });
});
