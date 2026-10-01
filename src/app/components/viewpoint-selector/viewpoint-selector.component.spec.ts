// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ViewpointSelectorComponent } from './viewpoint-selector.component';
import { Viewpoint, ViewpointService } from '../../services/viewpoint.service';

const ANALYST: Viewpoint = {
  id: 'analyst', label: 'Analyst', short: 'Analyst', icon: 'compass',
  tagline: 'Neutral, unified coverage view', defaultLens: 'unified',
  homeRoute: '/matrix', featuredLenses: ['unified', 'coverage', 'risk', 'detection'],
};
const RED: Viewpoint = {
  id: 'red', label: 'Red Team', short: 'Red', icon: 'swords',
  tagline: 'Adversary emulation & offense', defaultLens: 'atomic',
  homeRoute: '/matrix', featuredLenses: ['atomic', 'software'],
};
const DETECTION: Viewpoint = {
  id: 'detection', label: 'Detection Engineering', short: 'Detection', icon: 'radar',
  tagline: 'Detection engineering & rules', defaultLens: 'detection',
  homeRoute: '/detect', featuredLenses: ['detection', 'sigma'],
};

describe('ViewpointSelectorComponent', () => {
  let component: ViewpointSelectorComponent;
  let fixture: ComponentFixture<ViewpointSelectorComponent>;
  let viewpoint$: BehaviorSubject<Viewpoint>;
  let setViewpoint: jasmine.Spy;

  const VIEWPOINTS = [ANALYST, RED, DETECTION];

  beforeEach(async () => {
    viewpoint$ = new BehaviorSubject<Viewpoint>(ANALYST);
    setViewpoint = jasmine.createSpy('setViewpoint');

    await TestBed.configureTestingModule({
      imports: [ViewpointSelectorComponent],
      providers: [
        {
          provide: ViewpointService,
          useValue: {
            viewpoints: VIEWPOINTS,
            viewpoint$: viewpoint$.asObservable(),
            get current() { return viewpoint$.value; },
            setViewpoint,
          },
        },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(ViewpointSelectorComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  it('shows the current viewpoint short label on the trigger', () => {
    const current = fixture.nativeElement.querySelector('.vp-current');
    expect(current.textContent.trim()).toBe('Analyst');
  });

  it('the menu is closed by default', () => {
    expect(fixture.nativeElement.querySelector('.vp-menu')).toBeFalsy();
    const trigger = fixture.nativeElement.querySelector('.vp-trigger');
    expect(trigger.getAttribute('aria-expanded')).toBe('false');
  });

  it('opening the trigger lists every viewpoint', () => {
    component.toggle();
    fixture.detectChanges();
    const options = fixture.nativeElement.querySelectorAll('.vp-option');
    expect(options.length).toBe(VIEWPOINTS.length);
    const labels = [...options].map((el: any) => el.querySelector('.vp-option-label').textContent.trim());
    expect(labels).toEqual(['Analyst', 'Red Team', 'Detection Engineering']);
  });

  it('marks the active viewpoint with aria-checked', () => {
    component.toggle();
    fixture.detectChanges();
    const checked = [...fixture.nativeElement.querySelectorAll('.vp-option')]
      .filter((el: any) => el.getAttribute('aria-checked') === 'true');
    expect(checked.length).toBe(1);
    expect(checked[0].querySelector('.vp-option-label').textContent.trim()).toBe('Analyst');
  });

  it('selecting a viewpoint calls the service and closes the menu', () => {
    component.toggle();
    fixture.detectChanges();
    const options = fixture.nativeElement.querySelectorAll('.vp-option');
    options[1].click(); // Red Team
    fixture.detectChanges();
    expect(setViewpoint).toHaveBeenCalledOnceWith('red');
    expect(fixture.nativeElement.querySelector('.vp-menu')).toBeFalsy();
  });

  it('reflects the active viewpoint pushed from the service', () => {
    viewpoint$.next(DETECTION);
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.vp-current').textContent.trim()).toBe('Detection');
  });

  it('escape closes an open menu', () => {
    component.toggle();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.vp-menu')).toBeTruthy();
    component.onEscape();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.vp-menu')).toBeFalsy();
  });

  it('a click outside the component closes an open menu', () => {
    component.toggle();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.vp-menu')).toBeTruthy();
    document.body.click();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.vp-menu')).toBeFalsy();
  });
});
