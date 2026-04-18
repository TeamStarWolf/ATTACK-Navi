// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { TechniqueTooltipComponent } from './technique-tooltip.component';
import { Technique } from '../../models/technique';

const STUB_TECH = {
  id: 'attack-pattern--abc',
  attackId: 'T1059',
  name: 'Command Interpreter',
  description: 'Adversaries may abuse command interpreters',
} as Technique;

describe('TechniqueTooltipComponent', () => {
  let component: TechniqueTooltipComponent;
  let fixture: ComponentFixture<TechniqueTooltipComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({ imports: [TechniqueTooltipComponent] });
    fixture = TestBed.createComponent(TechniqueTooltipComponent);
    component = fixture.componentInstance;
  });

  it('starts hidden with no technique', () => {
    expect(component.visible).toBe(false);
    expect(component.technique).toBeNull();
  });

  it('show() sets visible + technique + counts', () => {
    component.show(STUB_TECH, 5, 12, 100, 100);
    expect(component.visible).toBe(true);
    expect(component.technique).toBe(STUB_TECH);
    expect(component.mitigationCount).toBe(5);
    expect(component.threatGroupCount).toBe(12);
  });

  it('hide() clears visibility + technique', () => {
    component.show(STUB_TECH, 5, 12, 100, 100);
    component.hide();
    expect(component.visible).toBe(false);
    expect(component.technique).toBeNull();
  });

  it('flips position when tooltip would overflow viewport', () => {
    component.show(STUB_TECH, 0, 0, window.innerWidth - 10, window.innerHeight - 10);
    // Right + bottom edge → x and y should be repositioned to the upper-left side
    expect(component.x).toBeLessThan(window.innerWidth);
    expect(component.y).toBeLessThan(window.innerHeight);
  });
});
