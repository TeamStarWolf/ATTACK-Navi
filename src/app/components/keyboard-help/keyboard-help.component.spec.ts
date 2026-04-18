// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { KeyboardHelpComponent } from './keyboard-help.component';

describe('KeyboardHelpComponent', () => {
  let component: KeyboardHelpComponent;
  let fixture: ComponentFixture<KeyboardHelpComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({ imports: [KeyboardHelpComponent] });
    fixture = TestBed.createComponent(KeyboardHelpComponent);
    component = fixture.componentInstance;
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  it('exposes a non-empty set of shortcut groups', () => {
    expect(component.groups.length).toBeGreaterThan(0);
    component.groups.forEach(g => {
      expect(g.title).toBeTruthy();
      expect(g.shortcuts.length).toBeGreaterThan(0);
    });
  });

  it('every shortcut has at least one key + a description', () => {
    for (const g of component.groups) {
      for (const s of g.shortcuts) {
        expect(s.keys.length).toBeGreaterThan(0);
        expect(s.description).toBeTruthy();
      }
    }
  });
});
