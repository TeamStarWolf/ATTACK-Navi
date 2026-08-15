// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { IconComponent } from './icon.component';
import { ICONS } from './icon-registry';

describe('IconComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [IconComponent] }).compileComponents();
  });

  function create(name: string, size?: number) {
    const fixture = TestBed.createComponent(IconComponent);
    fixture.componentRef.setInput('name', name);
    if (size !== undefined) fixture.componentRef.setInput('size', size);
    fixture.detectChanges();
    return fixture;
  }

  it('renders the requested icon paths', () => {
    const fixture = create('search');
    const svg: SVGElement = fixture.nativeElement.querySelector('svg');
    expect(svg).toBeTruthy();
    expect(svg.innerHTML).toContain('circle');
    expect(svg.getAttribute('aria-hidden')).toBe('true');
  });

  it('applies the size input to width and height', () => {
    const fixture = create('x', 24);
    const svg: SVGElement = fixture.nativeElement.querySelector('svg');
    expect(svg.getAttribute('width')).toBe('24');
    expect(svg.getAttribute('height')).toBe('24');
  });

  it('falls back to the circle glyph for unknown names', () => {
    const fixture = create('definitely-not-an-icon');
    const svg: SVGElement = fixture.nativeElement.querySelector('svg');
    const circle = svg.querySelector('circle');
    expect(svg.children.length).toBe(1);
    expect(circle?.getAttribute('r')).toBe('10');
  });

  it('exposes an accessible label when provided', () => {
    const fixture = TestBed.createComponent(IconComponent);
    fixture.componentRef.setInput('name', 'info');
    fixture.componentRef.setInput('label', 'Information');
    fixture.detectChanges();
    const svg: SVGElement = fixture.nativeElement.querySelector('svg');
    expect(svg.getAttribute('role')).toBe('img');
    expect(svg.getAttribute('aria-label')).toBe('Information');
    expect(svg.hasAttribute('aria-hidden')).toBeFalse();
  });

  it('every registry entry contains only whitelisted SVG shape tags', () => {
    const allowed = /^(path|circle|rect|line|polyline|polygon|ellipse)$/;
    for (const [name, markup] of Object.entries(ICONS)) {
      const tags = [...markup.matchAll(/<([a-z-]+)[\s/>]/g)].map((m) => m[1]);
      expect(tags.length).withContext(name).toBeGreaterThan(0);
      for (const tag of tags) {
        expect(tag).withContext(`${name}: <${tag}>`).toMatch(allowed);
      }
    }
  });
});
