// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { MatrixPageComponent } from './matrix-page.component';

describe('MatrixPageComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [MatrixPageComponent],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();
  });

  it('creates the matrix region and renders no matrix before a domain arrives', () => {
    const fixture = TestBed.createComponent(MatrixPageComponent);
    fixture.detectChanges();
    expect(fixture.componentInstance).toBeTruthy();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('.matrix-region')).toBeTruthy();
    expect(el.querySelector('app-matrix')).toBeNull();
  });

  it('reports zero selected techniques with no matrix mounted', () => {
    const fixture = TestBed.createComponent(MatrixPageComponent);
    fixture.detectChanges();
    expect(fixture.componentInstance.selectedTechniqueCount).toBe(0);
    expect(fixture.nativeElement.querySelector('.bulk-action-bar')).toBeNull();
  });
});
