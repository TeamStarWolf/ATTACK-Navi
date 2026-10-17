// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { AppComponent } from './app.component';
import { FilterService } from './services/filter.service';

describe('AppComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AppComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    }).compileComponents();
  });

  it('should create the app', () => {
    const fixture = TestBed.createComponent(AppComponent);
    const app = fixture.componentInstance;
    expect(app).toBeTruthy();
  });

  it('closes the technique drawer only when the route PATH changes', () => {
    const fixture = TestBed.createComponent(AppComponent);
    const app = fixture.componentInstance as unknown as {
      clearSelectionOnRouteChange(url: string): void;
    };
    const filterService = TestBed.inject(FilterService);
    const clear = spyOn(filterService, 'selectTechnique');

    app.clearSelectionOnRouteChange('/matrix');            // first nav: record only
    expect(clear).not.toHaveBeenCalled();

    app.clearSelectionOnRouteChange('/matrix?heat=kev');   // same path (url-state query write)
    expect(clear).not.toHaveBeenCalled();

    app.clearSelectionOnRouteChange('/exposure/risk');     // path change -> close drawer
    expect(clear).toHaveBeenCalledOnceWith(null);

    app.clearSelectionOnRouteChange('/exposure/risk?x=1'); // same path again -> no extra clear
    expect(clear).toHaveBeenCalledTimes(1);
  });
});
