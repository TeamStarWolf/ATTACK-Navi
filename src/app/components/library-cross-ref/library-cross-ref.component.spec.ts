// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { LibraryCrossRefComponent } from './library-cross-ref.component';
import { LibraryService } from '../../services/library.service';
import { ViewModeService } from '../../services/view-mode.service';

describe('LibraryCrossRefComponent', () => {
  let component: LibraryCrossRefComponent;
  let fixture: ComponentFixture<LibraryCrossRefComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [LibraryCrossRefComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: LibraryService, useValue: {
            library$: { subscribe: () => ({ unsubscribe: () => {} }) },
            getAssetsForTechnique: () => [],
        } },
        { provide: ViewModeService, useValue: { set: jasmine.createSpy('set') } },
      ],
    });
    fixture = TestBed.createComponent(LibraryCrossRefComponent);
    component = fixture.componentInstance;
  });

  it('is created and starts with empty assets list', () => {
    expect(component).toBeTruthy();
    expect(component.assets).toEqual([]);
  });

  it('shortType maps types to short labels', () => {
    expect(component.shortType('tool')).toBe('GH');
    expect(component.shortType('channel')).toBe('YT');
    expect(component.shortType('x-account')).toBe('@X');
    expect(component.shortType('book')).toBe('BO');
    expect(component.shortType('field-note')).toBe('FI');
  });

  it('openLibrary delegates to ViewModeService.set("library")', () => {
    component.openLibrary();
    const vm = TestBed.inject(ViewModeService) as any;
    expect(vm.set).toHaveBeenCalledWith('library');
  });
});
