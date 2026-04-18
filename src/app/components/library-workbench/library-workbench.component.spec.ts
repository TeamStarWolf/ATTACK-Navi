// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { LibraryWorkbenchComponent } from './library-workbench.component';
import { LibraryService } from '../../services/library.service';

describe('LibraryWorkbenchComponent', () => {
  let component: LibraryWorkbenchComponent;
  let fixture: ComponentFixture<LibraryWorkbenchComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [LibraryWorkbenchComponent],
      providers: [
        { provide: LibraryService, useValue: {
            library$: new BehaviorSubject({
              generated_at: '',
              counts: {},
              categories: {},
              vendors: {},
              tactic_counts: {},
              assets: [],
            }),
            getAssetsForTactic: () => [],
        } },
      ],
    });
    fixture = TestBed.createComponent(LibraryWorkbenchComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts on Explore tab', () => {
    expect(component).toBeTruthy();
    expect(component.currentTab).toBe('explore');
  });

  it('typeFilter starts at "all"', () => {
    expect(component.typeFilter).toBe('all');
  });

  describe('setTab', () => {
    it('updates currentTab', () => {
      component.setTab('coverage');
      expect(component.currentTab).toBe('coverage');
      component.setTab('vendors');
      expect(component.currentTab).toBe('vendors');
      component.setTab('lookup');
      expect(component.currentTab).toBe('lookup');
    });
  });

  describe('setTacticFilter', () => {
    it('toggles when same slug clicked twice', () => {
      component.setTacticFilter('credential-access');
      expect(component.tacticFilter).toBe('credential-access');
      component.setTacticFilter('credential-access');
      expect(component.tacticFilter).toBe('');
    });
  });

  describe('labelOf', () => {
    it('returns label for known type', () => {
      expect(component.labelOf('tool')).toBe('Tools');
    });

    it('returns string fallback for unknown', () => {
      expect(component.labelOf('unknown')).toBe('unknown');
    });
  });
});
