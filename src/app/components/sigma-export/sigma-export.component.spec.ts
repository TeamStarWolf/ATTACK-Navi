// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { SigmaExportComponent } from './sigma-export.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { SigmaService } from '../../services/sigma.service';

describe('SigmaExportComponent', () => {
  let component: SigmaExportComponent;
  let fixture: ComponentFixture<SigmaExportComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [SigmaExportComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy('setActivePanel'),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: {
            status$: new BehaviorSubject(new Map()),
        }},
        { provide: SigmaService, useValue: { getCachedRules: () => [], getRuleCount: () => 0 } },
      ],
    });
    fixture = TestBed.createComponent(SigmaExportComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  it('selectedMode starts at "current"', () => {
    expect(component.selectedMode).toBe('current');
  });

  it('previewYaml shows the empty-mode message before a domain loads', () => {
    expect(component.previewYaml).toBe('# No techniques found for the selected mode.');
  });

  describe('templates, not rules (E1.6)', () => {
    const techniques = ['T1001', 'T1059.001', 'T1003.001', 'T1112', 'T1566.001', 'T1059.003']
      .map(attackId => ({ id: `attack-pattern--${attackId}`, attackId, name: attackId }));
    // Stand-in for the generator: these three ids have a template.
    const WITH = new Set(['T1059.001', 'T1112', 'T1566.001']);
    let sigma: { hasTemplate: jasmine.Spy; generateRulesForTechniques: jasmine.Spy; exportRules: jasmine.Spy };

    function render(withTemplate: Set<string>) {
      sigma = {
        hasTemplate: jasmine.createSpy('hasTemplate').and.callFake((t: { attackId: string }) => withTemplate.has(t.attackId)),
        generateRulesForTechniques: jasmine.createSpy('generateRulesForTechniques')
          .and.callFake((ts: { attackId: string }[]) => ts.map(t => t.attackId).join(',')),
        exportRules: jasmine.createSpy('exportRules'),
      };
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({
        imports: [SigmaExportComponent],
        providers: [
          { provide: FilterService, useValue: { activePanel$: new BehaviorSubject<string | null>(null), setActivePanel: () => undefined } },
          { provide: DataService, useValue: { domain$: new BehaviorSubject({ techniques, techniquesByMitigation: new Map() }) } },
          { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) } },
          { provide: SigmaService, useValue: sigma },
        ],
      });
      fixture = TestBed.createComponent(SigmaExportComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
    }

    it('counts templates separately from techniques and previews the first three templates', () => {
      render(WITH);
      expect(component.techniqueCount).toBe(6);
      expect(component.templateCount).toBe(3);
      expect(component.countLabel).toBe('3 templates');
      const previewed = sigma.generateRulesForTechniques.calls.mostRecent().args[0].map((t: { attackId: string }) => t.attackId);
      expect(previewed).toEqual(['T1059.001', 'T1112', 'T1566.001']);
      const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
      expect(text).toContain('Sigma Template Export');
      expect(text).toContain('Templates, not rules');
      expect((fixture.nativeElement as HTMLElement).querySelector('.sigma-count-badge')?.textContent?.trim()).toBe('6');
      expect(text).toContain('techniques selected, 3 with a template');
      expect(text).toContain('Export 3 templates as YAML');
    });

    it('disables the export when no selected technique has a template', () => {
      render(new Set());
      expect(component.templateCount).toBe(0);
      expect(component.previewYaml).toBe('# None of the selected techniques has a Sigma template.');
      const button = (fixture.nativeElement as HTMLElement).querySelector('.sigma-export-btn') as HTMLButtonElement;
      expect(button.disabled).toBeTrue();
      component.exportAll();
      expect(sigma.exportRules).not.toHaveBeenCalled();
    });
  });
});
