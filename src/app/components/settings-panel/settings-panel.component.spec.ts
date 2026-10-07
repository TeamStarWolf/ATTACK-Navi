// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject } from 'rxjs';
import { SettingsPanelComponent } from './settings-panel.component';
import { DataService } from '../../services/data.service';

describe('SettingsPanelComponent', () => {
  it('class is exported', () => {
    expect(SettingsPanelComponent).toBeTruthy();
  });

  describe('third-party notices (Data tab)', () => {
    beforeEach(async () => {
      await TestBed.configureTestingModule({
        imports: [SettingsPanelComponent],
        providers: [
          provideHttpClient(withXhr()),
          provideHttpClientTesting(),
          {
            provide: DataService,
            useValue: {
              domain$: new BehaviorSubject(null),
              getCurrentAttackDomain: () => 'enterprise',
              getCurrentDomain: () => null,
              forceRefresh: () => Promise.resolve(),
            },
          },
        ],
      }).compileComponents();
    });

    // The component is OnPush, so the tab is chosen before the first change
    // detection pass rather than flipped on a rendered fixture.
    function render(tab: SettingsPanelComponent['activeTab']): ComponentFixture<SettingsPanelComponent> {
      const fixture = TestBed.createComponent(SettingsPanelComponent);
      fixture.componentInstance.activeTab = tab;
      fixture.detectChanges();
      return fixture;
    }

    it('links to the shipped notices file with a relative URL that works under any base href', () => {
      const fixture = render('data');
      const link = fixture.nativeElement.querySelector('a.third-party-notices-link') as HTMLAnchorElement;
      expect(link).toBeTruthy();
      // Relative to the document base (`<base href="./">`), so it resolves on
      // GitHub Pages (/ATTACK-Navi/assets/...) and in the Docker image (/assets/...).
      expect(link.getAttribute('href')).toBe('assets/THIRD_PARTY_NOTICES.md');
      expect(link.getAttribute('target')).toBe('_blank');
      expect(link.getAttribute('rel')).toContain('noopener');
    });

    it('shows the MITRE ATT&CK redistribution statement that the ATT&CK license requires', () => {
      const fixture = render('data');
      const text = (fixture.nativeElement.querySelector('.third-party-notice--mitre') as HTMLElement).textContent ?? '';
      expect(text).toContain('© 2026 The MITRE Corporation');
      expect(text).toContain('reproduced and distributed with the permission of The MITRE Corporation');
    });

    it('shows the NVD API attribution notice that the NVD terms of use ask for', () => {
      const fixture = render('data');
      const text = (fixture.nativeElement.querySelector('.third-party-notice--nvd') as HTMLElement).textContent ?? '';
      expect(text).toContain('This product uses the NVD API but is not endorsed or certified by the NVD.');
    });

    it('keeps the notices on the Data tab only', () => {
      const fixture = render('scoring');
      expect(fixture.nativeElement.querySelector('a.third-party-notices-link')).toBeNull();
      expect(fixture.nativeElement.querySelector('.third-party-notice--mitre')).toBeNull();
    });
  });
});
