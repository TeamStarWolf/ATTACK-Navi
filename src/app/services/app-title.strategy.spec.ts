// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// AppTitleStrategy: route titles from data.tab / data.title, and a detail page's
// own title (technique page design 4.9: "T1037 Boot or Logon Initialization
// Scripts · ATT&CK-Navi") held for its path across query-only navigations.
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideLocationMocks } from '@angular/common/testing';
import { Title } from '@angular/platform-browser';
import { Router, TitleStrategy, provideRouter } from '@angular/router';
import { AppTitleStrategy, titlePath } from './app-title.strategy';

@Component({ standalone: true, template: '' })
class Blank {}

describe('AppTitleStrategy', () => {
  let router: Router;
  let title: Title;
  let strategy: AppTitleStrategy;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([
          { path: 'matrix', component: Blank, data: { title: 'Matrix' } },
          { path: 'technique/:domain/:id', component: Blank, data: { title: 'Technique' } },
        ]),
        provideLocationMocks(),
        { provide: TitleStrategy, useClass: AppTitleStrategy },
      ],
    });
    router = TestBed.inject(Router);
    title = TestBed.inject(Title);
    strategy = TestBed.inject(TitleStrategy) as AppTitleStrategy;
  });

  it('titles a route from its data, ending with the brand', async () => {
    await router.navigateByUrl('/matrix');
    expect(title.getTitle()).toBe('Matrix · ATT&CK-Navi');
    await router.navigateByUrl('/technique/enterprise/T1037');
    expect(title.getTitle()).toBe('Technique · ATT&CK-Navi');
  });

  it('a detail title holds for its path across query-only navigations, and a different path drops it', async () => {
    await router.navigateByUrl('/technique/enterprise/T1037');
    strategy.setDetailTitle(router.url, 'T1037 Boot or Logon Initialization Scripts');
    expect(title.getTitle()).toBe('T1037 Boot or Logon Initialization Scripts · ATT&CK-Navi');
    // The URL writer adds tech= and heat=: the same page, the same title.
    await router.navigateByUrl('/technique/enterprise/T1037?heat=coverage&tech=T1037');
    expect(title.getTitle()).toBe('T1037 Boot or Logon Initialization Scripts · ATT&CK-Navi');
    await router.navigateByUrl('/technique/enterprise/T1059.001');
    expect(title.getTitle()).toBe('Technique · ATT&CK-Navi');
    await router.navigateByUrl('/matrix');
    expect(title.getTitle()).toBe('Matrix · ATT&CK-Navi');
  });

  it('titlePath drops the query string and the fragment', () => {
    expect(titlePath('/technique/enterprise/T1037?heat=coverage#x')).toBe('/technique/enterprise/T1037');
    expect(titlePath('/matrix')).toBe('/matrix');
  });
});
