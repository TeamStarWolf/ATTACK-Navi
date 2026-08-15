// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, Route, provideRouter } from '@angular/router';
import { WorkspaceShellComponent } from './workspace-shell.component';

@Component({ standalone: true, template: '' })
class StubTabComponent {}

function makeRouteConfig(): Route {
  return {
    path: 'detect',
    component: WorkspaceShellComponent,
    data: { title: 'Detection', icon: 'radar' },
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'detections' },
      { path: 'detections', component: StubTabComponent, data: { tab: 'Detections', icon: 'microscope' } },
      { path: 'sigma', component: StubTabComponent, data: { tab: 'Sigma', icon: 'sigma' } },
      { path: 'hidden-util', component: StubTabComponent }, // no data.tab → not a tab
    ],
  };
}

describe('WorkspaceShellComponent', () => {
  async function setup(routeConfig: Route = makeRouteConfig()) {
    await TestBed.configureTestingModule({
      imports: [WorkspaceShellComponent],
      providers: [
        provideRouter([routeConfig]),
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { data: routeConfig.data ?? {} },
            routeConfig,
          },
        },
      ],
    }).compileComponents();
    const fixture = TestBed.createComponent(WorkspaceShellComponent);
    fixture.detectChanges();
    return fixture;
  }

  it('renders the workspace title from route data', async () => {
    const fixture = await setup();
    const title = fixture.nativeElement.querySelector('.workspace-title');
    expect(title.textContent).toContain('Detection');
  });

  it('builds tabs only from children that declare data.tab', async () => {
    const fixture = await setup();
    const tabs = fixture.nativeElement.querySelectorAll('.ws-tab');
    expect(tabs.length).toBe(2);
    expect(tabs[0].textContent).toContain('Detections');
    expect(tabs[1].textContent).toContain('Sigma');
  });

  it('hides the tab bar for single-tab workspaces', async () => {
    const config = makeRouteConfig();
    config.children = [
      { path: 'only', component: StubTabComponent, data: { tab: 'Only' } },
    ];
    const fixture = await setup(config);
    expect(fixture.nativeElement.querySelector('.workspace-tabs')).toBeNull();
  });

  it('contains a router outlet for the active tab', async () => {
    const fixture = await setup();
    expect(fixture.nativeElement.querySelector('router-outlet')).toBeTruthy();
  });
});
