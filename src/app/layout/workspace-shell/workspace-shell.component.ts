// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, Component, OnInit, inject } from '@angular/core';
import { ActivatedRoute, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { IconComponent } from '../../shared/icons/icon.component';
import { IconName } from '../../shared/icons/icon-registry';

interface WorkspaceTab {
  path: string;
  label: string;
  icon?: IconName;
}

/**
 * Parent layout for a routed workspace. Renders the workspace header and a
 * tab bar derived from the route config's children (entries with data.tab),
 * with the active tab tracked by the router. Query params are preserved
 * across tab switches so matrix filters survive navigation.
 */
@Component({
  selector: 'app-workspace-shell',
  standalone: true,
  imports: [RouterOutlet, RouterLink, RouterLinkActive, IconComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './workspace-shell.component.html',
  styleUrl: './workspace-shell.component.scss',
})
export class WorkspaceShellComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);

  title = '';
  icon: IconName = 'grid';
  tabs: WorkspaceTab[] = [];

  ngOnInit(): void {
    const data = this.route.snapshot.data;
    this.title = (data['title'] as string) ?? '';
    this.icon = (data['icon'] as IconName) ?? 'grid';
    this.tabs = (this.route.routeConfig?.children ?? [])
      .filter((child) => child.path && child.data?.['tab'])
      .map((child) => ({
        path: child.path as string,
        label: child.data!['tab'] as string,
        icon: child.data!['icon'] as IconName | undefined,
      }));
  }
}
