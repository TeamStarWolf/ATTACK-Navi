// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  Output,
  EventEmitter,
  ChangeDetectionStrategy,
  inject,
  OnInit,
  OnDestroy,
  ChangeDetectorRef,
} from '@angular/core';

import { RouterLink, RouterLinkActive } from '@angular/router';
import { Subscription } from 'rxjs';
import { CveService } from '../../services/cve.service';
import { DataService } from '../../services/data.service';
import { IconComponent } from '../../shared/icons/icon.component';

interface WorkspaceNavItem {
  /** Workspace root path — routerLinkActive matches any child tab. */
  route: string;
  icon: string;
  label: string;
}

/**
 * One item per workspace (the tabs inside each workspace carry the detail
 * destinations). Order mirrors the daily workflow: observe → investigate →
 * detect → measure → improve.
 */
const WORKSPACES: WorkspaceNavItem[] = [
  { route: '/matrix', icon: 'grid', label: 'Matrix' },
  { route: '/dashboard', icon: 'layout-dashboard', label: 'Dashboard' },
  { route: '/intel', icon: 'users', label: 'Intel' },
  { route: '/detect', icon: 'radar', label: 'Detect' },
  { route: '/exposure', icon: 'shield-alert', label: 'Exposure' },
  { route: '/coverage', icon: 'shield-check', label: 'Coverage' },
  { route: '/library', icon: 'layers', label: 'Library' },
  { route: '/reports', icon: 'file-text', label: 'Reports' },
];

@Component({
  selector: 'app-nav-rail',
  standalone: true,
  imports: [RouterLink, RouterLinkActive, IconComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './nav-rail.component.html',
  styleUrl: './nav-rail.component.scss',
})
export class NavRailComponent implements OnInit, OnDestroy {
  /** Opens the keyboard-help overlay (hosted by AppComponent). */
  @Output() helpClick = new EventEmitter<void>();

  readonly workspaces = WORKSPACES;

  newKevCount = 0;
  newVersionAvailable = false;

  private cveService = inject(CveService);
  private dataService = inject(DataService);
  private cdr = inject(ChangeDetectorRef);
  private kevSub?: Subscription;
  private domainSub?: Subscription;

  ngOnInit(): void {
    this.kevSub = this.cveService.newKevCount$.subscribe(count => {
      this.newKevCount = count;
      this.cdr.markForCheck();
    });
    this.domainSub = this.dataService.domain$.subscribe(domain => {
      if (domain) {
        const lastSeen = localStorage.getItem('last-seen-attack-version');
        this.newVersionAvailable = lastSeen !== domain.attackVersion;
      }
      this.cdr.markForCheck();
    });
  }

  ngOnDestroy(): void {
    this.kevSub?.unsubscribe();
    this.domainSub?.unsubscribe();
  }

  onSettingsClick(): void {
    // Clear the version dot immediately; the persistent stamp happens in
    // ChangelogPanelComponent.ngOnInit when the changelog tab is visited.
    this.newVersionAvailable = false;
  }
}
