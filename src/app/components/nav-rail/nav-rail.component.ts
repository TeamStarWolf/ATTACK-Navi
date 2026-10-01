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
 * Canonical workspace catalog in the default order. The default leads with a
 * Vulnerability-Intelligence / IR / Threat workflow: the Matrix canvas, then
 * Exposure (CVE/KEV/risk), Intel (adversaries), Detect (IR), then posture and
 * reporting. Users can reorder the rail by dragging; the order persists per
 * browser (NAVRAIL_ORDER_KEY) and "Reset order" restores this default.
 */
const CATALOG: WorkspaceNavItem[] = [
  { route: '/matrix', icon: 'grid', label: 'Matrix' },
  { route: '/exposure', icon: 'shield-alert', label: 'Exposure' },
  { route: '/intel', icon: 'users', label: 'Intel' },
  { route: '/detect', icon: 'radar', label: 'Detect' },
  { route: '/coverage', icon: 'shield-check', label: 'Coverage' },
  { route: '/dashboard', icon: 'layout-dashboard', label: 'Dashboard' },
  { route: '/reports', icon: 'file-text', label: 'Reports' },
  { route: '/library', icon: 'layers', label: 'Library' },
  { route: '/status', icon: 'monitor', label: 'Status' },
];

const NAVRAIL_ORDER_KEY = 'navrail-order-v1';

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

  /** The live (possibly user-reordered) workspace list. */
  workspaces: WorkspaceNavItem[] = this.loadOrder();

  /** Index being dragged / hovered over, for the reorder affordance. */
  dragIndex: number | null = null;
  overIndex: number | null = null;

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

  // --- reorder (native HTML5 drag; click still navigates) --------------------

  get isCustomOrder(): boolean {
    return this.workspaces.some((w, i) => w.route !== CATALOG[i]?.route);
  }

  onDragStart(index: number, event: DragEvent): void {
    this.dragIndex = index;
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = 'move';
      // Required for Firefox to initiate the drag.
      event.dataTransfer.setData('text/plain', this.workspaces[index].route);
    }
  }

  onDragOver(index: number, event: DragEvent): void {
    event.preventDefault(); // allow drop
    if (event.dataTransfer) event.dataTransfer.dropEffect = 'move';
    if (this.overIndex !== index) {
      this.overIndex = index;
      this.cdr.markForCheck();
    }
  }

  onDrop(index: number, event: DragEvent): void {
    event.preventDefault();
    const from = this.dragIndex;
    if (from === null || from === index) {
      this.clearDrag();
      return;
    }
    const next = this.workspaces.slice();
    const [moved] = next.splice(from, 1);
    next.splice(index, 0, moved);
    this.workspaces = next;
    this.saveOrder();
    this.clearDrag();
  }

  onDragEnd(): void {
    this.clearDrag();
  }

  resetOrder(): void {
    this.workspaces = CATALOG.slice();
    try {
      localStorage.removeItem(NAVRAIL_ORDER_KEY);
    } catch {
      /* storage unavailable — in-memory reset still applies */
    }
    this.clearDrag();
  }

  private clearDrag(): void {
    this.dragIndex = null;
    this.overIndex = null;
    this.cdr.markForCheck();
  }

  /** Persist the current order as a list of routes. */
  private saveOrder(): void {
    try {
      localStorage.setItem(NAVRAIL_ORDER_KEY, JSON.stringify(this.workspaces.map(w => w.route)));
    } catch {
      /* storage unavailable (private mode / blocked) — order stays in-memory */
    }
  }

  /**
   * Load the saved route order and reconcile it with the catalog: keep known
   * routes in the saved order, drop unknown ones, and append any workspaces the
   * saved order predates (so new workspaces always appear). Falls back to the
   * default order on any error or empty/absent storage.
   */
  private loadOrder(): WorkspaceNavItem[] {
    let saved: string[] = [];
    try {
      saved = JSON.parse(localStorage.getItem(NAVRAIL_ORDER_KEY) ?? '[]');
    } catch {
      saved = [];
    }
    if (!Array.isArray(saved) || saved.length === 0) return CATALOG.slice();
    const byRoute = new Map(CATALOG.map(w => [w.route, w]));
    const ordered: WorkspaceNavItem[] = [];
    const seen = new Set<string>();
    for (const route of saved) {
      const item = byRoute.get(route);
      if (item && !seen.has(route)) {
        ordered.push(item);
        seen.add(route);
      }
    }
    for (const item of CATALOG) {
      if (!seen.has(item.route)) ordered.push(item);
    }
    return ordered;
  }
}
