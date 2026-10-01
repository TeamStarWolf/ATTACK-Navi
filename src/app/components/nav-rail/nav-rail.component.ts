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

interface NavSection {
  key: string;
  label: string;
  items: WorkspaceNavItem[];
}

/** All workspaces, keyed by route (the reconciliation catalog). */
const CATALOG: Record<string, WorkspaceNavItem> = {
  '/matrix':    { route: '/matrix',    icon: 'grid',             label: 'Matrix' },
  '/exposure':  { route: '/exposure',  icon: 'shield-alert',     label: 'Exposure' },
  '/intel':     { route: '/intel',     icon: 'users',            label: 'Intel' },
  '/detect':    { route: '/detect',    icon: 'radar',            label: 'Detect' },
  '/coverage':  { route: '/coverage',  icon: 'shield-check',     label: 'Coverage' },
  '/dashboard': { route: '/dashboard', icon: 'layout-dashboard', label: 'Dashboard' },
  '/reports':   { route: '/reports',   icon: 'file-text',        label: 'Reports' },
  '/library':   { route: '/library',   icon: 'layers',           label: 'Library' },
  '/status':    { route: '/status',    icon: 'monitor',          label: 'Status' },
};

/**
 * Workspaces organized from a Vulnerability-Intelligence / IR / Threat
 * perspective. Section membership is fixed (the VI/IR/Threat structure); order
 * WITHIN a section is user-customizable by dragging, persisted per browser
 * (NAVRAIL_ORDER_KEY). "Reset order" restores these defaults.
 */
const SECTION_DEFS: { key: string; label: string; routes: string[] }[] = [
  { key: 'threat',    label: 'Threat & Exposure', routes: ['/matrix', '/exposure', '/intel'] },
  { key: 'respond',   label: 'Response',          routes: ['/detect', '/coverage'] },
  { key: 'reference', label: 'Reference',         routes: ['/dashboard', '/reports', '/library', '/status'] },
];

const NAVRAIL_ORDER_KEY = 'navrail-sections-v1';

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

  /** The live (possibly user-reordered) sections. */
  sections: NavSection[] = this.loadSections();

  /** Drag state: which section + item is being dragged, and the hover target. */
  dragSection: number | null = null;
  dragIndex: number | null = null;
  overKey: string | null = null; // `${sectionIndex}:${itemIndex}`

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
    this.newVersionAvailable = false;
  }

  // --- reorder (native HTML5 drag; click still navigates; within-section only) ---

  get isCustomOrder(): boolean {
    return this.sections.some((sec, i) => {
      const def = SECTION_DEFS[i];
      return !def || sec.items.length !== def.routes.length ||
        sec.items.some((it, j) => it.route !== def.routes[j]);
    });
  }

  isDragging(si: number, ii: number): boolean {
    return this.dragSection === si && this.dragIndex === ii;
  }

  onDragStart(si: number, ii: number, event: DragEvent): void {
    this.dragSection = si;
    this.dragIndex = ii;
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('text/plain', this.sections[si].items[ii].route);
    }
  }

  onDragOver(si: number, ii: number, event: DragEvent): void {
    if (si !== this.dragSection) return; // reorder only within the same section
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = 'move';
    const key = si + ':' + ii;
    if (this.overKey !== key) {
      this.overKey = key;
      this.cdr.markForCheck();
    }
  }

  onDrop(si: number, ii: number, event: DragEvent): void {
    if (si !== this.dragSection || this.dragIndex === null || this.dragIndex === ii) {
      this.clearDrag();
      return;
    }
    event.preventDefault();
    const items = this.sections[si].items.slice();
    const [moved] = items.splice(this.dragIndex, 1);
    items.splice(ii, 0, moved);
    this.sections[si] = { ...this.sections[si], items };
    this.sections = this.sections.slice();
    this.saveOrder();
    this.clearDrag();
  }

  onDragEnd(): void {
    this.clearDrag();
  }

  resetOrder(): void {
    this.sections = SECTION_DEFS.map(def => ({
      key: def.key,
      label: def.label,
      items: def.routes.map(r => CATALOG[r]).filter(Boolean),
    }));
    try {
      localStorage.removeItem(NAVRAIL_ORDER_KEY);
    } catch {
      /* storage unavailable — in-memory reset still applies */
    }
    this.clearDrag();
  }

  private clearDrag(): void {
    this.dragSection = null;
    this.dragIndex = null;
    this.overKey = null;
    this.cdr.markForCheck();
  }

  /** Persist each section's route order. */
  private saveOrder(): void {
    try {
      const payload: Record<string, string[]> = {};
      for (const sec of this.sections) payload[sec.key] = sec.items.map(i => i.route);
      localStorage.setItem(NAVRAIL_ORDER_KEY, JSON.stringify(payload));
    } catch {
      /* storage unavailable (private mode / blocked) — order stays in-memory */
    }
  }

  /**
   * Build the sections from the fixed defs, applying any saved per-section order.
   * A saved route is honored only if it still belongs to that section (membership
   * is fixed); routes the save predates are appended; unknown routes dropped.
   */
  private loadSections(): NavSection[] {
    let saved: Record<string, string[]> = {};
    try {
      saved = JSON.parse(localStorage.getItem(NAVRAIL_ORDER_KEY) ?? '{}') || {};
    } catch {
      saved = {};
    }
    return SECTION_DEFS.map(def => {
      const allowed = new Set(def.routes);
      const savedOrder: string[] = Array.isArray(saved[def.key]) ? saved[def.key] : [];
      const ordered: string[] = [];
      const seen = new Set<string>();
      for (const r of savedOrder) {
        if (allowed.has(r) && !seen.has(r)) { ordered.push(r); seen.add(r); }
      }
      for (const r of def.routes) if (!seen.has(r)) ordered.push(r);
      return {
        key: def.key,
        label: def.label,
        items: ordered.map(r => CATALOG[r]).filter(Boolean),
      };
    });
  }
}
