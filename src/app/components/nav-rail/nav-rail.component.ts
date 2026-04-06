import {
  Component,
  Input,
  Output,
  EventEmitter,
  ChangeDetectionStrategy,
  inject,
  OnInit,
  OnDestroy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { CveService } from '../../services/cve.service';
import { DataService } from '../../services/data.service';

type NavItem =
  | { id: string; icon: string; label: string; group?: string }
  | { type: 'divider'; label: string };

const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', icon: '📊', label: 'Dashboard' },
  { id: 'search', icon: '🔎', label: 'Search' },

  { type: 'divider', label: 'Threats' },
  { id: 'threats', icon: '👥', label: 'Threats' },
  { id: 'actor', icon: '🕵️', label: 'Actors' },
  { id: 'actor-compare', icon: '⚖️', label: 'Actor vs.' },
  { id: 'scenario', icon: '🎭', label: 'Scenario' },
  { id: 'campaign-timeline', icon: '🗓️', label: 'Campaigns' },
  { id: 'software', icon: '🛠️', label: 'Software' },
  { id: 'intelligence', icon: '🧠', label: 'INTEL' },

  { type: 'divider', label: 'Analysis' },
  { id: 'killchain', icon: '⛓️', label: 'Kill Chain' },
  { id: 'risk-matrix', icon: '📉', label: 'Risk' },
  { id: 'analytics', icon: '📈', label: 'Analytics' },
  { id: 'detection', icon: '🔬', label: 'Detect' },
  { id: 'technique-graph', icon: '🕸️', label: 'Graph' },
  { id: 'datasources', icon: '📡', label: 'Sources' },
  { id: 'cve', icon: '🔍', label: 'CVE' },
  { id: 'gap-analysis', icon: '🔎', label: 'GAP RPT' },

  { type: 'divider', label: 'Coverage' },
  { id: 'assessment', icon: '🧭', label: 'ASSESS' },
  { id: 'controls', icon: '🔒', label: 'Controls' },
  { id: 'compliance', icon: '🛡️', label: 'Comply' },
  { id: 'priority', icon: '⬆️', label: 'Priority' },
  { id: 'whatif', icon: '🔮', label: 'What-If' },
  { id: 'timeline', icon: '📅', label: 'Timeline' },
  { id: 'coverage-diff', icon: 'Δ', label: 'Diff' },
  { id: 'target', icon: '🎯', label: 'Target' },
  { id: 'assets', icon: '💻', label: 'ASSETS' },
  { id: 'watchlist', icon: '🔖', label: 'Watchlist' },

  { type: 'divider', label: 'Tools' },
  { id: 'sigma', icon: 'Σ', label: 'SIGMA' },
  { id: 'siem', icon: '⚡', label: 'SIEM' },
  { id: 'yara', icon: '📝', label: 'YARA' },
  { id: 'purple', icon: '🟣', label: 'Purple' },
  { id: 'layers', icon: '📚', label: 'Layers' },
  { id: 'comparison', icon: '⚔️', label: 'Compare' },
  { id: 'custom-mit', icon: '🏢', label: 'Custom' },
  { id: 'tags', icon: '🏷️', label: 'Tags' },
  { id: 'roadmap', icon: '🗺️', label: 'Roadmap' },
  { id: 'changelog', icon: '📋', label: 'Changelog' },
  { id: 'collection', icon: '📦', label: 'COLLECT' },
  { id: 'ir-playbook', icon: '🚨', label: 'IR PLAY' },
  { id: 'report', icon: '📄', label: 'Report' },
];

const NAV_ITEMS_BOTTOM: NavItem[] = [
  { id: 'settings', icon: '⚙️', label: 'Settings' },
];

@Component({
  selector: 'app-nav-rail',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <nav class="nav-rail-inner" role="navigation" aria-label="Main navigation">
      <div class="nav-list">
        @for (item of navItems; track $index) {
          @if (isDivider(item)) {
            <div class="nav-divider">
              <span class="nav-divider-label">{{ item.label }}</span>
            </div>
          } @else {
            <button
              class="nav-item"
              [class.active]="activePanel === item.id"
              [title]="item.label"
              [attr.aria-current]="activePanel === item.id ? 'page' : null"
              [attr.aria-label]="item.label"
              (click)="onNavClick(item.id)"
            >
              <span class="nav-icon" aria-hidden="true">{{ item.icon }}</span>
              <span class="nav-label">{{ item.label }}</span>
              @if (item.id === 'cve' && newKevCount > 0) {
                <span class="nav-badge" [attr.aria-label]="newKevCount + ' new KEV entries'">+{{ newKevCount }}</span>
              }
              @if (item.id === 'changelog' && newVersionAvailable) {
                <span class="nav-badge version-badge" aria-label="New ATT&CK version available"></span>
              }
            </button>
          }
        }
      </div>
      <div class="nav-items-bottom">
        <div class="nav-divider bottom-divider">
          <span class="nav-divider-label"></span>
        </div>
        @for (item of navItemsBottom; track $index) {
          @if (!isDivider(item)) {
            <button
              class="nav-item"
              [class.active]="activePanel === item.id"
              [title]="item.label"
              [attr.aria-current]="activePanel === item.id ? 'page' : null"
              [attr.aria-label]="item.label"
              (click)="panelToggle.emit(item.id)"
            >
              <span class="nav-icon" aria-hidden="true">{{ item.icon }}</span>
              <span class="nav-label">{{ item.label }}</span>
            </button>
          }
        }
        <button
          class="nav-item help-btn"
          title="Focus search"
          aria-label="Focus search"
          (click)="focusSearch.emit()"
        >
          <span class="nav-icon" aria-hidden="true">⌨️</span>
          <span class="nav-label">Search</span>
        </button>
      </div>
    </nav>
  `,
  styles: [`
    :host {
      display: flex;
      flex-direction: column;
      width: 78px;
      flex-shrink: 0;
      background:
        linear-gradient(180deg, rgba(255, 255, 255, 0.02), transparent),
        rgba(5, 13, 20, 0.82);
      border-right: 1px solid rgba(151, 185, 211, 0.12);
      overflow: hidden;
      backdrop-filter: blur(18px);
    }

    .nav-rail-inner {
      display: flex;
      flex-direction: column;
      height: 100%;
      padding: 8px 0 8px;
      align-items: center;
    }

    .nav-list {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 2px;
      flex: 1;
      overflow-y: auto;
      overflow-x: hidden;
      width: 100%;
      scrollbar-width: thin;
      scrollbar-color: rgba(88, 166, 255, 0.25) transparent;
      /* Fade hint at bottom so users know there's more to scroll */
      -webkit-mask-image: linear-gradient(to bottom, black calc(100% - 24px), transparent 100%);
      mask-image: linear-gradient(to bottom, black calc(100% - 24px), transparent 100%);
    }

    .nav-items-bottom {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 2px;
      padding-bottom: 4px;
      flex-shrink: 0;
      width: 100%;
    }

    .nav-divider {
      padding: 10px 0 4px;
      margin-top: 6px;
      width: 100%;
    }

    .nav-divider::before {
      content: '';
      display: block;
      height: 1px;
      background: rgba(255,255,255,0.08);
      margin: 0 12px 8px;
    }

    .nav-divider-label {
      display: block;
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.14em;
      color: rgba(255,255,255,0.28);
      text-align: center;
      text-transform: uppercase;
      padding: 0 4px;
    }

    .bottom-divider {
      margin-top: 2px;
      padding-top: 4px;
    }

    .nav-item {
      position: relative;
      width: 64px;
      min-height: 50px;
      border-radius: 14px;
      background: transparent;
      border: 1px solid transparent;
      cursor: pointer;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 3px;
      color: #6e8599;
      transition: all 0.15s;
      padding: 0;
      flex-shrink: 0;
      margin: 0 auto;
    }

    .nav-badge {
      position: absolute;
      top: 2px;
      right: 4px;
      min-width: 18px;
      height: 18px;
      border-radius: 9px;
      background: #e53935;
      color: #fff;
      font-size: 9px;
      font-weight: 700;
      line-height: 18px;
      text-align: center;
      padding: 0 4px;
      box-shadow: 0 1px 4px rgba(0, 0, 0, 0.4);
      pointer-events: none;
      animation: badge-pop 0.25s ease-out;
    }

    .version-badge {
      min-width: 10px !important;
      width: 10px !important;
      height: 10px !important;
      padding: 0 !important;
      border-radius: 50% !important;
      background: #2196F3 !important;
      box-shadow: 0 0 6px rgba(33, 150, 243, 0.6);
    }

    @keyframes badge-pop {
      0% { transform: scale(0); }
      70% { transform: scale(1.15); }
      100% { transform: scale(1); }
    }

    .nav-icon {
      font-size: 15px;
      line-height: 1;
    }

    .nav-label {
      font-size: 8px;
      color: inherit;
      font-weight: 600;
      letter-spacing: 0.06em;
      white-space: normal;
      text-transform: uppercase;
      line-height: 1;
      text-align: center;
      max-width: 60px;
    }

    .nav-item:hover {
      background: rgba(255,255,255,0.06);
      border-color: rgba(255,255,255,0.08);
      color: #c2d8ea;
      transform: translateY(-1px);
    }

    .nav-item.active {
      background: linear-gradient(180deg, rgba(111, 211, 255, 0.14), rgba(111, 211, 255, 0.08));
      color: #6fd3ff;
      border-color: rgba(111, 211, 255, 0.24);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.04), 0 0 0 1px rgba(111,211,255,0.06);
    }

    .help-btn {
      color: #597085;
    }

    .help-btn:hover {
      color: #c2d8ea;
    }

    /* ── Light mode ── */
    :host-context(body.light-mode) {
      background: #f1f5f9 !important;
      border-right-color: #e2e8f0 !important;
      backdrop-filter: none !important;
    }

    :host-context(body.light-mode) .nav-divider::before {
      background: rgba(0, 0, 0, 0.08);
    }

    :host-context(body.light-mode) .nav-divider-label {
      color: #94a3b8;
    }

    :host-context(body.light-mode) .nav-item {
      color: #64748b;
    }

    :host-context(body.light-mode) .nav-item:hover {
      background: rgba(0, 0, 0, 0.04);
      border-color: rgba(0, 0, 0, 0.06);
      color: #1a1a2e;
    }

    :host-context(body.light-mode) .nav-item.active {
      background: rgba(37, 99, 235, 0.08);
      color: #2563eb;
      border-color: rgba(37, 99, 235, 0.2);
      box-shadow: inset 0 1px 0 rgba(37, 99, 235, 0.04), 0 0 0 1px rgba(37, 99, 235, 0.06);
    }

    :host-context(body.light-mode) .help-btn {
      color: #94a3b8;
    }

    :host-context(body.light-mode) .help-btn:hover {
      color: #1a1a2e;
    }

    :host-context(body.light-mode) .nav-list {
      scrollbar-color: #cbd5e1 transparent;
    }

    /* Mobile: collapse to horizontal bottom bar */
    @media (max-width: 768px) {
      :host {
        position: fixed;
        bottom: 0;
        left: 0;
        right: 0;
        width: 100%;
        height: 56px;
        z-index: 200;
        flex-direction: row;
        border-right: none;
        border-top: 1px solid rgba(151, 185, 211, 0.12);
      }

      .nav-rail-inner {
        flex-direction: row;
        padding: 0;
        height: 100%;
        width: 100%;
      }

      .nav-list {
        flex-direction: row;
        overflow-x: auto;
        overflow-y: hidden;
        gap: 0;
        padding: 0 4px;
        flex: 1;
        -webkit-mask-image: none;
        mask-image: none;
        scrollbar-width: none;
      }

      .nav-list::-webkit-scrollbar {
        display: none;
      }

      .nav-item {
        width: 48px;
        min-width: 48px;
        min-height: 48px;
        font-size: 13px;
        margin: 0;
        border-radius: 10px;
      }

      .nav-label {
        font-size: 7px;
      }

      .nav-divider {
        display: none;
      }

      .nav-divider-label {
        display: none;
      }

      .nav-items-bottom {
        display: none;
      }
    }
  `],
})
export class NavRailComponent implements OnInit, OnDestroy {
  @Input() activePanel: string | null = null;
  @Output() panelToggle = new EventEmitter<string>();
  @Output() focusSearch = new EventEmitter<void>();

  readonly navItems = NAV_ITEMS;
  readonly navItemsBottom = NAV_ITEMS_BOTTOM;

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

  onNavClick(id: string): void {
    if (id === 'cve') {
      this.cveService.dismissKevBadge();
    }
    if (id === 'changelog') {
      const domain = this.dataService.getCurrentDomain();
      if (domain) {
        localStorage.setItem('last-seen-attack-version', domain.attackVersion);
      }
      this.newVersionAvailable = false;
    }
    this.panelToggle.emit(id);
  }

  isDivider(item: NavItem): item is { type: 'divider'; label: string } {
    return 'type' in item && item.type === 'divider';
  }
}
