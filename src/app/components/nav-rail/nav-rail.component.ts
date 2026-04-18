// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
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
  templateUrl: './nav-rail.component.html',
  styleUrl: './nav-rail.component.scss',
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
