// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription, combineLatest } from 'rxjs';
import { FilterService, HeatmapMode } from '../../services/filter.service';
import { ImplementationService } from '../../services/implementation.service';
import { DataService } from '../../services/data.service';
import { AttackCveService } from '../../services/attack-cve.service';

interface FilterPreset {
  id: string;
  label: string;
  icon: string;
  description: string;
  heatmapMode: HeatmapMode;
}

@Component({
  selector: 'app-quick-filters',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './quick-filters.component.html',
  styleUrl: './quick-filters.component.scss',
})
export class QuickFiltersComponent implements OnInit, OnDestroy {
  private readonly STORAGE_KEY = 'mitre-nav-quick-filters-expanded';

  expanded = false;
  activePreset: string | null = null;

  readonly presets: FilterPreset[] = [
    {
      id: 'no-mitigation',
      label: 'No Mitigation',
      icon: '🚨',
      description: 'Highlight techniques with zero mitigations mapped',
      heatmapMode: 'coverage',
    },
    {
      id: 'kev-exposed',
      label: 'KEV Exposed',
      icon: '🔥',
      description: 'Show techniques with CVE exposures from CISA KEV',
      heatmapMode: 'kev',
    },
    {
      id: 'not-implemented',
      label: 'Not Implemented',
      icon: '❌',
      description: 'Show techniques whose mitigations are not started',
      heatmapMode: 'status',
    },
    {
      id: 'apt-focus',
      label: 'APT Focus',
      icon: '👥',
      description: 'Highlight techniques used by the most threat actors',
      heatmapMode: 'exposure',
    },
    {
      id: 'no-detection',
      label: 'No Detection',
      icon: '🔍',
      description: 'Show techniques with no CAR/Atomic/D3FEND detection coverage',
      heatmapMode: 'detection',
    },
    {
      id: 'cve-exposure',
      label: 'CVE Exposure',
      icon: '💀',
      description: 'Highlight techniques with known CVE exploitation paths',
      heatmapMode: 'cve',
    },
  ];

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private implService: ImplementationService,
    private dataService: DataService,
    private attackCveService: AttackCveService,
    private cdr: ChangeDetectorRef,
  ) {
    this.expanded = localStorage.getItem(this.STORAGE_KEY) === 'true';
  }

  ngOnInit(): void {
    // Track heatmap mode changes to sync active preset indicator
    this.subs.add(
      this.filterService.heatmapMode$.subscribe(mode => {
        // If heatmap mode no longer matches the active preset, clear it
        if (this.activePreset) {
          const preset = this.presets.find(p => p.id === this.activePreset);
          if (preset && preset.heatmapMode !== mode) {
            this.activePreset = null;
          }
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  toggleExpanded(): void {
    this.expanded = !this.expanded;
    localStorage.setItem(this.STORAGE_KEY, String(this.expanded));
    this.cdr.markForCheck();
  }

  applyPreset(preset: FilterPreset): void {
    if (this.activePreset === preset.id) {
      this.clearPreset();
      return;
    }

    this.activePreset = preset.id;

    // Set the heatmap mode
    this.filterService.setHeatmapMode(preset.heatmapMode);

    // For "not-implemented" preset, also set the implStatusFilter to 'not-started'
    if (preset.id === 'not-implemented') {
      this.filterService.setImplStatusFilter('not-started');
    } else {
      this.filterService.setImplStatusFilter(null);
    }

    // For "no-mitigation" preset, also dim uncovered if not already set
    if (preset.id === 'no-mitigation') {
      // Ensure coverage mode and let the cell color (red) speak for itself
      this.filterService.setHeatmapMode('coverage');
    }

    this.cdr.markForCheck();
  }

  clearPreset(): void {
    this.activePreset = null;
    this.filterService.setHeatmapMode('coverage');
    this.filterService.setImplStatusFilter(null);
    this.cdr.markForCheck();
  }
}
