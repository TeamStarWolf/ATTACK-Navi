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
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { AttackSoftware } from '../../models/software';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';

@Component({
  selector: 'app-software-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './software-panel.component.html',
  styleUrl: './software-panel.component.scss',
})
export class SoftwarePanelComponent implements OnInit, OnDestroy {
  software: AttackSoftware[] = [];
  searchText = '';
  typeFilter: 'all' | 'tool' | 'malware' = 'all';
  filteredSoftware: AttackSoftware[] = [];
  activeSoftwareIds = new Set<string>();

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    // Self-sourced from the domain (was an @Input from the app shell pre-router)
    this.subs.add(
      this.dataService.domain$.subscribe((domain) => {
        this.software = domain?.software ?? [];
        this.applyFilter();
      }),
    );
    this.subs.add(
      this.filterService.activeSoftwareIds$.subscribe((ids) => {
        this.activeSoftwareIds = ids;
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  applyFilter(): void {
    const q = this.searchText.toLowerCase().trim();
    this.filteredSoftware = this.software.filter((sw) => {
      if (this.typeFilter !== 'all' && sw.type !== this.typeFilter) return false;
      if (!q) return true;
      return (
        sw.attackId.toLowerCase().includes(q) ||
        sw.name.toLowerCase().includes(q) ||
        sw.aliases.some((a) => a.toLowerCase().includes(q))
      );
    });
    this.cdr.markForCheck();
  }

  toggleSoftware(sw: AttackSoftware): void {
    this.filterService.toggleSoftware(sw.id);
  }

  isActive(sw: AttackSoftware): boolean {
    return this.activeSoftwareIds.has(sw.id);
  }

  clearAll(): void { this.filterService.clearSoftware(); }

  techniqueCount(sw: AttackSoftware): number {
    return this.dataService.getTechniquesForSoftware(sw.id).length;
  }

  get toolCount(): number { return this.software.filter((s) => s.type === 'tool').length; }
  get malwareCount(): number { return this.software.filter((s) => s.type === 'malware').length; }
  get activeCount(): number { return this.activeSoftwareIds.size; }
}
