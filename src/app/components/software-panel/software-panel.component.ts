import {
  Component,
  Input,
  OnInit,
  OnChanges,
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
export class SoftwarePanelComponent implements OnInit, OnChanges, OnDestroy {
  @Input() software: AttackSoftware[] = [];

  open = false;
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
    this.subs.add(
      this.filterService.activePanel$.subscribe((panel) => {
        this.open = panel === 'software';
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.filterService.activeSoftwareIds$.subscribe((ids) => {
        this.activeSoftwareIds = ids;
        this.cdr.markForCheck();
      }),
    );
    this.applyFilter();
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  ngOnChanges(): void { this.applyFilter(); }

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

  close(): void { this.filterService.setActivePanel(null); }

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
