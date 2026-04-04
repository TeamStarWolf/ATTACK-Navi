import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { YaraService, YaraRule } from '../../services/yara.service';
import { Technique } from '../../models/technique';
import { Domain } from '../../models/domain';

@Component({
  selector: 'app-yara-export',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './yara-export.component.html',
  styleUrl: './yara-export.component.scss',
})
export class YaraExportComponent implements OnInit, OnDestroy {
  open = false;
  domain: Domain | null = null;
  selectedMode: 'current' | 'implemented' | 'all' = 'all';
  previewRules: YaraRule[] = [];
  totalCount = 0;
  coveredCount = 0;
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private implService: ImplementationService,
    private yaraService: YaraService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(this.filterService.activePanel$.subscribe(panel => {
      this.open = (panel as string) === 'yara';
      if (this.open) this.generatePreview();
      this.cdr.markForCheck();
    }));
    this.subs.add(this.dataService.domain$.subscribe(domain => {
      this.domain = domain;
      if (this.open) this.generatePreview();
      this.cdr.markForCheck();
    }));
  }

  close(): void { this.filterService.setActivePanel(null); }
  setMode(mode: 'current' | 'implemented' | 'all'): void { this.selectedMode = mode; this.generatePreview(); }

  private getTechniques(): Technique[] {
    if (!this.domain) return [];
    switch (this.selectedMode) {
      case 'implemented': {
        const implMap = this.implService.getStatusMap();
        const implMitIds = new Set([...implMap.entries()].filter(([,v]) => v === 'implemented').map(([k]) => k));
        if (!implMitIds.size) return [];
        const techSet = new Set<string>();
        for (const mitId of implMitIds) {
          const techs = this.domain.techniquesByMitigation.get(mitId) ?? [];
          for (const t of techs) techSet.add(t.id);
        }
        return this.domain.techniques.filter(t => techSet.has(t.id));
      }
      case 'current': {
        // Use active mitigation filters to determine current view (same pattern as sigma-export)
        const activeMits = (this.filterService as any)['activeMitigationFiltersSubject']?.value ?? [];
        if (activeMits.length > 0) {
          const techSet = new Set<string>();
          for (const m of activeMits) {
            const techs = this.domain.techniquesByMitigation.get(m.id) ?? [];
            for (const t of techs) techSet.add(t.id);
          }
          const filtered = this.domain.techniques.filter(t => techSet.has(t.id));
          return filtered.length > 0 ? filtered : this.domain.techniques;
        }
        return this.domain.techniques;
      }
      default: return this.domain.techniques;
    }
  }

  generatePreview(): void {
    const techs = this.getTechniques();
    const allRules = this.yaraService.generateRules(techs);
    this.totalCount = techs.length;
    this.coveredCount = allRules.length;
    this.previewRules = allRules.slice(0, 2);
    this.cdr.markForCheck();
  }

  export(): void {
    const techs = this.getTechniques();
    const rules = this.yaraService.generateRules(techs);
    this.yaraService.exportRules(rules);
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }
}
