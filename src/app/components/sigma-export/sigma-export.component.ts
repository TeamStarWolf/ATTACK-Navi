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
import { Domain } from '../../models/domain';
import { Technique } from '../../models/technique';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { SigmaService } from '../../services/sigma.service';

export type SigmaExportMode = 'current' | 'implemented' | 'all' | 'custom';

@Component({
  selector: 'app-sigma-export',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './sigma-export.component.html',
  styleUrl: './sigma-export.component.scss',
})
export class SigmaExportComponent implements OnInit, OnDestroy {
  open = false;
  domain: Domain | null = null;
  selectedMode: SigmaExportMode = 'current';
  previewYaml = '';
  techniqueCount = 0;
  customTechIds: string[] = [];

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private implService: ImplementationService,
    private sigmaService: SigmaService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(panel => {
        this.open = panel === 'sigma';
        if (this.open) {
          this.generatePreview();
        }
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.dataService.domain$.subscribe(domain => {
        this.domain = domain;
        if (this.open) {
          this.generatePreview();
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  generatePreview(): void {
    const techs = this.getTechniquesForMode();
    this.techniqueCount = techs.length;
    const previewTechs = techs.slice(0, 3);
    this.previewYaml = previewTechs.length > 0
      ? this.sigmaService.generateRulesForTechniques(previewTechs)
      : '# No techniques found for the selected mode.';
    this.cdr.markForCheck();
  }

  exportAll(): void {
    const techs = this.getTechniquesForMode();
    if (techs.length === 0) return;
    this.sigmaService.exportRules(techs);
  }

  getTechniquesForMode(): Technique[] {
    if (!this.domain) return [];

    switch (this.selectedMode) {
      case 'all':
        return this.domain.techniques;

      case 'implemented': {
        const implementedMitIds = this.implService.getImplementedIds();
        if (!implementedMitIds.size) return [];
        const techSet = new Set<string>();
        for (const mitId of implementedMitIds) {
          const techs = this.domain.techniquesByMitigation.get(mitId) ?? [];
          for (const t of techs) techSet.add(t.id);
        }
        return this.domain.techniques.filter(t => techSet.has(t.id));
      }

      case 'custom':
        return this.domain.techniques.filter(t =>
          this.customTechIds.includes(t.attackId)
        );

      case 'current':
      default: {
        // Use highlighted techniques from active mitigation filters, or fall back to all
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
    }
  }

  onModeChange(): void {
    this.generatePreview();
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  get countLabel(): string {
    return this.techniqueCount === 1 ? '1 technique' : `${this.techniqueCount} techniques`;
  }
}
