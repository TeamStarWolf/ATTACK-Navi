// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';

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
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './sigma-export.component.html',
  styleUrl: './sigma-export.component.scss',
})
export class SigmaExportComponent implements OnInit, OnDestroy {
  domain: Domain | null = null;
  selectedMode: SigmaExportMode = 'current';
  previewYaml = '';
  techniqueCount = 0;
  /** Selected techniques the generator has a template for (plan E1.6). */
  templateCount = 0;
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
      this.dataService.domain$.subscribe(domain => {
        this.domain = domain;
        this.generatePreview();
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
    const withTemplate = techs.length ? techs.filter(t => this.sigmaService.hasTemplate(t)) : [];
    this.templateCount = withTemplate.length;
    if (techs.length === 0) {
      this.previewYaml = '# No techniques found for the selected mode.';
    } else if (withTemplate.length === 0) {
      this.previewYaml = '# None of the selected techniques has a Sigma template.';
    } else {
      // Preview the first three templates, not the first three techniques:
      // most techniques have no template and would preview as nothing.
      this.previewYaml = this.sigmaService.generateRulesForTechniques(withTemplate.slice(0, 3));
    }
    this.cdr.markForCheck();
  }

  exportAll(): void {
    const techs = this.getTechniquesForMode();
    if (techs.length === 0 || this.templateCount === 0) return;
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

  get countLabel(): string {
    return this.templateCount === 1 ? '1 template' : `${this.templateCount} templates`;
  }
}
