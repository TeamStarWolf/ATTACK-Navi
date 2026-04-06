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
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { Mitigation } from '../../models/mitigation';

interface Chip {
  label: string;
  clear: () => void;
}

@Component({
  selector: 'app-filter-chips',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (chips.length > 0) {
      <div class="chips-bar">
        <span class="chips-label">Active filters:</span>
        @for (chip of chips; track chip.label) {
          <div class="chip">
            <span class="chip-text">{{ chip.label }}</span>
            <button class="chip-remove" (click)="chip.clear()" title="Remove filter">✕</button>
          </div>
        }
        <button class="clear-all-btn" (click)="filterService.clearAll()">Clear all</button>
      </div>
    }
  `,
  styleUrl: './filter-chips.component.scss',
})
export class FilterChipsComponent implements OnInit, OnDestroy {
  chips: Chip[] = [];
  private subs = new Subscription();

  constructor(
    public filterService: FilterService,
    private dataService: DataService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      combineLatest([
        this.filterService.activeMitigationFilters$,
        this.filterService.techniqueQuery$,
        this.filterService.platformFilter$,
        this.filterService.dimUncovered$,
        this.filterService.hiddenTacticIds$,
        this.filterService.activeThreatGroupIds$,
        this.filterService.activeSoftwareIds$,
        this.filterService.activeCampaignIds$,
        this.filterService.activeDataSource$,
        this.dataService.domain$,
      ]).subscribe(([mitigations, query, platform, dimUncovered, hiddenIds, threatGroupIds, softwareIds, campaignIds, dataSource, domain]) => {
        this.chips = [];

        for (const m of mitigations) {
          const captured: Mitigation = m;
          this.chips.push({
            label: `Mitigation: ${m.attackId} – ${m.name}`,
            clear: () => this.filterService.removeMitigationFilter(captured),
          });
        }

        if (query.trim()) {
          this.chips.push({
            label: `Technique: "${query.trim()}"`,
            clear: () => this.filterService.setTechniqueQuery(''),
          });
        }

        if (platform) {
          this.chips.push({
            label: `Platform: ${platform}`,
            clear: () => this.filterService.setPlatformFilter(null),
          });
        }

        if (dataSource) {
          this.chips.push({
            label: `Detection: ${dataSource}`,
            clear: () => this.filterService.setDataSourceFilter(null),
          });
        }

        if (dimUncovered) {
          this.chips.push({
            label: 'Dimming uncovered',
            clear: () => this.filterService.toggleDimUncovered(),
          });
        }

        for (const tacticId of hiddenIds) {
          const capturedId = tacticId;
          const tactic = domain?.tacticColumns.find((c) => c.tactic.id === tacticId)?.tactic;
          if (tactic) {
            this.chips.push({
              label: `Hidden: ${tactic.name}`,
              clear: () => this.filterService.toggleTacticVisibility(capturedId),
            });
          }
        }

        for (const groupId of threatGroupIds) {
          const capturedId = groupId;
          const group = domain?.groups.find((g) => g.id === groupId);
          if (group) {
            this.chips.push({
              label: `Threat: ${group.attackId} ${group.name}`,
              clear: () => this.filterService.toggleThreatGroup(capturedId),
            });
          }
        }

        for (const swId of softwareIds) {
          const capturedId = swId;
          const sw = domain?.software.find((s) => s.id === swId);
          if (sw) {
            this.chips.push({
              label: `Software: ${sw.attackId} ${sw.name}`,
              clear: () => this.filterService.toggleSoftware(capturedId),
            });
          }
        }

        for (const campId of campaignIds) {
          const capturedId = campId;
          const campaign = domain?.campaigns.find((c) => c.id === campId);
          if (campaign) {
            this.chips.push({
              label: `Campaign: ${campaign.attackId} ${campaign.name}`,
              clear: () => this.filterService.toggleCampaign(capturedId),
            });
          }
        }

        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }
}
