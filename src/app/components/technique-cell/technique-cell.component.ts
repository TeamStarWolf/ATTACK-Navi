// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  Input,
  Output,
  EventEmitter,
  OnChanges,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  HostListener,
} from '@angular/core';
import { Subscription } from 'rxjs';
import { CommonModule } from '@angular/common';
import tinycolor from 'tinycolor2';
import { Technique } from '../../models/technique';
import { HeatmapMode } from '../../services/filter.service';
import { ImplStatus } from '../../services/implementation.service';
import { TechniqueAnnotation } from '../../services/annotation.service';
import { SettingsService } from '../../services/settings.service';

@Component({
  selector: 'app-technique-cell',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    'role': 'gridcell',
    '[attr.aria-label]': 'technique.attackId + \': \' + technique.name',
  },
  template: `
    <div
      class="cell"
      tabindex="0"
      [class.sub]="technique.isSubtechnique"
      [class.highlighted]="isHighlighted"
      [class.dimmed]="isDimmed"
      [class.selected]="isSelected"
      [class.focused]="isFocused"
      [class.search-dimmed]="hasActiveSearch && !isSearchMatch"
      [class.search-highlighted]="hasActiveSearch && isSearchMatch"
      [style.background-color]="bgColor"
      [style.color]="textColor"
      (click)="selected.emit(technique)"
      (keydown.enter)="selected.emit(technique)"
      (keydown.space)="$event.preventDefault(); selected.emit(technique)"
    >
      @if (showTechniqueId) {
        <span class="id">{{ technique.attackId }}</span>
      }
      @if (showTechniqueName) {
        <span class="name">{{ technique.name }}</span>
      }
      @if (heatmapMode === 'coverage' && implStatus) {
        <span
          class="impl-dot"
          [style.background]="implDotColor"
          [title]="'Status: ' + implStatus"
        ></span>
      }
      @if (hasNote) {
        <span class="note-dot" title="Has analyst notes">📝</span>
      }
      @if (annotation) {
        <div class="annotation-dot" [class]="'ann-' + annotation.color" [title]="annotation.note"></div>
      }
      @if (isWatched) {
        <div class="watch-indicator" title="On watchlist">🔖</div>
      }
      <div class="badge-row">
        @if (exposureScore > 0) {
          <span class="exposure-badge" [title]="exposureScore + ' threat actor(s) use this technique'">
            👥{{ exposureScore }}
          </span>
        }
        @if (softwareScore > 0) {
          <span class="software-badge" [title]="softwareScore + ' software/malware use this technique'">
            🛠{{ softwareScore }}
          </span>
        }
        @if (campaignScore > 0) {
          <span class="campaign-badge" [title]="campaignScore + ' campaign(s) use this technique'">
            🎯{{ campaignScore }}
          </span>
        }
        @if (heatmapMode === 'd3fend') {
          <span class="d3fend-badge" [title]="d3fendScore + ' D3FEND countermeasure(s)'">
            🛡{{ d3fendScore }}
          </span>
        }
        @if (heatmapMode === 'atomic' && atomicScore > 0) {
          <span class="atomic-badge" [title]="atomicScore + ' Atomic Red Team test(s)'">
            ⚛{{ atomicScore }}
          </span>
        }
        @if (heatmapMode === 'cri' && criScore > 0) {
          <span class="cri-hm-badge" [title]="criScore + ' CRI Profile control(s)'">
            🏦{{ criScore }}
          </span>
        }
        @if (showMitigationCount) {
          <span class="badge" [title]="technique.mitigationCount + ' mitigations'">
            {{ technique.mitigationCount }}
          </span>
        }
      </div>
    </div>

    @if (showTooltip) {
      <div class="tooltip-card" [style.left.px]="tooltipX" [style.top.px]="tooltipY">
        <div class="tt-header">
          <span class="tt-id">{{ technique.attackId }}</span>
          <span class="tt-badge">{{ technique.mitigationCount }} mitigation{{ technique.mitigationCount !== 1 ? 's' : '' }}</span>
          @if (exposureScore > 0) {
            <span class="tt-exposure">👥 {{ exposureScore }} groups</span>
          }
          @if (softwareScore > 0) {
            <span class="tt-exposure">🛠 {{ softwareScore }} software</span>
          }
          @if (campaignScore > 0) {
            <span class="tt-exposure">🎯 {{ campaignScore }} campaign(s)</span>
          }
        </div>
        <div class="tt-name">{{ technique.name }}</div>
        @if (technique.platforms.length) {
          <div class="tt-meta">{{ technique.platforms.join(' · ') }}</div>
        }
        @if (technique.tacticShortnames.length) {
          <div class="tt-tactics">{{ technique.tacticShortnames.join(' · ') }}</div>
        }
        @if (technique.isSubtechnique) {
          <div class="tt-sub-badge">Sub-technique</div>
        }
      </div>
    }
  `,
  styleUrl: './technique-cell.component.scss',
})
export class TechniqueCellComponent implements OnChanges, OnInit, OnDestroy {
  @Input() technique!: Technique;
  @Input() isHighlighted = false;
  @Input() isDimmed = false;
  @Input() isSelected = false;
  @Input() exposureScore = 0;
  @Input() softwareScore = 0;
  @Input() campaignScore = 0;
  @Input() heatmapMode: HeatmapMode = 'coverage';
  @Input() implStatus: ImplStatus | null = null;
  @Input() maxExposure = 1;
  @Input() maxSoftware = 1;
  @Input() maxCampaign = 1;
  @Input() riskScore = 0;
  @Input() maxRisk = 1;
  @Input() controlStatus: 'covered' | 'planned' | 'none' = 'none';
  @Input() hasNote = false;
  @Input() kevScore = 0;
  @Input() maxKev = 1;
  @Input() d3fendScore = 0;
  @Input() maxD3fend = 1;
  @Input() atomicScore = 0;
  @Input() maxAtomic = 10;
  @Input() engageScore = 0;
  @Input() carScore = 0;
  @Input() cveScore = 0;
  @Input() maxCveScore = 1;
  @Input() detectionScore = 0;
  @Input() frequencyScore = 0;
  @Input() criScore = 0;
  @Input() maxCriScore = 1;
  @Input() unifiedScore = 0;
  @Input() sigmaScore = 0;
  @Input() nistScore = 0;
  @Input() verisScore = 0;
  @Input() epssScore = 0;
  @Input() elasticScore = 0;
  @Input() splunkScore = 0;
  @Input() intelScore = 0;
  @Input() maxIntelScore = 1;
  @Input() m365Score = 0;
  @Input() maxM365Score = 1;
  @Input() myExposureScore = 0;
  @Input() maxMyExposure = 1;
  @Input() wazuhScore = 0;
  @Input() maxWazuhScore = 1;
  @Input() csaCcmScore = 0;
  @Input() maxCsaCcmScore = 1;
  @Input() m365ControlsScore = 0;
  @Input() maxM365ControlsScore = 1;
  @Input() showTechniqueId = true;
  @Input() showMitigationCount = true;
  @Input() showTechniqueName = true;
  @Input() isFocused = false;
  @Input() annotation: TechniqueAnnotation | undefined = undefined;
  @Input() isSearchMatch = true;
  @Input() hasActiveSearch = false;
  @Input() isWatched = false;

  @Output() selected = new EventEmitter<Technique>();

  bgColor = '#ffffff';
  textColor = '#000000';
  implDotColor = '';
  showTooltip = false;
  tooltipX = 0;
  tooltipY = 0;

  private settingsSub = new Subscription();

  constructor(private cdr: ChangeDetectorRef, private settingsService: SettingsService) {}

  ngOnInit(): void {
    this.settingsSub = this.settingsService.settings$.subscribe(() => {
      this.ngOnChanges();
      this.cdr.markForCheck();
    });
  }

  ngOnDestroy(): void {
    this.settingsSub.unsubscribe();
  }

  ngOnChanges(): void {
    if (this.heatmapMode === 'exposure') {
      this.bgColor = this.computeExposureColor(this.exposureScore, this.maxExposure);
    } else if (this.heatmapMode === 'software') {
      this.bgColor = this.computeExposureColor(this.softwareScore, this.maxSoftware);
    } else if (this.heatmapMode === 'campaign') {
      this.bgColor = this.computeCampaignColor(this.campaignScore, this.maxCampaign);
    } else if (this.heatmapMode === 'status') {
      this.bgColor = this.computeStatusColor(this.implStatus);
    } else if (this.heatmapMode === 'controls') {
      this.bgColor = this.computeControlColor(this.controlStatus);
    } else if (this.heatmapMode === 'risk') {
      this.bgColor = this.computeRiskColor(this.riskScore, this.maxRisk);
    } else if (this.heatmapMode === 'kev') {
      this.bgColor = this.computeKevColor(this.kevScore, this.maxKev);
    } else if (this.heatmapMode === 'd3fend') {
      this.bgColor = this.computeD3fendColor(this.d3fendScore);
    } else if (this.heatmapMode === 'atomic') {
      this.bgColor = this.computeAtomicColor(this.atomicScore);
    } else if (this.heatmapMode === 'engage') {
      this.bgColor = this.computeEngageColor(this.engageScore);
    } else if (this.heatmapMode === 'car') {
      this.bgColor = this.computeCarColor(this.carScore);
    } else if (this.heatmapMode === 'cve') {
      this.bgColor = this.computeCveColor();
    } else if (this.heatmapMode === 'detection') {
      this.bgColor = this.computeDetectionColor();
    } else if (this.heatmapMode === 'frequency') {
      this.bgColor = this.computeFrequencyColor(this.frequencyScore);
    } else if (this.heatmapMode === 'cri') {
      this.bgColor = this.computeCriColor(this.criScore, this.maxCriScore);
    } else if (this.heatmapMode === 'unified') {
      this.bgColor = this.computeUnifiedColor(this.unifiedScore);
    } else if (this.heatmapMode === 'sigma') {
      this.bgColor = this.computeSigmaColor(this.sigmaScore);
    } else if (this.heatmapMode === 'nist') {
      this.bgColor = this.computeNistColor(this.nistScore);
    } else if (this.heatmapMode === 'veris') {
      this.bgColor = this.computeVerisColor(this.verisScore);
    } else if (this.heatmapMode === 'epss') {
      this.bgColor = this.computeEpssColor(this.epssScore);
    } else if (this.heatmapMode === 'elastic') {
      this.bgColor = this.computeElasticColor(this.elasticScore);
    } else if (this.heatmapMode === 'splunk') {
      this.bgColor = this.computeSplunkColor(this.splunkScore);
    } else if (this.heatmapMode === 'intelligence') {
      this.bgColor = this.computeIntelligenceColor(this.intelScore, this.maxIntelScore);
    } else if (this.heatmapMode === 'm365') {
      this.bgColor = this.computeM365Color(this.m365Score);
    } else if (this.heatmapMode === 'my-exposure') {
      this.bgColor = this.computeMyExposureColor(this.myExposureScore);
    } else if (this.heatmapMode === 'wazuh') {
      this.bgColor = this.computeWazuhColor(this.wazuhScore);
    } else if (this.heatmapMode === 'csa-ccm') {
      this.bgColor = this.computeCsaCcmColor(this.csaCcmScore);
    } else if (this.heatmapMode === 'm365-controls') {
      this.bgColor = this.computeM365ControlsColor(this.m365ControlsScore);
    } else {
      this.bgColor = this.computeColor(this.technique.mitigationCount);
    }
    const tc = tinycolor(this.bgColor);
    this.textColor = tc.isLight() ? '#212121' : '#ffffff';
    this.implDotColor = this.implStatus ? this.computeStatusColor(this.implStatus) : '';
  }

  @HostListener('mouseenter', ['$event'])
  onMouseEnter(e: MouseEvent): void {
    this.tooltipX = Math.min(e.clientX + 14, window.innerWidth - 230);
    this.tooltipY = Math.min(e.clientY + 14, window.innerHeight - 160);
    this.showTooltip = true;
    this.cdr.markForCheck();
  }

  @HostListener('mouseleave')
  onMouseLeave(): void {
    this.showTooltip = false;
    this.cdr.markForCheck();
  }

  private computeColor(count: number): string {
    const colors = this.settingsService.getCoverageColors();
    if (count <= 0) return colors[0];
    if (count >= colors.length - 1) return colors[colors.length - 1];
    return colors[count];
  }

  private computeExposureColor(score: number, max: number): string {
    if (score === 0) return '#eceff1';
    const ratio = max > 0 ? score / max : 0;
    if (ratio >= 0.75) return '#b71c1c';
    if (ratio >= 0.5) return '#e53935';
    if (ratio >= 0.25) return '#ff7043';
    return '#ffb74d';
  }

  private computeCampaignColor(score: number, max: number): string {
    if (score === 0) return '#eceff1';
    const ratio = max > 0 ? score / max : 0;
    if (ratio >= 0.75) return '#4a148c';
    if (ratio >= 0.5) return '#7b1fa2';
    if (ratio >= 0.25) return '#ab47bc';
    return '#ce93d8';
  }

  private computeControlColor(status: 'covered' | 'planned' | 'none'): string {
    switch (status) {
      case 'covered': return '#00c853';
      case 'planned': return '#1565c0';
      default: return '#1c2b30';
    }
  }

  private computeRiskColor(score: number, max: number): string {
    if (score === 0) return '#eceff1';
    const ratio = max > 0 ? score / max : 0;
    if (ratio >= 0.75) return '#4a0000';
    if (ratio >= 0.5) return '#b71c1c';
    if (ratio >= 0.25) return '#e53935';
    return '#ff7043';
  }

  private computeKevColor(score: number, max: number): string {
    if (score === 0) return '#eceff1';
    if (score <= 2) return '#ffd54f';
    if (score <= 5) return '#ff9800';
    return '#d32f2f';
  }

  private computeD3fendColor(score: number): string {
    if (score === 0) return '#d32f2f';
    if (score === 1) return '#e64a19';
    if (score === 2) return '#f57c00';
    if (score === 3) return '#1565c0';
    return '#1a6fba';
  }

  computeAtomicColor(score: number): string {
    if (score === 0) return '#1a1a0a';
    if (score === 1) return '#6d3a10';
    if (score === 2) return '#c06020';
    if (score === 3) return '#e08030';
    return '#f0a040';
  }

  computeEngageColor(score: number): string {
    if (score === 0) return '#0a1a0a';
    if (score === 1) return '#4a3a10';
    if (score === 2) return '#906020';
    if (score === 3) return '#c08030';
    return '#f0a040';
  }

  computeCarColor(score: number): string {
    if (score === 0) return '#0a0a1a';
    if (score === 1) return '#0d2a4a';
    if (score === 2) return '#1a4a7a';
    if (score === 3) return '#2a6aaa';
    return '#58a6ff';
  }

  computeCveColor(): string {
    const score = this.cveScore;
    if (score === 0) return '#1a2332';
    if (score <= 2) return '#4a1a4a';
    if (score <= 5) return '#7b2d8b';
    if (score <= 10) return '#a855b5';
    return '#d946ef';
  }

  computeDetectionColor(): string {
    const score = this.detectionScore;
    if (score === 0) return '#1a2332';
    if (score <= 3) return '#0c2d2d';
    if (score <= 8) return '#0d5e5e';
    if (score <= 15) return '#0e8a7a';
    return '#10b981';
  }

  private computeStatusColor(status: ImplStatus | null): string {
    switch (status) {
      case 'implemented': return '#4caf50';
      case 'in-progress': return '#ff9800';
      case 'planned': return '#2196f3';
      case 'not-started': return '#e53935';
      default: return '#90a4ae'; // no status
    }
  }

  computeFrequencyColor(score: number): string {
    if (score === 0) return '#1c2a38';
    if (score <= 2) return '#1e3a5f';
    if (score <= 5) return '#1565c0';
    if (score <= 10) return '#0ea5e9';
    return '#38bdf8';
  }

  computeCriColor(score: number, max: number): string {
    if (score === 0) return '#1a0a2e';
    const ratio = max > 0 ? score / max : 0;
    if (ratio >= 0.75) return '#6a1b9a';
    if (ratio >= 0.5)  return '#8e24aa';
    if (ratio >= 0.25) return '#ab47bc';
    return '#ce93d8';
  }

  private computeSigmaColor(count: number): string {
    if (count === 0) return '#0a1a1a';
    if (count <= 3)  return '#0d4a3a';
    if (count <= 8)  return '#0d7a5e';
    if (count <= 15) return '#0ea87a';
    return '#10b981';
  }

  private computeNistColor(count: number): string {
    if (count === 0) return '#0d1b2a';
    if (count <= 5)  return '#1a4a7a';
    if (count <= 15) return '#1565c0';
    if (count <= 30) return '#1976d2';
    return '#42a5f5';
  }

  private computeEpssColor(epss: number): string {
    // epss is 0–1 probability; 0 = no CVEs mapped
    if (epss === 0)    return '#1a1a0a';
    if (epss < 0.01)   return '#5c4a00';
    if (epss < 0.05)   return '#c17900';
    if (epss < 0.20)   return '#e65100';
    return '#d32f2f';
  }

  private computeVerisColor(count: number): string {
    if (count === 0) return '#1a0a0a';
    if (count <= 2)  return '#5c1a1a';
    if (count <= 5)  return '#a83232';
    if (count <= 10) return '#d64e4e';
    return '#f28b8b';
  }

  private computeElasticColor(count: number): string {
    if (count === 0) return '#0a1a0a';
    if (count <= 3)  return '#1a3a1a';
    if (count <= 8)  return '#2a6a2a';
    if (count <= 15) return '#3a9a3a';
    return '#4caf50';
  }

  private computeIntelligenceColor(score: number, max: number): string {
    if (score === 0) return '#0a1a2e';
    if (score <= 2) return '#1a3a7a';
    if (score <= 5) return '#5a2d8b';
    if (score <= 10) return '#8b1a5a';
    return '#d32f2f';
  }

  private computeSplunkColor(count: number): string {
    if (count === 0) return '#1a0a0a';
    if (count <= 3)  return '#4a2a0a';
    if (count <= 8)  return '#7a4a1a';
    if (count <= 15) return '#c06a20';
    return '#ff9800';
  }

  private computeM365Color(count: number): string {
    if (count === 0) return '#0a1a2e';
    if (count <= 2)  return '#003a6e';
    if (count <= 5)  return '#005a9e';
    if (count <= 10) return '#0078d4';
    return '#4ca6ff';
  }

  private computeMyExposureColor(score: number): string {
    if (score === 0) return '#1a2332';
    if (score === 1) return '#ff9800';
    if (score <= 3)  return '#f44336';
    if (score <= 6)  return '#d32f2f';
    return '#b71c1c';
  }

  private computeWazuhColor(count: number): string {
    if (count === 0) return '#0a1520';
    if (count <= 1)  return '#0d3a5c';
    if (count <= 3)  return '#1a6fa0';
    if (count <= 5)  return '#2196c8';
    return '#3aabe0';
  }

  /** CSA CCM: green gradient. */
  private computeCsaCcmColor(count: number): string {
    if (count === 0) return '#0a1a10';
    if (count <= 2)  return '#1a4a2a';
    if (count <= 5)  return '#2a7a3a';
    if (count <= 10) return '#3aaa4a';
    return '#4cce5a';
  }

  /** M365 Controls: Microsoft blue gradient. */
  private computeM365ControlsColor(count: number): string {
    if (count === 0) return '#0a1028';
    if (count <= 2)  return '#0a3068';
    if (count <= 5)  return '#0050a8';
    if (count <= 10) return '#0070e8';
    return '#40a0ff';
  }

  /** Unified Risk Score: 0–100 composite. Low = red (poorly defended/targeted), high = green. */
  computeUnifiedColor(score: number): string {
    // Score 0–25 = very low: dark red
    if (score <= 15) return '#7f0000';
    if (score <= 30) return '#c62828';
    if (score <= 50) return '#e65100';
    if (score <= 65) return '#f9a825';
    if (score <= 80) return '#558b2f';
    return '#1b5e20';
  }
}
