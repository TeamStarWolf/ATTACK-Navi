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

import tinycolor from 'tinycolor2';
import { SAFE_SEQ, SAFE_STATUS, SAFE_CONTROLS } from '../../models/safe-palette';
import { Technique } from '../../models/technique';
import { HeatmapMode } from '../../services/filter.service';
import { ImplStatus } from '../../services/implementation.service';
import { TechniqueAnnotation } from '../../services/annotation.service';
import { SettingsService } from '../../services/settings.service';

@Component({
  selector: 'app-technique-cell',
  standalone: true,
  imports: [],
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
  @Input() maxAtomic = 1;
  @Input() engageScore = 0;
  @Input() maxEngageScore = 1;
  @Input() carScore = 0;
  @Input() maxCarScore = 1;
  @Input() cveScore = 0;
  @Input() maxCveScore = 1;
  @Input() detectionScore = 0;
  @Input() maxDetectionScore = 1;
  @Input() frequencyScore = 0;
  @Input() maxFrequencyScore = 1;
  @Input() criScore = 0;
  @Input() maxCriScore = 1;
  @Input() unifiedScore = 0;
  @Input() sigmaScore = 0;
  @Input() maxSigmaScore = 1;
  @Input() nistScore = 0;
  @Input() maxNistScore = 1;
  @Input() verisScore = 0;
  @Input() maxVerisScore = 1;
  @Input() epssScore = 0;
  @Input() elasticScore = 0;
  @Input() maxElasticScore = 1;
  @Input() splunkScore = 0;
  @Input() maxSplunkScore = 1;
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
  @Input() killChainScore = 0;
  @Input() maxKillChainScore = 1;
  @Input() pocScore = 0;
  @Input() maxPocScore = 1;
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
      this.bgColor = this.computeRelativeColor(this.kevScore, this.maxKev, '#eceff1', ['#ffd54f', '#ffb300', '#ff7043', '#d32f2f']);
    } else if (this.heatmapMode === 'd3fend') {
      this.bgColor = this.computeRelativeColor(this.d3fendScore, this.maxD3fend, '#d32f2f', ['#e64a19', '#f57c00', '#1565c0', '#1a6fba']);
    } else if (this.heatmapMode === 'atomic') {
      this.bgColor = this.computeRelativeColor(this.atomicScore, this.maxAtomic, '#1a1a0a', ['#6d3a10', '#c06020', '#e08030', '#f0a040']);
    } else if (this.heatmapMode === 'engage') {
      this.bgColor = this.computeRelativeColor(this.engageScore, this.maxEngageScore, '#0a1a0a', ['#4a3a10', '#906020', '#c08030', '#f0a040']);
    } else if (this.heatmapMode === 'car') {
      this.bgColor = this.computeRelativeColor(this.carScore, this.maxCarScore, '#0a0a1a', ['#0d2a4a', '#1a4a7a', '#2a6aaa', '#58a6ff']);
    } else if (this.heatmapMode === 'cve') {
      this.bgColor = this.computeRelativeColor(this.cveScore, this.maxCveScore, '#1a2332', ['#4a1a4a', '#7b2d8b', '#a855b5', '#d946ef']);
    } else if (this.heatmapMode === 'detection') {
      this.bgColor = this.computeRelativeColor(this.detectionScore, this.maxDetectionScore, '#1a2332', ['#0c2d2d', '#0d5e5e', '#0e8a7a', '#10b981']);
    } else if (this.heatmapMode === 'frequency') {
      this.bgColor = this.computeRelativeColor(this.frequencyScore, this.maxFrequencyScore, '#1c2a38', ['#1e3a5f', '#1565c0', '#0ea5e9', '#38bdf8']);
    } else if (this.heatmapMode === 'cri') {
      this.bgColor = this.computeCriColor(this.criScore, this.maxCriScore);
    } else if (this.heatmapMode === 'unified') {
      this.bgColor = this.computeUnifiedColor(this.unifiedScore);
    } else if (this.heatmapMode === 'sigma') {
      this.bgColor = this.computeRelativeColor(this.sigmaScore, this.maxSigmaScore, '#0a1a1a', ['#0d4a3a', '#0d7a5e', '#0ea87a', '#10b981']);
    } else if (this.heatmapMode === 'nist') {
      this.bgColor = this.computeRelativeColor(this.nistScore, this.maxNistScore, '#0d1b2a', ['#1a4a7a', '#1565c0', '#1976d2', '#42a5f5']);
    } else if (this.heatmapMode === 'veris') {
      this.bgColor = this.computeRelativeColor(this.verisScore, this.maxVerisScore, '#1a0a0a', ['#5c1a1a', '#a83232', '#d64e4e', '#f28b8b']);
    } else if (this.heatmapMode === 'epss') {
      this.bgColor = this.computeEpssColor(this.epssScore);
    } else if (this.heatmapMode === 'elastic') {
      this.bgColor = this.computeRelativeColor(this.elasticScore, this.maxElasticScore, '#0a1a0a', ['#1a3a1a', '#2a6a2a', '#3a9a3a', '#4caf50']);
    } else if (this.heatmapMode === 'splunk') {
      this.bgColor = this.computeRelativeColor(this.splunkScore, this.maxSplunkScore, '#1a0a0a', ['#4a2a0a', '#7a4a1a', '#c06a20', '#ff9800']);
    } else if (this.heatmapMode === 'intelligence') {
      this.bgColor = this.computeRelativeColor(this.intelScore, this.maxIntelScore, '#0a1a2e', ['#1a3a7a', '#5a2d8b', '#8b1a5a', '#d32f2f']);
    } else if (this.heatmapMode === 'm365') {
      this.bgColor = this.computeRelativeColor(this.m365Score, this.maxM365Score, '#0a1a2e', ['#003a6e', '#005a9e', '#0078d4', '#4ca6ff']);
    } else if (this.heatmapMode === 'my-exposure') {
      this.bgColor = this.computeRelativeColor(this.myExposureScore, this.maxMyExposure, '#1a2332', ['#ff9800', '#f44336', '#d32f2f', '#b71c1c']);
    } else if (this.heatmapMode === 'wazuh') {
      this.bgColor = this.computeRelativeColor(this.wazuhScore, this.maxWazuhScore, '#0a1520', ['#0d3a5c', '#1a6fa0', '#2196c8', '#3aabe0']);
    } else if (this.heatmapMode === 'csa-ccm') {
      this.bgColor = this.computeRelativeColor(this.csaCcmScore, this.maxCsaCcmScore, '#0a1a10', ['#1a4a2a', '#2a7a3a', '#3aaa4a', '#4cce5a']);
    } else if (this.heatmapMode === 'm365-controls') {
      this.bgColor = this.computeRelativeColor(this.m365ControlsScore, this.maxM365ControlsScore, '#0a1028', ['#0a3068', '#0050a8', '#0070e8', '#40a0ff']);
    } else if (this.heatmapMode === 'kill-chain') {
      this.bgColor = this.computeRelativeColor(this.killChainScore, this.maxKillChainScore, '#0e0a1a', ['#2d1a5e', '#5a2d8b', '#7b3faa', '#9c5cc5']);
    } else if (this.heatmapMode === 'poc-exploits') {
      this.bgColor = this.computeRelativeColor(this.pocScore, this.maxPocScore, '#1a0e0a', ['#5c2a0a', '#a84a1a', '#d96a2a', '#ff8c3a']);
    } else {
      this.bgColor = this.computeColor(this.technique.mitigationCount);
    }
    // Pick whichever text color actually has the higher WCAG contrast
    // against the computed background (isLight()'s brightness threshold
    // mis-served mid-tone backgrounds).
    this.textColor = tinycolor
      .mostReadable(this.bgColor, ['#212121', '#ffffff'])
      .toHexString();
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

  private computeRelativeColor(score: number, max: number, zero: string, colors: [string, string, string, string]): string {
    if (score === 0) return zero;
    // Colorblind-safe mode: one viridis ramp for every relative mode.
    const ramp = this.settingsService.current.colorblindSafe ? SAFE_SEQ : colors;
    const ratio = max > 0 ? score / max : 0;
    if (ratio >= 0.75) return ramp[3];
    if (ratio >= 0.5) return ramp[2];
    if (ratio >= 0.25) return ramp[1];
    return ramp[0];
  }

  private computeColor(count: number): string {
    const colors = this.settingsService.getCoverageColors();
    if (count <= 0) return colors[0];
    if (count >= colors.length - 1) return colors[colors.length - 1];
    return colors[count];
  }

  private computeExposureColor(score: number, max: number): string {
    return this.computeRelativeColor(score, max, '#eceff1', ['#ffb74d', '#ff7043', '#e53935', '#b71c1c']);
  }

  private computeCampaignColor(score: number, max: number): string {
    return this.computeRelativeColor(score, max, '#eceff1', ['#ce93d8', '#ab47bc', '#7b1fa2', '#4a148c']);
  }

  private computeControlColor(status: 'covered' | 'planned' | 'none'): string {
    if (this.settingsService.current.colorblindSafe) {
      return SAFE_CONTROLS[status] ?? SAFE_CONTROLS['none'];
    }
    switch (status) {
      case 'covered': return '#00c853';
      case 'planned': return '#1565c0';
      default: return '#1c2b30';
    }
  }

  private computeRiskColor(score: number, max: number): string {
    return this.computeRelativeColor(score, max, '#eceff1', ['#ff7043', '#e53935', '#b71c1c', '#4a0000']);
  }

  private computeStatusColor(status: ImplStatus | null): string {
    if (this.settingsService.current.colorblindSafe) {
      return SAFE_STATUS[status ?? 'none'] ?? SAFE_STATUS['none'];
    }
    switch (status) {
      case 'implemented': return '#4caf50';
      case 'in-progress': return '#ff9800';
      case 'planned': return '#2196f3';
      case 'not-started': return '#e53935';
      default: return '#90a4ae'; // no status
    }
  }

  computeCriColor(score: number, max: number): string {
    return this.computeRelativeColor(score, max, '#1a0a2e', ['#ce93d8', '#ab47bc', '#8e24aa', '#6a1b9a']);
  }

  private computeEpssColor(epss: number): string {
    // epss is 0–1 probability; 0 = no CVEs mapped
    if (epss === 0) return '#1a1a0a';
    const ramp: [string, string, string, string] = this.settingsService.current.colorblindSafe
      ? SAFE_SEQ
      : ['#5c4a00', '#c17900', '#e65100', '#d32f2f'];
    if (epss < 0.01) return ramp[0];
    if (epss < 0.05) return ramp[1];
    if (epss < 0.20) return ramp[2];
    return ramp[3];
  }

  /** Unified Risk Score: 0–100 composite. Low = poorly defended, high = strong. */
  computeUnifiedColor(score: number): string {
    if (this.settingsService.current.colorblindSafe) {
      // 6-stop viridis: monotonic luminance keeps low→high readable.
      if (score <= 15) return '#440154';
      if (score <= 30) return '#414487';
      if (score <= 50) return '#2a788e';
      if (score <= 65) return '#22a884';
      if (score <= 80) return '#7ad151';
      return '#fde725';
    }
    if (score <= 15) return '#7f0000';
    if (score <= 30) return '#c62828';
    if (score <= 50) return '#e65100';
    if (score <= 65) return '#f9a825';
    if (score <= 80) return '#558b2f';
    return '#1b5e20';
  }
}
