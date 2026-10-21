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
  inject,
} from '@angular/core';
import { Subscription } from 'rxjs';

import tinycolor from 'tinycolor2';
import { SAFE_SEQ } from '../../models/safe-palette';
import { Technique } from '../../models/technique';
import { HeatmapMode } from '../../services/filter.service';
import { ImplStatus } from '../../services/implementation.service';
import { TechniqueAnnotation } from '../../services/annotation.service';
import { SettingsService } from '../../services/settings.service';
import { LENS_NA_COLOR, heatmapModeDef } from '../../models/heatmap-modes';
import { SCORE_ONLY_LENSES, registryColor } from '../../models/lens-registry';
import {
  type PostureCellVM, type PostureTheme, postureHasCheck, postureLensCell, posturePatterns,
} from '../../models/posture/posture-ramp';
import { provenLabBadge, statusStop, statusStopFill, statusStopLabel } from '../../models/posture/lens-ramps';
import { type MyMarkBucket, myMarkFill } from '../../models/posture/gap';
import { ThemeService } from '../../services/theme.service';

@Component({
  selector: 'app-technique-cell',
  standalone: true,
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div
      class="cell"
      role="button"
      [attr.aria-label]="technique.attackId + ': ' + technique.name + (posture ? ', ' + posture.label : '') + (threatGap ? ', threat gap' : '')"
      tabindex="0"
      [class.sub]="technique.isSubtechnique"
      [class.highlighted]="isHighlighted"
      [class.dimmed]="isDimmed"
      [class.selected]="isSelected"
      [class.focused]="isFocused"
      [class.search-dimmed]="hasActiveSearch && !isSearchMatch"
      [class.search-highlighted]="hasActiveSearch && isSearchMatch"
      [class.lens-na]="lensUnavailable"
      [class.posture-partial]="posturePartial"
      [class.posture-contradicted]="postureContradicted"
      [class.posture-not-reproducible]="postureNotReproducible"
      [style.background-color]="bgColor"
      [style.color]="textColor"
      (click)="selected.emit(technique)"
      (keydown.enter)="selected.emit(technique)"
      (keydown.space)="$event.preventDefault(); selected.emit(technique)"
    >
      @if (myMark && showMyMarks) {
        <span class="my-mark" aria-hidden="true" [attr.data-bucket]="myMark" [style.--my-mark-color]="myMarkColor"></span>
      }
      @if (threatGap) {
        <span class="threat-gap-outline" aria-hidden="true"></span>
      }
      @if (showTechniqueId) {
        <span class="id">{{ technique.attackId }}</span>
      }
      @if (postureCheck) {
        <span class="posture-check" aria-hidden="true">✓</span>
      }
      @if (proofLab) {
        <span class="proof-lab-badge" aria-hidden="true">lab</span>
      }
      @if (showTechniqueName) {
        <span class="name">{{ technique.name }}</span>
      }
      @if (heatmapMode === 'coverage' && implStatus) {
        <span
          class="impl-dot"
          [class.impl-dot-partial]="!!implPartialVia"
          [style.background]="implDotColor"
          [title]="'Status: ' + implDotLabel"
        ></span>
      }
      @if (hasNote && showNoteDot) {
        <span class="note-dot" title="Has analyst notes">📝</span>
      }
      @if (annotation && showAnnotationDot) {
        <div class="annotation-dot" [class]="'ann-' + annotation.color" [title]="annotation.note"></div>
      }
      @if (isWatched && showWatchIndicator) {
        <div class="watch-indicator" title="On watchlist">🔖</div>
      }
      <div class="badge-row">
        @if (exposureScore > 0 && showExposureBadge) {
          <span class="exposure-badge" [title]="exposureScore + ' threat actor(s) use this technique'">
            👥{{ exposureScore }}
          </span>
        }
        @if (softwareScore > 0 && showSoftwareBadge) {
          <span class="software-badge" [title]="softwareScore + ' software/malware use this technique'">
            🛠{{ softwareScore }}
          </span>
        }
        @if (campaignScore > 0 && showCampaignBadge) {
          <span class="campaign-badge" [title]="campaignScore + ' campaign(s) use this technique'">
            🎯{{ campaignScore }}
          </span>
        }
        @if (heatmapMode === 'd3fend' && showMetricBadge && !lensUnavailable) {
          <span class="d3fend-badge" [title]="d3fendScore + ' D3FEND countermeasure(s)'">
            🛡{{ d3fendScore }}
          </span>
        }
        @if (heatmapMode === 'atomic' && atomicScore > 0 && showMetricBadge && !lensUnavailable) {
          <span class="atomic-badge" [title]="atomicScore + ' Atomic Red Team test(s)'">
            ⚛{{ atomicScore }}
          </span>
        }
        @if (heatmapMode === 'cri' && criScore > 0 && showMetricBadge && !lensUnavailable) {
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
        @if (posture) {
          <div class="tt-posture">{{ posture.label }}</div>
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
  @Input() heatmapMode: HeatmapMode = 'unified';
  /**
   * The active lens has no data for the domain on screen (E1.2): paint the
   * neutral n/a hatch instead of the lens's zero colour, so a missing source
   * never reads as a real zero.
   */
  @Input() lensUnavailable = false;
  /**
   * This technique's posture on a registry-hosted posture lens (P2-13); null
   * on every other lens. The matrix builds it once per posture change.
   */
  @Input() posture: PostureCellVM | null = null;
  /**
   * My marks (P2-17): the technique's bucket when the owner has a mark that
   * holds, or 'contradicted'; null for none and known. Drawn as a 3 px left bar
   * on every lens; the lens colour is untouched.
   */
  @Input() myMark: MyMarkBucket | null = null;
  /** Threat gaps overlay (P2-17): draw the 2 px amber inset outline (models/posture/gap.ts). */
  @Input() threatGap = false;
  @Input() implStatus: ImplStatus | null = null;
  /** The broad mitigation(s) the technique is implemented through only (D16, P2-14); null when full or none. */
  @Input() implPartialVia: string | null = null;
  @Input() maxExposure = 1;
  @Input() maxSoftware = 1;
  @Input() maxCampaign = 1;
  @Input() riskScore = 0;
  @Input() maxRisk = 1;
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
  /** Reference depth (heat=unified), 0-100: the unified lens's registry projection (P2-15), coloured by its `color`. */
  @Input() unifiedScore = 0;
  @Input() sigmaScore = 0;
  @Input() maxSigmaScore = 1;
  @Input() libraryScore = 0;
  @Input() maxLibraryScore = 1;
  /** When set (user-imported layer active), overrides the `library` ramp with the layer's own color. */
  @Input() libraryColorOverride: string | null = null;
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

  // Per-cell display toggles, sourced from SettingsService.cellDisplay inside
  // the existing settings$ subscription (NOT @Inputs — matrix.component stays
  // untouched). Default true so cells render identically to today.
  showExposureBadge = true;
  showSoftwareBadge = true;
  showCampaignBadge = true;
  showMetricBadge = true;
  showNoteDot = true;
  showAnnotationDot = true;
  showWatchIndicator = true;
  /** AppSettings.cellDisplay.myMarks (P2-17), default true. */
  showMyMarks = true;

  @Output() selected = new EventEmitter<Technique>();

  bgColor = '#ffffff';
  textColor = '#000000';
  implDotColor = '';
  /** The implementation dot's words: the status stop, 'implemented, partial via M1038' when broad only (P2-14). */
  implDotLabel = '';
  /** The Proven lens's 'lab' badge: the best proof was recorded in the range (P2-14). */
  proofLab = false;
  /** Posture lens patterns and mark (P2-13): drawn on top of the fill, never by hue alone. */
  posturePartial = false;
  postureContradicted = false;
  postureNotReproducible = false;
  postureCheck = false;
  /** The My marks bar's colour: the bucket's posture ramp token in the current theme. */
  myMarkColor = '';
  showTooltip = false;
  tooltipX = 0;
  tooltipY = 0;

  private settingsSub = new Subscription();
  private readonly themeService = inject(ThemeService);
  /** The theme a registry lens colours for; follows ThemeService. */
  private theme: PostureTheme = 'dark';

  constructor(private cdr: ChangeDetectorRef, private settingsService: SettingsService) {}

  ngOnInit(): void {
    this.settingsSub = this.settingsService.settings$.subscribe((s) => {
      const cd = s.cellDisplay;
      if (cd) {
        this.showExposureBadge = cd.exposureBadge;
        this.showSoftwareBadge = cd.softwareBadge;
        this.showCampaignBadge = cd.campaignBadge;
        this.showMetricBadge = cd.metricBadge;
        this.showNoteDot = cd.noteDot;
        this.showAnnotationDot = cd.annotationDot;
        this.showWatchIndicator = cd.watchIndicator;
        this.showMyMarks = cd.myMarks !== false;
      }
      this.ngOnChanges();
      this.cdr.markForCheck();
    });
    this.settingsSub.add(
      this.themeService.isLight$.subscribe((light) => {
        const theme: PostureTheme = light ? 'light' : 'dark';
        if (theme === this.theme) return;
        this.theme = theme;
        this.ngOnChanges();
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.settingsSub.unsubscribe();
  }

  ngOnChanges(): void {
    const def = heatmapModeDef(this.heatmapMode);
    const registry = !this.lensUnavailable && !!def?.color;
    if (this.lensUnavailable) {
      this.bgColor = LENS_NA_COLOR;
    } else if (def?.color) {
      // Registry-hosted lens (P2-13): the one colour function the minimap and legend also call.
      // A score-only lens (P2-15: Reference depth) colours its score input; it has no posture.
      const cell = SCORE_ONLY_LENSES.has(def.value) ? { score: this.unifiedScore } : postureLensCell(this.posture);
      this.bgColor = registryColor(def, cell, {
        theme: this.theme, colorblindSafe: this.settingsService.current.colorblindSafe,
      });
    } else if (this.heatmapMode === 'exposure') {
      this.bgColor = this.computeExposureColor(this.exposureScore, this.maxExposure);
    } else if (this.heatmapMode === 'software') {
      this.bgColor = this.computeExposureColor(this.softwareScore, this.maxSoftware);
    } else if (this.heatmapMode === 'campaign') {
      this.bgColor = this.computeCampaignColor(this.campaignScore, this.maxCampaign);
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
    } else if (this.heatmapMode === 'library') {
      this.bgColor = this.libraryColorOverride
        ?? this.computeRelativeColor(this.libraryScore, this.maxLibraryScore, '#12122a', ['#1e3a5f', '#2f6ab0', '#38bdf8', '#a78bfa']);
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
    } else if (this.heatmapMode === 'f3-origin') {
      this.bgColor = this.computeF3OriginColor();
    } else {
      this.bgColor = this.computeColor(this.technique.mitigationCount);
    }
    // Pick whichever text color actually has the higher WCAG contrast
    // against the computed background (isLight()'s brightness threshold
    // mis-served mid-tone backgrounds). Candidates are PURE black/white:
    // #212121 lost to white on mid greens at 3.95 vs 4.08 — both failing —
    // where #000 clears AA at 5.15.
    this.textColor = tinycolor
      .mostReadable(this.bgColor, ['#000000', '#ffffff'])
      .toHexString();
    // The coverage lens's implementation dot shares the status lens's stops (P2-14).
    const dotStop = statusStop({ status: this.implStatus, partialVia: this.implPartialVia });
    this.implDotColor = this.implStatus ? statusStopFill(dotStop, this.theme) : '';
    this.implDotLabel = this.implStatus ? statusStopLabel(dotStop, this.implPartialVia) : '';
    this.proofLab = registry && this.heatmapMode === 'proven' && !!this.posture && provenLabBadge(postureLensCell(this.posture));
    const patterns = registry && this.posture ? posturePatterns(this.posture) : [];
    this.posturePartial = patterns.includes('partial');
    this.postureContradicted = patterns.includes('contradicted');
    this.postureNotReproducible = patterns.includes('not-reproducible');
    this.postureCheck = registry && !!this.posture && postureHasCheck(this.posture.bucket);
    this.myMarkColor = this.myMark ? myMarkFill(this.myMark, this.theme) : '';
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

  private computeRiskColor(score: number, max: number): string {
    return this.computeRelativeColor(score, max, '#eceff1', ['#ff7043', '#e53935', '#b71c1c', '#4a0000']);
  }

  /**
   * F3 domain origin: shared-with-ATT&CK (T-id) vs fraud-native (F-id).
   * The T-prefix rule IS CTID's isAttack flag — verified 1:1 against their
   * published matrix data (fight-fraud-framework f3-v1.1.json).
   */
  private computeF3OriginColor(): string {
    const shared = this.technique.attackId.startsWith('T');
    if (this.settingsService.current.colorblindSafe) {
      return shared ? '#0072b2' : '#cc79a7'; // Okabe-Ito blue / reddish purple
    }
    return shared ? '#1565c0' : '#6a1b9a';
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
}
