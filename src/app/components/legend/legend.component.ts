import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { FilterService, HeatmapMode } from '../../services/filter.service';

interface LegendStop { color: string; label: string; }
interface LegendConfig { label: string; stops: LegendStop[]; categorical?: boolean; }

const MODE_CONFIGS: Record<HeatmapMode, LegendConfig> = {
  coverage: {
    label: 'Mitigations',
    stops: [
      { color: '#d32f2f', label: '0' },
      { color: '#ff9800', label: '1' },
      { color: '#ffd54f', label: '2' },
      { color: '#aed581', label: '3' },
      { color: '#4caf50', label: '4+' },
    ],
  },
  exposure: {
    label: 'Exposure',
    stops: [
      { color: '#eceff1', label: '0' },
      { color: '#ffb74d', label: 'low' },
      { color: '#ff7043', label: 'med' },
      { color: '#e53935', label: 'high' },
      { color: '#b71c1c', label: 'critical' },
    ],
  },
  software: {
    label: 'Software',
    stops: [
      { color: '#eceff1', label: '0' },
      { color: '#ffb74d', label: '1' },
      { color: '#ff7043', label: '2' },
      { color: '#e53935', label: '3' },
      { color: '#b71c1c', label: '4+' },
    ],
  },
  campaign: {
    label: 'Campaigns',
    stops: [
      { color: '#eceff1', label: '0' },
      { color: '#ce93d8', label: '1' },
      { color: '#ab47bc', label: '2' },
      { color: '#7b1fa2', label: '3' },
      { color: '#4a148c', label: '4+' },
    ],
  },
  status: {
    label: 'Status',
    categorical: true,
    stops: [
      { color: '#90a4ae', label: 'none' },
      { color: '#e53935', label: '!' },
      { color: '#ff9800', label: '🔧' },
      { color: '#2196f3', label: '📋' },
      { color: '#4caf50', label: '✓' },
    ],
  },
  controls: {
    label: 'Controls',
    categorical: true,
    stops: [
      { color: '#1c2b30', label: 'none' },
      { color: '#1565c0', label: 'planned' },
      { color: '#00c853', label: 'covered' },
    ],
  },
  risk: {
    label: 'Risk Score',
    stops: [
      { color: '#eceff1', label: '0' },
      { color: '#ff7043', label: 'low' },
      { color: '#e53935', label: 'med' },
      { color: '#b71c1c', label: 'high' },
      { color: '#4a0000', label: 'critical' },
    ],
  },
  kev: {
    label: 'KEV CVEs',
    stops: [
      { color: '#eceff1', label: '0' },
      { color: '#ffd54f', label: '1–2' },
      { color: '#ff9800', label: '3–5' },
      { color: '#d32f2f', label: '6+' },
    ],
  },
  d3fend: {
    label: 'D3FEND',
    stops: [
      { color: '#d32f2f', label: '0' },
      { color: '#e64a19', label: '1' },
      { color: '#f57c00', label: '2' },
      { color: '#1565c0', label: '3' },
      { color: '#1a6fba', label: '4+' },
    ],
  },
  atomic: {
    label: 'Atomic Tests',
    stops: [
      { color: '#1a1a0a', label: '0' },
      { color: '#6d3a10', label: '1' },
      { color: '#c06020', label: '2' },
      { color: '#e08030', label: '3' },
      { color: '#f0a040', label: '4+' },
    ],
  },
  engage: {
    label: 'Engage',
    stops: [
      { color: '#0a1a0a', label: '0' },
      { color: '#4a3a10', label: '1' },
      { color: '#906020', label: '2' },
      { color: '#c08030', label: '3' },
      { color: '#f0a040', label: '4+' },
    ],
  },
  car: {
    label: 'CAR Analytics',
    stops: [
      { color: '#0a0a1a', label: '0' },
      { color: '#0d2a4a', label: '1' },
      { color: '#1a4a7a', label: '2' },
      { color: '#2a6aaa', label: '3' },
      { color: '#58a6ff', label: '4+' },
    ],
  },
  cve: {
    label: 'CVEs',
    stops: [
      { color: '#1a2332', label: '0' },
      { color: '#4a1a4a', label: '1–2' },
      { color: '#7b2d8b', label: '3–5' },
      { color: '#a855b5', label: '6–10' },
      { color: '#d946ef', label: '11+' },
    ],
  },
  detection: {
    label: 'Sigma Rules',
    stops: [
      { color: '#1a2332', label: '0' },
      { color: '#0c2d2d', label: '1–3' },
      { color: '#0d5e5e', label: '4–8' },
      { color: '#0e8a7a', label: '9–15' },
      { color: '#10b981', label: '16+' },
    ],
  },
  frequency: {
    label: 'Groups',
    stops: [
      { color: '#1c2a38', label: '0' },
      { color: '#1e3a5f', label: '1–2' },
      { color: '#1565c0', label: '3–5' },
      { color: '#0ea5e9', label: '6–10' },
      { color: '#38bdf8', label: '11+' },
    ],
  },
  cri: {
    label: 'CRI Controls',
    stops: [
      { color: '#1a0a2e', label: '0' },
      { color: '#ce93d8', label: 'low' },
      { color: '#ab47bc', label: 'med' },
      { color: '#8e24aa', label: 'high' },
      { color: '#6a1b9a', label: 'max' },
    ],
  },
  unified: {
    label: 'Unified Risk',
    stops: [
      { color: '#7f0000', label: 'critical' },
      { color: '#c62828', label: 'high' },
      { color: '#f9a825', label: 'medium' },
      { color: '#558b2f', label: 'good' },
      { color: '#1b5e20', label: 'strong' },
    ],
  },
  sigma: {
    label: 'Sigma Rules',
    stops: [
      { color: '#0a1a1a', label: '0' },
      { color: '#0d4a3a', label: '1–3' },
      { color: '#0d7a5e', label: '4–8' },
      { color: '#0ea87a', label: '9–15' },
      { color: '#10b981', label: '16+' },
    ],
  },
  nist: {
    label: 'NIST 800-53',
    stops: [
      { color: '#0d1b2a', label: '0' },
      { color: '#1a4a7a', label: '1–5' },
      { color: '#1565c0', label: '6–15' },
      { color: '#1976d2', label: '16–30' },
      { color: '#42a5f5', label: '31+' },
    ],
  },
  veris: {
    label: 'VERIS Actions',
    stops: [
      { color: '#1a0a0a', label: '0' },
      { color: '#5c1a1a', label: '1–2' },
      { color: '#a83232', label: '3–5' },
      { color: '#d64e4e', label: '6–10' },
      { color: '#f28b8b', label: '11+' },
    ],
  },
  epss: {
    label: 'EPSS Probability',
    stops: [
      { color: '#1a1a0a', label: 'None' },
      { color: '#5c4a00', label: '<1%' },
      { color: '#c17900', label: '1–5%' },
      { color: '#e65100', label: '5–20%' },
      { color: '#d32f2f', label: '20%+' },
    ],
  },
  elastic: {
    label: 'Elastic Rules',
    stops: [
      { color: '#0a1a0a', label: '0' },
      { color: '#1a3a1a', label: '1–3' },
      { color: '#2a6a2a', label: '4–8' },
      { color: '#3a9a3a', label: '9–15' },
      { color: '#4caf50', label: '16+' },
    ],
  },
  splunk: {
    label: 'Splunk Detections',
    stops: [
      { color: '#1a0a0a', label: '0' },
      { color: '#4a2a0a', label: '1–3' },
      { color: '#7a4a1a', label: '4–8' },
      { color: '#c06a20', label: '9–15' },
      { color: '#ff9800', label: '16+' },
    ],
  },
  intelligence: {
    label: 'Intel Signals',
    stops: [
      { color: '#0a1a2e', label: '0' },
      { color: '#1a3a7a', label: '1–2' },
      { color: '#5a2d8b', label: '3–5' },
      { color: '#8b1a5a', label: '6–10' },
      { color: '#d32f2f', label: '11+' },
    ],
  },
  m365: {
    label: 'M365 Defender',
    stops: [
      { color: '#0a1a2e', label: '0' },
      { color: '#003a6e', label: '1–2' },
      { color: '#005a9e', label: '3–5' },
      { color: '#0078d4', label: '6–10' },
      { color: '#4ca6ff', label: '11+' },
    ],
  },
};

@Component({
  selector: 'app-legend',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="legend">
      <span class="legend-label">{{ config.label }}</span>
      <div class="legend-scale">
        @for (stop of config.stops; track stop.label) {
          <div class="legend-stop">
            <div class="swatch" [style.background]="stop.color"></div>
            <span class="stop-label">{{ stop.label }}</span>
          </div>
        }
        @if (!config.categorical) {
          <span class="scale-arrow">fewer ←→ more</span>
        }
      </div>
    </div>
  `,
  styleUrl: './legend.component.scss',
})
export class LegendComponent implements OnInit, OnDestroy {
  heatmapMode: HeatmapMode = 'coverage';

  get config(): LegendConfig {
    return MODE_CONFIGS[this.heatmapMode] ?? MODE_CONFIGS['coverage'];
  }

  private sub = new Subscription();

  constructor(private filterService: FilterService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.sub.add(
      this.filterService.heatmapMode$.subscribe(mode => {
        this.heatmapMode = mode;
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.sub.unsubscribe();
  }
}
