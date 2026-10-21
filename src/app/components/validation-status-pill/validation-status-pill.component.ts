// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component, Input, ChangeDetectionStrategy, ChangeDetectorRef,
  OnChanges, OnInit, OnDestroy, inject, SimpleChanges,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { ValidationService, ValidationRunV2, ValidationStatus } from '../../services/validation.service';
import { PanelNavService } from '../../services/panel-nav.service';

const STATUS_LABEL: Record<ValidationStatus, string> = {
  passed: 'PASS', failed: 'FAIL', partial: 'PARTIAL',
  'no-telemetry': 'NO TELEMETRY', untested: 'UNTESTED',
  'not-reproducible': 'Not reproducible (patched target)',
};

@Component({
  selector: 'app-validation-status-pill',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="vsp">
      <header class="vsp-head">
        <h4>Detection Validation</h4>
        <button class="vsp-open" (click)="openValidationPanel()" title="Open the Detection Validation Workbench">
          🎯 Open Workbench →
        </button>
      </header>
      @if (latest) {
        <div class="vsp-row">
          <span class="vsp-status" [attr.data-status]="latest.status">{{ statusLabel(latest.status) }}</span>
          @if (labProven) {
            <!-- truth-vocab-allow-next-line proven-only -- labProven gates this to proofScope 'range'; the run carries its date and source -->
            <span class="vsp-lab" title="Validated against a published Lylat range build">lab</span>
          }
          <span class="vsp-meta">
            {{ latest.detectionsFired.length }} of {{ latest.detectionsExpected.length }} detection rules fired
          </span>
        </div>
        @if (labRuleRefs.length) {
          <div class="vsp-row vsp-rules">
            <!-- truth-vocab-allow-next-line proven-only -- labRuleRefs holds only range-Proven rule ids; each is validated by the imported range run -->
            range-validated rules:
            @for (ref of labRuleRefs; track ref) { <code class="vsp-rule">{{ ref }}</code> }
          </div>
        }
        <div class="vsp-row vsp-when">
          last run {{ latest.runDate | date:'short' }}
          @if (latest.operator) { · by {{ latest.operator }} }
          @if (allRuns.length > 1) { · {{ allRuns.length }} total runs }
        </div>
        @if (latest.notes) {
          <p class="vsp-notes">"{{ latest.notes }}"</p>
        }
      } @else {
        <p class="vsp-empty">
          <span class="vsp-status" data-status="untested">UNTESTED</span>
          No validation runs recorded for {{ attackId }} yet.
        </p>
      }
    </section>
  `,
  styles: [`
    .vsp {
      margin: 12px 0; padding: 10px 12px;
      background: rgba(16, 185, 129, 0.04);
      border: 1px solid rgba(16, 185, 129, 0.18);
      border-radius: 6px;
    }
    .vsp-head {
      display: flex; justify-content: space-between; align-items: center;
      margin: 0 0 8px;
      h4 {
        font-size: 12px; text-transform: uppercase; letter-spacing: 0.07em;
        color: #10b981; margin: 0; font-weight: 700;
      }
    }
    .vsp-open {
      background: transparent; border: 1px solid var(--border-subtle, #2a2f3d);
      color: var(--text-muted, #8b93a7); padding: 3px 9px;
      border-radius: 4px; cursor: pointer; font-size: 11px;
      &:hover { color: #10b981; border-color: #10b981; }
    }
    .vsp-row {
      display: flex; align-items: center; gap: 8px;
      font-size: 12.5px; color: var(--text-main, #e6e8ee);
    }
    .vsp-when { color: var(--text-muted, #8b93a7); font-size: 11px; margin-top: 2px; }
    .vsp-meta { color: var(--text-muted, #8b93a7); }
    .vsp-lab {
      font-size: 9.5px; font-weight: 800; letter-spacing: 0.06em; text-transform: uppercase;
      padding: 2px 7px; border-radius: 4px; flex-shrink: 0;
      background: rgba(16,185,129,0.14); color: #10b981; border: 1px solid rgba(16,185,129,0.4);
    }
    .vsp-rules {
      flex-wrap: wrap; gap: 5px; margin-top: 4px;
      font-size: 11px; color: var(--text-muted, #8b93a7);
    }
    .vsp-rule {
      font-family: var(--font-mono, ui-monospace, monospace); font-size: 10.5px;
      padding: 1px 5px; border-radius: 3px;
      background: rgba(16,185,129,0.08); color: #10b981;
    }
    .vsp-empty {
      display: flex; align-items: center; gap: 8px;
      font-size: 12px; color: var(--text-muted, #8b93a7); margin: 0;
    }
    .vsp-notes {
      font-size: 11.5px; color: var(--text-muted, #8b93a7);
      font-style: italic; margin: 6px 0 0; padding-left: 6px;
      border-left: 2px solid rgba(16, 185, 129, 0.3);
    }
    .vsp-status {
      font-size: 9.5px; font-weight: 800; letter-spacing: 0.06em;
      padding: 2px 7px; border-radius: 4px; text-transform: uppercase;
      flex-shrink: 0;
      &[data-status="passed"]      { background: rgba(16,185,129,0.18); color: #10b981; }
      &[data-status="partial"]     { background: rgba(245,158,11,0.18); color: #f59e0b; }
      &[data-status="failed"]      { background: rgba(239,68,68,0.18); color: #ef4444; }
      &[data-status="no-telemetry"]{ background: rgba(107,114,128,0.18); color: #6b7280; }
      &[data-status="untested"]    { background: rgba(156,163,175,0.18); color: #9ca3af; }
      &[data-status="not-reproducible"] { background: rgba(139,92,246,0.18); color: #8b5cf6; }
    }
  `],
})
export class ValidationStatusPillComponent implements OnInit, OnChanges, OnDestroy {
  @Input() attackId = '';

  private validation = inject(ValidationService);
  private panelNav = inject(PanelNavService);
  private cdr = inject(ChangeDetectorRef);
  private sub?: Subscription;

  latest: ValidationRunV2 | null = null;
  allRuns: ValidationRunV2[] = [];

  ngOnInit(): void {
    this.sub = this.validation.runs$.subscribe(() => {
      this.recompute();
      this.cdr.markForCheck();
    });
  }

  ngOnChanges(_: SimpleChanges): void {
    this.recompute();
  }

  ngOnDestroy(): void {
    this.sub?.unsubscribe();
  }

  private recompute(): void {
    if (!this.attackId) {
      this.latest = null;
      this.allRuns = [];
      return;
    }
    this.allRuns = this.validation.forTechnique(this.attackId);
    this.latest = this.validation.latestFor(this.attackId);
  }

  /** The latest run is range-scoped proof: it was validated against a published range build. */
  get labProven(): boolean {
    return this.latest?.proofScope === 'range' && (this.latest.status === 'passed' || this.latest.status === 'partial');
  }

  /** The detection rule ids validated in a range run, newest first, de-duplicated. */
  get labRuleRefs(): string[] {
    const seen = new Set<string>();
    for (const run of this.allRuns) {
      if (run.proofScope !== 'range') continue;
      for (const o of run.outcomes ?? []) {
        if (o.detectionRef) seen.add(o.detectionRef);
      }
    }
    return [...seen];
  }

  openValidationPanel(): void {
    this.panelNav.open('validation');
  }

  statusLabel(s: ValidationStatus): string {
    return STATUS_LABEL[s];
  }
}
