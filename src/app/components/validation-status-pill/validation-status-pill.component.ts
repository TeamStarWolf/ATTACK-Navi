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
import { validationDateTime } from '../../models/local-date';
import { type FiredRuleTally, firedRuleCount, firedRuleTally } from '../../models/posture/fired-rules';

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
          @if (tally(latest); as t) {
            @if (t.executed) {
              <span class="vsp-status" [attr.data-status]="latest.status">{{ statusLabel(latest.status) }}</span>
              @if (labRange) {
                <span class="vsp-lab" title="Exercised against a published Lylat range build">lab</span>
              }
              <span class="vsp-meta">{{ t.words }}</span>
            } @else {
              <!-- RP-F decision 44: an attack that did not execute fired nothing; no fraction, no fired count. -->
              <span class="vsp-not-run"><span class="vsp-status" [attr.data-status]="latest.status">{{ statusLabel(latest.status) }}</span>, {{ t.words }}</span>
            }
          }
        </div>
        @if (labProofRecords.length) {
          <div class="vsp-row vsp-rules">
            range-run rules:
            @for (rec of labProofRecords; track rec.ref) {
              <code class="vsp-rule">{{ rec.ref }} <span class="vsp-rule-date">{{ rec.date | date:'mediumDate' }}</span></code>
            }
          </div>
        }
        <div class="vsp-row vsp-when">
          last run {{ runWhen(latest.runDate) }}
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
    .vsp-not-run { color: var(--text-muted, #8b93a7); }
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
    .vsp-rule-date { color: var(--text-muted, #8b93a7); font-weight: 400; }
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

  /** The latest run is range-scoped: proofScope 'range' with a scored status. */
  get labRange(): boolean {
    return this.latest?.proofScope === 'range' && (this.latest.status === 'passed' || this.latest.status === 'partial');
  }

  /**
   * The range-run detection records — each detection ref with the date it was
   * validated — newest first, one entry per ref (keeping its newest date). Each
   * entry is data-bound (ref + date), so the lint reads it as evidence, not a claim.
   */
  get labProofRecords(): { ref: string; date: string }[] {
    const newest = new Map<string, string>();
    for (const run of this.allRuns) {
      if (run.proofScope !== 'range') continue;
      for (const o of run.outcomes ?? []) {
        if (!o.detectionRef) continue;
        const prev = newest.get(o.detectionRef);
        if (prev === undefined || run.runDate > prev) newest.set(o.detectionRef, run.runDate);
      }
    }
    return [...newest.entries()]
      .map(([ref, date]) => ({ ref, date }))
      .sort((a, b) => (a.date === b.date ? a.ref.localeCompare(b.ref) : a.date < b.date ? 1 : -1));
  }

  openValidationPanel(): void {
    this.panelNav.open('validation');
  }

  statusLabel(s: ValidationStatus): string {
    return STATUS_LABEL[s];
  }

  /** The rules the run fired, counted as the evidence card counts them (firedRules, RP-F decision 30b). */
  firedCount(run: ValidationRunV2): number {
    return firedRuleCount(run);
  }

  /**
   * The run's fired rules beside its expected ones, through the shared helper (RP-F
   * decision 38): 'k of M expected rules fired' (k counts expected rules that fired),
   * plus ', plus n unexpected' when other rules fired, or 'N fired, none expected'.
   */
  tally(run: ValidationRunV2): FiredRuleTally {
    return firedRuleTally(run);
  }

  /** The run's local date and time, with the formatter the evidence card prints its day with (RP-F decision 16). */
  runWhen(date: string): string {
    return validationDateTime(date);
  }
}
