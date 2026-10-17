// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, ChangeDetectorRef, Component, DestroyRef, OnInit, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { SourceRecord, SourceStatus } from '../../models/source-record';
import { SourceRegistryService } from '../../services/source-registry.service';
import { SourceRetryService } from '../../services/source-retry.service';

/** One row of the data-health table. */
export interface SourceHealthRow {
  record: SourceRecord;
  /** The status word shown (and asserted by the e2e). */
  statusLabel: string;
  /** Version, or the reviewed date when there is no version. */
  vintage: string;
  /** The reason for a failure, the upstream archive date, or the record's note. */
  detail: string;
  /** null when Retry can run; otherwise why not. */
  retryBlocked: string | null;
  /** 'Load now' for a source not requested yet, 'Retry' otherwise. */
  retryLabel: string;
}

const STATUS_LABEL: Record<SourceStatus, string> = {
  pending: 'not requested',
  loading: 'loading',
  loaded: 'loaded',
  failed: 'failed',
  empty: 'empty',
  stale: 'stale',
  'archived-upstream': 'archived-upstream',
};

/** The order of the summary counts. */
const SUMMARY_ORDER: SourceStatus[] = ['failed', 'empty', 'stale', 'archived-upstream', 'loaded', 'loading', 'pending'];

/**
 * The data-health view (E1.3; plan 6.4 "Data & Trust" rows): every SourceRecord with
 * its status (loaded / failed / empty / stale / archived-upstream, plus not requested
 * and loading), version or reviewed date, rows, the reason for a failure, and a Retry
 * per source that runs that source's loader again.
 */
@Component({
  selector: 'app-source-health',
  standalone: true,
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="sh-head">
      <p class="sh-summary" data-testid="source-health-summary">
        @for (s of summary; track s.status) {
          <span class="sh-count" [attr.data-status]="s.status">{{ s.count }} {{ s.label }}</span>
        }
      </p>
      <label class="sh-filter">
        <input type="checkbox" [checked]="problemsOnly" (change)="toggleProblemsOnly()" />
        Only failed or empty
      </label>
    </div>
    <div class="sh-scroll">
      <table class="sh-table">
        <caption class="sh-caption">Each data source this app ships or fetches, and what happened to it this session</caption>
        <thead>
          <tr>
            <th scope="col" class="sh-col-source">Source</th>
            <th scope="col" class="sh-col-kind">Kind</th>
            <th scope="col" class="sh-col-vintage">Version or reviewed</th>
            <th scope="col" class="sh-col-status">Status</th>
            <th scope="col" class="sh-col-rows">Rows</th>
            <th scope="col" class="sh-col-detail">Detail</th>
            <th scope="col" class="sh-col-action"><span class="sh-visually-hidden">Retry</span></th>
          </tr>
        </thead>
        <tbody>
          @for (row of visibleRows; track row.record.id) {
            <tr [attr.data-source-id]="row.record.id" [attr.data-status]="row.record.status">
              <th scope="row" class="sh-name">{{ row.record.name }}<span class="sh-id">{{ row.record.id }}</span></th>
              <td>{{ row.record.kind }}</td>
              <td>{{ row.vintage }}</td>
              <td><span class="sh-status" [attr.data-status]="row.record.status">{{ row.statusLabel }}</span></td>
              <td class="sh-rows">{{ row.record.rows ?? '' }}</td>
              <td class="sh-detail">{{ row.detail }}</td>
              <td class="sh-action">
                @if (row.retryBlocked === null) {
                  <button type="button" class="sh-retry" (click)="retry(row.record.id)"
                    [attr.aria-label]="row.retryLabel + ': ' + row.record.name">{{ row.retryLabel }}</button>
                } @else {
                  <span class="sh-noretry">{{ row.retryBlocked }}</span>
                }
              </td>
            </tr>
          }
        </tbody>
      </table>
    </div>
  `,
  styles: [`
    :host { display: block; min-width: 0; margin-top: var(--space-4); }
    .sh-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: var(--space-2); margin-bottom: var(--space-2); }
    .sh-summary { margin: 0; display: flex; flex-wrap: wrap; gap: var(--space-3); font-size: var(--text-sm); color: var(--text-secondary); }
    .sh-count[data-status='failed'], .sh-count[data-status='empty'] { color: var(--text-primary); font-weight: 600; }
    .sh-filter { font-size: var(--text-sm); color: var(--text-secondary); display: inline-flex; align-items: center; gap: var(--space-1); }
    .sh-scroll { overflow-x: auto; border: 1px solid var(--border-subtle); border-radius: var(--radius-md); }
    /* Fixed layout: long URLs and versions wrap inside their column instead of widening the page. */
    .sh-table { width: 100%; table-layout: fixed; border-collapse: collapse; font-size: var(--text-sm); color: var(--text-primary); }
    .sh-table th, .sh-table td { overflow-wrap: anywhere; }
    .sh-col-source { width: 22%; } .sh-col-kind { width: 9%; } .sh-col-vintage { width: 17%; } .sh-col-status { width: 12%; }
    .sh-col-rows { width: 7%; } .sh-col-detail { width: 21%; } .sh-col-action { width: 12%; }
    .sh-caption { text-align: left; padding: var(--space-2) var(--space-3); color: var(--text-secondary); font-size: var(--text-xs); }
    .sh-table th, .sh-table td { padding: var(--space-1) var(--space-3); border-top: 1px solid var(--border-subtle); text-align: left; vertical-align: top; }
    .sh-table thead th { font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-secondary); font-weight: 600; }
    .sh-name { font-weight: 600; }
    .sh-id { display: block; font-weight: 400; font-size: var(--text-xs); color: var(--text-secondary); font-family: ui-monospace, monospace; }
    .sh-status { display: inline-block; padding: 0 var(--space-2); border-radius: var(--radius-full); border: 1px solid var(--border-default); }
    .sh-status[data-status='failed'] { border-color: var(--danger); font-weight: 650; }
    .sh-status[data-status='empty'], .sh-status[data-status='stale'], .sh-status[data-status='archived-upstream'] { border-color: var(--warning); }
    .sh-rows { font-variant-numeric: tabular-nums; }
    .sh-detail { color: var(--text-secondary); }
    .sh-noretry { color: var(--text-secondary); font-size: var(--text-xs); }
    .sh-retry {
      padding: 2px var(--space-2); border-radius: var(--radius-sm); border: 1px solid var(--border-default);
      background: var(--bg-raised); color: var(--text-primary); cursor: pointer; font-size: var(--text-sm); white-space: nowrap;
    }
    .sh-retry:hover { background: var(--bg-hover); }
    .sh-retry:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
    .sh-visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
  `],
})
export class SourceHealthComponent implements OnInit {
  private readonly registry = inject(SourceRegistryService);
  private readonly retryService = inject(SourceRetryService);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly destroyRef = inject(DestroyRef);

  rows: SourceHealthRow[] = [];
  summary: { status: SourceStatus; label: string; count: number }[] = [];
  problemsOnly = false;

  get visibleRows(): SourceHealthRow[] {
    return this.problemsOnly
      ? this.rows.filter(r => r.record.status === 'failed' || r.record.status === 'empty')
      : this.rows;
  }

  ngOnInit(): void {
    this.registry.records$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(records => {
      this.rows = records.map(r => this.toRow(r));
      this.summary = SUMMARY_ORDER
        .map(status => ({ status, label: STATUS_LABEL[status], count: records.filter(r => r.status === status).length }))
        .filter(s => s.count > 0);
      this.cdr.markForCheck();
    });
  }

  toggleProblemsOnly(): void {
    this.problemsOnly = !this.problemsOnly;
    this.cdr.markForCheck();
  }

  retry(id: string): void {
    this.retryService.retry(id);
  }

  private toRow(record: SourceRecord): SourceHealthRow {
    let detail = record.note ?? '';
    if (record.status === 'failed') detail = record.lastError ?? 'the request failed';
    else if (record.status === 'empty') detail = 'answered with no usable rows';
    else if (record.archivedUpstream) detail = `upstream archived or withdrawn ${record.archivedUpstream}${detail ? '. ' + detail : ''}`;
    return {
      record,
      statusLabel: STATUS_LABEL[record.status],
      vintage: record.version ?? (record.reviewedDate ? `reviewed ${record.reviewedDate}` : ''),
      detail,
      retryBlocked: this.retryService.unavailableReason(record.id),
      retryLabel: record.status === 'pending' ? 'Load now' : 'Retry',
    };
  }
}
