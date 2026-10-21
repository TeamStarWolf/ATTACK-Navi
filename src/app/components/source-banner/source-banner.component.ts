// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, ChangeDetectorRef, Component, DestroyRef, OnInit, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router, RouterLink } from '@angular/router';
import { combineLatest, filter, map, startWith } from 'rxjs';
import { DATA_PRESENT_STATUSES, SourceRecord } from '../../models/source-record';
import { DataService } from '../../services/data.service';
import { SourceRegistryService } from '../../services/source-registry.service';
import { sourcesForRoute } from '../../services/route-sources';
import { EMPTY_SOURCE_DETAIL } from '../../models/briefing';

/** A source this view reads that did not load ('failed') or loaded nothing usable ('empty'). */
export interface MissingSource {
  id: string;
  name: string;
  status: 'failed' | 'empty';
  /** Why: the recorded error for 'failed'; for 'empty', EMPTY_SOURCE_DETAIL (models/briefing.ts). */
  detail: string;
  /** The stand-in that loaded in its place (a source whose fallbackFor names this one), with its version. */
  fallback?: string;
}

/**
 * The sources a route reads that are failed or empty right now, in the route's order.
 * A failed source with a stand-in (the bundled KEV snapshot for the live KEV feed) says
 * which stand-in is in use; when the stand-in did not load either, it is listed too.
 */
export function missingSources(ids: readonly string[], records: readonly SourceRecord[]): MissingSource[] {
  const byId = new Map(records.map(r => [r.id, r]));
  const missing: MissingSource[] = [];
  const add = (r: SourceRecord, fallback?: string) => {
    if (missing.some(m => m.id === r.id)) return;
    missing.push({
      id: r.id,
      name: r.name,
      status: r.status as 'failed' | 'empty',
      detail: r.status === 'failed' ? (r.lastError ?? 'the request failed') : EMPTY_SOURCE_DETAIL,
      ...(fallback ? { fallback } : {}),
    });
  };
  const isMissing = (r: SourceRecord | undefined): r is SourceRecord => !!r && (r.status === 'failed' || r.status === 'empty');
  for (const id of ids) {
    const r = byId.get(id);
    if (!isMissing(r)) continue;
    const standIn = records.find(f => f.fallbackFor === r.id);
    const standInHasData = !!standIn && DATA_PRESENT_STATUSES.includes(standIn.status) && (standIn.rows ?? 1) > 0;
    add(r, standInHasData ? `${standIn!.name}, ${standIn!.version ?? 'version unknown'}` : undefined);
    if (isMissing(standIn)) add(standIn);
  }
  return missing;
}

/**
 * The shared view banner (E1.3): on any route, names each source that route reads
 * (route-sources.ts) when its SourceRecord is 'failed' or 'empty'. The two are told
 * apart: a failed source "did not load", with the recorded reason, and the link offers
 * data health and Retry; an empty source answered but nothing usable could be read
 * from it, under "Incomplete data",
 * with no Retry (the request itself worked; data health still lists it). It renders
 * nothing while every source the route reads is loaded, loading or not requested.
 */
@Component({
  selector: 'app-source-banner',
  standalone: true,
  imports: [RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (failed.length || empty.length) {
      <div class="source-banner" role="status" data-testid="source-banner">
        @if (failed.length) {
          <div class="sb-group" data-testid="source-banner-failed">
            <span class="sb-label">Missing data</span>
            <div class="sb-text">
              {{ failed.length === 1 ? 'A source this view reads did not load:' : failed.length + ' sources this view reads did not load:' }}
              @for (m of failed; track m.id; let last = $last) {
                <span class="sb-source" [attr.data-source-id]="m.id" data-status="failed" [title]="m.detail"
                  ><span class="sb-name">{{ m.name }} (failed)</span>: {{ m.detail }}{{ m.fallback ? '; using ' + m.fallback : '' }}{{ last ? '.' : ' | ' }}</span>
              }
              Results that use them are incomplete.
            </div>
            <a class="sb-link" routerLink="/status">Data health and Retry</a>
          </div>
        }
        @if (empty.length) {
          <div class="sb-group" data-testid="source-banner-empty">
            <span class="sb-label">Incomplete data</span>
            <div class="sb-text">
              {{ empty.length === 1
                ? 'A source this view reads ' + emptyDetail + ':'
                : 'Each of these ' + empty.length + ' sources this view reads ' + emptyDetail + ':' }}
              @for (m of empty; track m.id; let last = $last) {
                <span class="sb-source" [attr.data-source-id]="m.id" data-status="empty" [title]="m.detail"
                  ><span class="sb-name">{{ m.name }}</span>{{ last ? '.' : ', ' }}</span>
              }
              Results that use them are incomplete.
            </div>
            @if (!failed.length) {
              <a class="sb-link" routerLink="/status">Data health</a>
            }
          </div>
        }
      </div>
    }
  `,
  styles: [`
    :host { display: block; flex-shrink: 0; }
    .source-banner {
      display: flex;
      flex-direction: column;
      gap: var(--space-1);
      margin: var(--space-2) var(--space-3);
      padding: var(--space-2) var(--space-3);
      border: 1px solid var(--border-subtle);
      border-left: 3px solid var(--warning);
      border-radius: var(--radius-md);
      background: var(--bg-raised);
      color: var(--text-primary);
      font-size: var(--text-sm);
      line-height: 1.45;
    }
    .sb-group {
      display: flex;
      align-items: baseline;
      flex-wrap: wrap;
      gap: var(--space-1) var(--space-3);
      min-width: 0;
    }
    .sb-label {
      font-weight: 650;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      font-size: var(--text-xs);
    }
    .sb-text {
      flex: 1 1 24rem;
      min-width: 0;
      max-height: 4.5em;
      overflow-y: auto;
      overflow-wrap: anywhere;
    }
    .sb-name { font-weight: 600; }
    .sb-link {
      color: var(--text-primary);
      text-decoration: underline;
      white-space: nowrap;
    }
  `],
})
export class SourceBannerComponent implements OnInit {
  private readonly router = inject(Router);
  private readonly registry = inject(SourceRegistryService);
  private readonly data = inject(DataService);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly destroyRef = inject(DestroyRef);

  /** The lead of the empty group. */
  readonly emptyDetail = EMPTY_SOURCE_DETAIL;

  missing: MissingSource[] = [];
  /** Sources that did not load: shown with their reason and a Retry link. */
  failed: MissingSource[] = [];
  /** Sources that answered with nothing usable: shown apart, with no Retry. */
  empty: MissingSource[] = [];

  ngOnInit(): void {
    const url$ = this.router.events.pipe(
      filter((e): e is NavigationEnd => e instanceof NavigationEnd),
      map(e => e.urlAfterRedirects),
      startWith(this.router.url),
    );
    combineLatest([url$, this.data.currentDomain$, this.registry.records$])
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(([url, domain, records]) => {
        this.missing = missingSources(sourcesForRoute(url, domain), records);
        this.failed = this.missing.filter(m => m.status === 'failed');
        this.empty = this.missing.filter(m => m.status === 'empty');
        this.cdr.markForCheck();
      });
  }
}
