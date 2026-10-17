// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, ChangeDetectorRef, Component, DestroyRef, OnInit, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router, RouterLink } from '@angular/router';
import { combineLatest, filter, map, startWith } from 'rxjs';
import { SourceRecord } from '../../models/source-record';
import { DataService } from '../../services/data.service';
import { SourceRegistryService } from '../../services/source-registry.service';
import { sourcesForRoute } from '../../services/route-sources';

/** A source this view reads that did not load. */
export interface MissingSource {
  id: string;
  name: string;
  status: 'failed' | 'empty';
  /** Why: the recorded error, or what 'empty' means. */
  detail: string;
}

/** The sources a route reads that are failed or empty right now, in the route's order. */
export function missingSources(ids: readonly string[], records: readonly SourceRecord[]): MissingSource[] {
  const byId = new Map(records.map(r => [r.id, r]));
  const missing: MissingSource[] = [];
  for (const id of ids) {
    const r = byId.get(id);
    if (!r || (r.status !== 'failed' && r.status !== 'empty')) continue;
    missing.push({
      id: r.id,
      name: r.name,
      status: r.status,
      detail: r.status === 'failed' ? (r.lastError ?? 'the request failed') : 'the source answered with no usable rows',
    });
  }
  return missing;
}

/**
 * The shared view banner (E1.3): on any route, names each source that route reads
 * (route-sources.ts) when its SourceRecord is 'failed' or 'empty', with the reason,
 * and links to the data-health view where each source has a Retry. It renders
 * nothing while every source the route reads is loaded, loading or not requested.
 */
@Component({
  selector: 'app-source-banner',
  standalone: true,
  imports: [RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (missing.length) {
      <div class="source-banner" role="status" data-testid="source-banner">
        <span class="sb-label">Missing data</span>
        <span class="sb-text">
          {{ missing.length === 1 ? 'A source this view reads did not load:' : missing.length + ' sources this view reads did not load:' }}
          @for (m of missing; track m.id; let last = $last) {
            <span class="sb-source" [attr.data-source-id]="m.id" [attr.data-status]="m.status" [title]="m.detail"
              >{{ m.name }} ({{ m.status }}){{ last ? '. ' : ', ' }}</span>
          }
          Results that use them are incomplete.
        </span>
        <a class="sb-link" routerLink="/status">Data health and Retry</a>
      </div>
    }
  `,
  styles: [`
    :host { display: block; flex-shrink: 0; }
    .source-banner {
      display: flex;
      align-items: baseline;
      flex-wrap: wrap;
      gap: var(--space-1) var(--space-3);
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
    }
    .sb-source { font-weight: 600; }
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

  missing: MissingSource[] = [];

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
        this.cdr.markForCheck();
      });
  }
}
