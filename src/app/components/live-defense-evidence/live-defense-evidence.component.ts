// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The Live Defense cell-detail panel. When the Live Defense lens is active and a
// technique it heats is selected, it shows why: the 0-100 heat with its confidence
// badge and recency/ransomware breakdown, a plain-language cite-or-abstain brief, an
// "updated <date>" stamp, and the KEV CVEs behind the number — each with its id, CISA
// KEV name (quoted), date added, ransomware flag and a link. It renders only under the
// Live Defense lens (it does not change the drawer for other lenses) and shows nothing
// for a technique the lens does not heat (fail quiet). It reports KEV exploitation
// pressure as of the pinned snapshot, never a posture.
import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import type { Technique } from '../../models/technique';
import { DEFAULT_HEATMAP_MODE, FilterService } from '../../services/filter.service';
import { LiveDefenseService, type LiveDefenseEvidence } from '../../services/live-defense.service';

@Component({
  selector: 'app-live-defense-evidence',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (evidence(); as ev) {
      <section class="ld" aria-label="Live Defense evidence">
        <header class="ld-head">
          <span class="ld-title">Live Defense</span>
          <span class="ld-badge" [class.ld-high]="ev.confidence === 'high'">{{ ev.confidence }} confidence</span>
        </header>

        <div class="ld-heat">
          <span class="ld-score">{{ ev.score }}</span><span class="ld-of">/100</span>
          <span class="ld-rank">KEV exploitation pressure · rank {{ ev.rank }}</span>
        </div>

        <p class="ld-brief">{{ ev.brief }}</p>

        <dl class="ld-breakdown">
          <div><dt>KEV CVEs mapped</dt><dd>{{ ev.itemCount }}</dd></div>
          <div><dt>Ransomware-linked</dt><dd>{{ ev.ransomwareCount }}</dd></div>
          <div><dt>Recency half-life</dt><dd>{{ ev.breakdown.halfLifeDays }} days</dd></div>
          <div><dt>Updated</dt><dd>{{ ev.breakdown.asOf }}</dd></div>
        </dl>

        <p class="ld-sources-note">
          Showing {{ ev.breakdown.itemsShown }} of {{ ev.itemCount }} sourced CVEs (newest and heaviest first).
        </p>
        <ul class="ld-items">
          @for (it of ev.items; track it.cve) {
            <li class="ld-item">
              <a class="ld-cve" [href]="it.url" target="_blank" rel="noopener noreferrer"
                 [attr.aria-label]="it.cve + ' on NVD (opens in a new tab)'">{{ it.cve }}</a>
              <span class="ld-date">added {{ it.dateAdded }}</span>
              @if (it.knownRansomware) { <span class="ld-ransom" title="CISA: known ransomware campaign use">ransomware</span> }
              <span class="ld-item-conf">{{ it.confidence }}</span>
              <span class="ld-quote">“{{ it.quote }}”</span>
            </li>
          }
        </ul>

        <footer class="ld-foot">
          Sourced from the CISA Known Exploited Vulnerabilities catalogue (CC0), as of the pinned snapshot; mapped by
          exploitation weakness (CWE). KEV exploitation pressure, not a statement about your defensive posture.
          Links open on NVD in a new tab.
        </footer>
      </section>
    }
  `,
  styles: [`
    .ld { margin: 0.5rem 0; padding: 0.6rem 0.75rem; border: 1px solid var(--border-default);
          border-radius: 6px; background: var(--bg-raised); color: var(--text-primary); font-size: 0.82rem; }
    .ld-head { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }
    .ld-title { font-weight: 600; letter-spacing: 0.02em; color: var(--text-primary); }
    .ld-badge { font-size: 0.7rem; padding: 0.1rem 0.45rem; border-radius: 999px; text-transform: lowercase;
                background: var(--bg-active); color: var(--text-secondary); border: 1px solid var(--border-default); }
    .ld-badge.ld-high { color: var(--text-primary); border-color: var(--accent); }
    .ld-heat { display: flex; align-items: baseline; gap: 0.35rem; margin: 0.4rem 0; }
    .ld-score { font-size: 1.6rem; font-weight: 700; color: var(--accent); line-height: 1; }
    .ld-of { color: var(--text-muted); }
    .ld-rank { margin-left: auto; font-size: 0.72rem; color: var(--text-secondary); }
    .ld-brief { margin: 0.3rem 0 0.5rem; line-height: 1.45; color: var(--text-primary); }
    .ld-breakdown { display: grid; grid-template-columns: 1fr 1fr; gap: 0.2rem 0.75rem; margin: 0.4rem 0; }
    .ld-breakdown > div { display: flex; justify-content: space-between; gap: 0.5rem; }
    .ld-breakdown dt { color: var(--text-muted); margin: 0; }
    .ld-breakdown dd { margin: 0; font-variant-numeric: tabular-nums; font-weight: 600; color: var(--text-primary); }
    .ld-sources-note { font-size: 0.72rem; color: var(--text-muted); margin: 0.4rem 0 0.2rem; }
    .ld-items { list-style: none; margin: 0; padding: 0; max-height: 15rem; overflow-y: auto; }
    .ld-item { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.35rem;
               padding: 0.25rem 0; border-top: 1px solid var(--border-subtle); }
    .ld-cve { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 600; color: var(--accent); }
    .ld-date { font-size: 0.72rem; color: var(--text-muted); }
    .ld-ransom { font-size: 0.68rem; padding: 0 0.3rem; border-radius: 3px;
                 background: var(--bg-active); color: var(--danger); border: 1px solid var(--danger); }
    .ld-item-conf { font-size: 0.68rem; color: var(--text-muted); text-transform: lowercase; }
    .ld-quote { flex-basis: 100%; font-size: 0.74rem; color: var(--text-secondary); font-style: italic; }
    .ld-foot { margin-top: 0.5rem; font-size: 0.7rem; color: var(--text-muted); line-height: 1.4; }
  `],
})
export class LiveDefenseEvidenceComponent {
  private readonly liveDefense = inject(LiveDefenseService);
  private readonly filter = inject(FilterService);
  /** Recompute once the artifacts finish loading, even if a technique was selected first. */
  private readonly loaded = toSignal(this.liveDefense.loaded$, { initialValue: false });
  /** Only render under the Live Defense lens, so the drawer is unchanged for other lenses. */
  private readonly mode = toSignal(this.filter.heatmapMode$, { initialValue: DEFAULT_HEATMAP_MODE });
  readonly technique = input<Technique | null>(null);

  readonly evidence = computed<LiveDefenseEvidence | null>(() => {
    if (this.mode() !== 'live-defense') return null;
    this.loaded();
    const t = this.technique();
    return t ? this.liveDefense.getEvidence(t.attackId) : null;
  });
}
