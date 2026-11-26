// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The Live Defense cell-detail panel. When a technique the Live Defense lens
// heats is selected, it shows why: the 0-100 heat with its confidence badge and
// recency/ransomware breakdown, a plain-language cite-or-abstain brief, an
// "updated <date>" stamp, and the KEV CVEs behind the number — each with its id,
// CISA KEV name (quoted), date added, ransomware flag and a link. A technique the
// lens does not heat shows nothing (fail quiet), so the panel never implies a
// posture; it reports active exploitation pressure, sourced from the KEV catalog.
import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import type { Technique } from '../../models/technique';
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
              <a class="ld-cve" [href]="it.url" target="_blank" rel="noopener noreferrer">{{ it.cve }}</a>
              <span class="ld-date">added {{ it.dateAdded }}</span>
              @if (it.knownRansomware) { <span class="ld-ransom" title="CISA: known ransomware campaign use">ransomware</span> }
              <span class="ld-item-conf">{{ it.confidence }}</span>
              <span class="ld-quote">“{{ it.quote }}”</span>
            </li>
          }
        </ul>

        <footer class="ld-foot">
          Sourced from the CISA Known Exploited Vulnerabilities catalog (CC0); mapped by exploitation weakness (CWE).
          Active exploitation pressure, not a statement about your defensive posture.
        </footer>
      </section>
    }
  `,
  styles: [`
    .ld { margin: 0.5rem 0; padding: 0.6rem 0.75rem; border: 1px solid var(--border, #2b2b3a);
          border-radius: 6px; background: var(--panel-bg, rgba(255,122,24,0.04)); font-size: 0.82rem; }
    .ld-head { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }
    .ld-title { font-weight: 600; letter-spacing: 0.02em; }
    .ld-badge { font-size: 0.7rem; padding: 0.1rem 0.4rem; border-radius: 999px;
                background: rgba(154,42,26,0.25); color: var(--text, #e8e8ef); text-transform: lowercase; }
    .ld-badge.ld-high { background: rgba(255,122,24,0.3); }
    .ld-heat { display: flex; align-items: baseline; gap: 0.35rem; margin: 0.4rem 0; }
    .ld-score { font-size: 1.6rem; font-weight: 700; color: #ff7a18; line-height: 1; }
    .ld-of { opacity: 0.6; }
    .ld-rank { margin-left: auto; font-size: 0.72rem; opacity: 0.8; }
    .ld-brief { margin: 0.3rem 0 0.5rem; line-height: 1.45; }
    .ld-breakdown { display: grid; grid-template-columns: 1fr 1fr; gap: 0.2rem 0.75rem; margin: 0.4rem 0; }
    .ld-breakdown > div { display: flex; justify-content: space-between; gap: 0.5rem; }
    .ld-breakdown dt { opacity: 0.75; margin: 0; }
    .ld-breakdown dd { margin: 0; font-variant-numeric: tabular-nums; font-weight: 600; }
    .ld-sources-note { font-size: 0.72rem; opacity: 0.75; margin: 0.4rem 0 0.2rem; }
    .ld-items { list-style: none; margin: 0; padding: 0; max-height: 15rem; overflow-y: auto; }
    .ld-item { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.35rem;
               padding: 0.25rem 0; border-top: 1px solid var(--border-faint, rgba(255,255,255,0.06)); }
    .ld-cve { font-family: var(--mono, monospace); font-weight: 600; color: var(--accent, #58a6ff); }
    .ld-date { font-size: 0.72rem; opacity: 0.7; }
    .ld-ransom { font-size: 0.68rem; padding: 0 0.3rem; border-radius: 3px;
                 background: rgba(211,47,47,0.25); color: #ffb4b4; }
    .ld-item-conf { font-size: 0.68rem; opacity: 0.6; text-transform: lowercase; }
    .ld-quote { flex-basis: 100%; font-size: 0.74rem; opacity: 0.82; font-style: italic; }
    .ld-foot { margin-top: 0.5rem; font-size: 0.7rem; opacity: 0.7; line-height: 1.4; }
  `],
})
export class LiveDefenseEvidenceComponent {
  private readonly liveDefense = inject(LiveDefenseService);
  /** Recompute once the artifacts finish loading, even if a technique was selected first. */
  private readonly loaded = toSignal(this.liveDefense.loaded$, { initialValue: false });
  readonly technique = input<Technique | null>(null);

  readonly evidence = computed<LiveDefenseEvidence | null>(() => {
    this.loaded();
    const t = this.technique();
    return t ? this.liveDefense.getEvidence(t.attackId) : null;
  });
}
