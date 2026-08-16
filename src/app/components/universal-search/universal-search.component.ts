// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef, ElementRef, ViewChild } from '@angular/core';

import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { debounceTime, distinctUntilChanged, Subject } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { CommandPaletteService } from '../../services/command-palette.service';
import { HelpOverlayService } from '../../services/help-overlay.service';
import { ThemeService } from '../../services/theme.service';
import { UrlStateService } from '../../services/url-state.service';
import { ExportActionsService } from '../../services/export-actions.service';
import { NAV_COMMANDS, ACTION_COMMANDS } from '../../models/palette-commands';
import { DataService } from '../../services/data.service';
import { D3fendService } from '../../services/d3fend.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { EngageService } from '../../services/engage.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { Domain } from '../../models/domain';
import { Technique } from '../../models/technique';
import { Mitigation } from '../../models/mitigation';

type ResultKind = 'technique' | 'mitigation' | 'd3fend' | 'car' | 'atomic' | 'engage' | 'group' | 'software' | 'campaign' | 'cve' | 'nav' | 'action';

interface SearchResult {
  kind: ResultKind;
  id: string;
  name: string;
  description?: string;
  url?: string;
  score: number;
  data?: any;
  /** [start, end) ranges of the query match within `name`, for highlighting. */
  nameMatch?: [number, number] | null;
}

/** Frecency store: how often + how recently each result was chosen. */
interface FrecencyEntry { count: number; last: number; }
const FRECENCY_KEY = 'palette-frecency-v1';
const FRECENCY_MAX_ENTRIES = 200;
/** Half-life of the recency boost: ~7 days. */
const FRECENCY_HALF_LIFE_MS = 7 * 24 * 60 * 60 * 1000;

@Component({
  selector: 'app-universal-search',
  standalone: true,
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './universal-search.component.html',
  styleUrl: './universal-search.component.scss',
})
export class UniversalSearchComponent implements OnInit, OnDestroy {
  @ViewChild('searchInput') searchInputRef!: ElementRef<HTMLInputElement>;

  open = false;
  query = '';
  results: SearchResult[] = [];
  activeKindFilter: ResultKind | 'all' = 'all';
  activeResultIndex = -1;
  domain: Domain | null = null;
  private search$ = new Subject<string>();
  private subs = new Subscription();

  readonly kindFilterOptions: (ResultKind | 'all')[] = ['all', 'nav', 'action', 'technique', 'mitigation', 'cve', 'group', 'campaign', 'software', 'd3fend', 'car', 'atomic', 'engage'];
  readonly kindLabels: Record<ResultKind | 'all', string> = {
    all: 'All', nav: 'Go to', action: 'Actions',
    technique: 'Techniques', mitigation: 'Mitigations',
    cve: 'CVEs', d3fend: 'D3FEND', car: 'CAR', atomic: 'Atomic',
    engage: 'Engage', group: 'Groups', software: 'Software',
    campaign: 'Campaigns',
  };

  constructor(
    private filterService: FilterService,
    private panelNav: PanelNavService,
    private palette: CommandPaletteService,
    private helpOverlay: HelpOverlayService,
    private themeService: ThemeService,
    private urlStateService: UrlStateService,
    private exportActions: ExportActionsService,
    private dataService: DataService,
    private d3fendService: D3fendService,
    private carService: CARService,
    private atomicService: AtomicService,
    private engageService: EngageService,
    private attackCveService: AttackCveService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(this.palette.open$.subscribe(open => {
      this.open = open;
      if (!this.open) {
        this.query = '';
        this.results = [];
      } else {
        // Freshly opened with an empty box: offer recent destinations.
        this.runSearch('');
      }
      this.cdr.markForCheck();
    }));
    this.subs.add(this.dataService.domain$.subscribe(d => { this.domain = d; }));
    this.subs.add(this.search$.pipe(debounceTime(150), distinctUntilChanged()).subscribe(q => this.runSearch(q)));
  }

  onInput(): void {
    this.activeResultIndex = -1;
    this.search$.next(this.query);
  }

  // ── Frecency (frequent + recent selections rank higher) ─────────────────

  private frecency: Record<string, FrecencyEntry> = this.loadFrecency();

  private loadFrecency(): Record<string, FrecencyEntry> {
    try {
      return JSON.parse(localStorage.getItem(FRECENCY_KEY) ?? '{}');
    } catch {
      return {};
    }
  }

  private frecencyBoost(kind: ResultKind, id: string): number {
    const entry = this.frecency[`${kind}:${id}`];
    if (!entry) return 0;
    // Up to +30 for a frequently used item, decaying with ~7-day half-life —
    // enough to break ties and float favorites, never enough to beat an
    // exact-match score (100).
    const decay = Math.pow(2, -(Date.now() - entry.last) / FRECENCY_HALF_LIFE_MS);
    return Math.min(30, entry.count * 6) * decay;
  }

  private recordUse(r: SearchResult): void {
    const key = `${r.kind}:${r.id}`;
    const entry = this.frecency[key] ?? { count: 0, last: 0 };
    entry.count += 1;
    entry.last = Date.now();
    this.frecency[key] = entry;
    const keys = Object.keys(this.frecency);
    if (keys.length > FRECENCY_MAX_ENTRIES) {
      // Evict the stalest, least-used entries.
      keys
        .sort((a, b) => (this.frecency[a].count - this.frecency[b].count) || (this.frecency[a].last - this.frecency[b].last))
        .slice(0, keys.length - FRECENCY_MAX_ENTRIES)
        .forEach(k => delete this.frecency[k]);
    }
    try {
      localStorage.setItem(FRECENCY_KEY, JSON.stringify(this.frecency));
    } catch { /* storage unavailable */ }
  }

  /** With an empty query, surface the user's most-frecent destinations. */
  private buildRecentResults(): SearchResult[] {
    const entries = Object.entries(this.frecency)
      .sort((a, b) => (this.frecencyBoostFromEntry(b[1])) - (this.frecencyBoostFromEntry(a[1])))
      .slice(0, 10);
    const out: SearchResult[] = [];
    for (const [key] of entries) {
      const sep = key.indexOf(':');
      const kind = key.slice(0, sep) as ResultKind;
      const id = key.slice(sep + 1);
      const resolved = this.resolveResult(kind, id);
      if (resolved) out.push(resolved);
    }
    return out;
  }

  private frecencyBoostFromEntry(entry: FrecencyEntry): number {
    const decay = Math.pow(2, -(Date.now() - entry.last) / FRECENCY_HALF_LIFE_MS);
    return Math.min(30, entry.count * 6) * decay;
  }

  /** Rebuild a SearchResult for a frecency key (recent-items list). */
  private resolveResult(kind: ResultKind, id: string): SearchResult | null {
    if (kind === 'nav') {
      const nav = NAV_COMMANDS.find(n => n.panelId === id);
      return nav ? { kind, id, name: nav.label, description: `Go to ${nav.workspace}`, score: 0, data: nav } : null;
    }
    if (kind === 'action') {
      const action = ACTION_COMMANDS.find(a => a.id === id);
      return action ? { kind, id, name: action.label, description: action.description, score: 0, data: action } : null;
    }
    if (!this.domain) return null;
    if (kind === 'technique') {
      const t = this.domain.techniques.find(x => x.attackId === id);
      return t ? { kind, id, name: t.name, description: t.description?.substring(0, 100), url: t.url, score: 0, data: t } : null;
    }
    if (kind === 'mitigation') {
      const m = this.domain.mitigations.find(x => x.attackId === id);
      return m ? { kind, id, name: m.name, description: m.description?.substring(0, 100), url: m.url, score: 0, data: m } : null;
    }
    if (kind === 'group') {
      const g = this.domain.groups.find(x => x.attackId === id);
      return g ? { kind, id, name: g.name, description: (g.aliases ?? []).join(', '), score: 0, data: g } : null;
    }
    if (kind === 'software') {
      const s = this.domain.software.find(x => x.attackId === id);
      return s ? { kind, id, name: s.name, description: s.description?.substring(0, 80), score: 0, data: s } : null;
    }
    return null; // other kinds aren't resolvable without a query
  }

  /** [start, end) of the query within name, for match highlighting. */
  private matchRange(q: string, name: string): [number, number] | null {
    const idx = name.toLowerCase().indexOf(q);
    return idx >= 0 ? [idx, idx + q.length] : null;
  }

  /** Subsequence fuzzy match: checks if all chars of query appear in order in text */
  fuzzyMatch(query: string, text: string): boolean {
    const ql = query.toLowerCase();
    const tl = text.toLowerCase();
    let qi = 0;
    for (let ti = 0; ti < tl.length && qi < ql.length; ti++) {
      if (tl[ti] === ql[qi]) qi++;
    }
    return qi === ql.length;
  }

  onResultKeydown(event: KeyboardEvent): void {
    const visible = this.filteredResults;
    if (!visible.length) return;

    if (event.key === 'ArrowDown') {
      event.preventDefault();
      this.activeResultIndex = Math.min(this.activeResultIndex + 1, visible.length - 1);
      this.scrollActiveIntoView();
      this.cdr.markForCheck();
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      this.activeResultIndex = Math.max(this.activeResultIndex - 1, -1);
      if (this.activeResultIndex === -1 && this.searchInputRef) {
        this.searchInputRef.nativeElement.focus();
      } else {
        this.scrollActiveIntoView();
      }
      this.cdr.markForCheck();
    } else if (event.key === 'Enter') {
      event.preventDefault();
      if (this.activeResultIndex >= 0 && this.activeResultIndex < visible.length) {
        this.selectResult(visible[this.activeResultIndex]);
      }
    }
  }

  private scrollActiveIntoView(): void {
    setTimeout(() => {
      const el = document.querySelector('.us-result.active-result');
      if (el) el.scrollIntoView({ block: 'nearest' });
    });
  }

  private runSearch(q: string): void {
    if (!q) {
      // Empty palette: show the user's most-used destinations.
      this.results = this.buildRecentResults();
      this.activeResultIndex = -1;
      this.cdr.markForCheck();
      return;
    }
    if (q.length < 2) { this.results = []; this.activeResultIndex = -1; this.cdr.markForCheck(); return; }
    const ql = q.toLowerCase();
    const results: SearchResult[] = [];

    // Navigation commands ("Go to …") — boosted so destinations beat entities
    // on name matches ("dashboard", "gap analysis", "export").
    for (const nav of NAV_COMMANDS) {
      const score = this.score(ql, nav.panelId, nav.label, `${nav.workspace} ${nav.keywords ?? ''}`);
      if (score > 0) {
        results.push({ kind: 'nav', id: nav.panelId, name: nav.label, description: `Go to ${nav.workspace}`, score: score + 15, data: nav });
      }
    }

    // Action commands ("Do …")
    for (const action of ACTION_COMMANDS) {
      const score = this.score(ql, action.id, action.label, `${action.description} ${action.keywords ?? ''}`);
      if (score > 0) {
        results.push({ kind: 'action', id: action.id, name: action.label, description: action.description, score: score + 10, data: action });
      }
    }

    if (this.domain) {
      // Techniques
      for (const t of this.domain.techniques) {
        const score = this.score(ql, t.attackId, t.name, t.description ?? '');
        if (score > 0) results.push({ kind: 'technique', id: t.attackId, name: t.name, description: t.description?.substring(0, 100), url: t.url, score, data: t });
      }
      // Mitigations
      for (const m of this.domain.mitigations) {
        const score = this.score(ql, m.attackId, m.name, m.description ?? '');
        if (score > 0) results.push({ kind: 'mitigation', id: m.attackId, name: m.name, description: m.description?.substring(0, 100), url: m.url, score, data: m });
      }
      // Groups
      for (const g of this.domain.groups) {
        const score = this.score(ql, g.attackId, g.name, (g.aliases ?? []).join(' '));
        if (score > 0) results.push({ kind: 'group', id: g.attackId, name: g.name, description: (g.aliases ?? []).join(', '), score, data: g });
      }
      // Campaigns
      if (this.domain.campaigns) {
        for (const c of this.domain.campaigns) {
          const score = this.score(ql, c.attackId, c.name, c.description ?? '');
          if (score > 0) results.push({ kind: 'campaign', id: c.attackId, name: c.name, description: c.description?.substring(0, 100), score, data: c });
        }
      }
      // Software
      for (const s of this.domain.software) {
        const score = this.score(ql, s.attackId, s.name, s.description ?? '');
        if (score > 0) results.push({ kind: 'software', id: s.attackId, name: s.name, description: s.description?.substring(0, 80), url: `https://attack.mitre.org/software/${s.attackId}`, score, data: s });
      }
    }

    // D3FEND
    for (const d of this.d3fendService.getAllTechniques()) {
      const score = this.score(ql, d.id, d.name, d.definition);
      if (score > 0) results.push({ kind: 'd3fend', id: d.id, name: d.name, description: d.definition, url: d.url, score });
    }

    // CAR
    for (const c of this.carService.getAll()) {
      const score = this.score(ql, c.id, c.name, c.description);
      if (score > 0) results.push({ kind: 'car', id: c.id, name: c.name, description: c.description, url: c.url, score });
    }

    // Atomic
    const seen = new Set<string>();
    for (const a of this.atomicService.getAll()) {
      const key = a.attackId + '|' + a.name;
      if (seen.has(key)) continue; seen.add(key);
      const score = this.score(ql, a.attackId, a.name, a.platforms.join(' '));
      if (score > 0) results.push({ kind: 'atomic', id: a.attackId, name: a.name, description: `Platforms: ${a.platforms.join(', ')}`, url: a.url, score });
    }

    // Engage
    const seenE = new Set<string>();
    for (const [, acts] of (this.engageService as any).byAttackId) {
      for (const act of acts as any[]) {
        if (seenE.has(act.id)) continue; seenE.add(act.id);
        const score = this.score(ql, act.id, act.name, act.definition);
        if (score > 0) results.push({ kind: 'engage', id: act.id, name: act.name, description: act.definition, url: act.url, score });
      }
    }

    // CVE (search CTID mappings by CVE ID, description, or capability group)
    const cveResults = this.attackCveService.searchCves(q);
    for (const m of cveResults) {
      const desc = m.description ? m.description.substring(0, 100) : (m.capabilityGroup ? `Category: ${m.capabilityGroup.replace(/_/g, ' ')}` : '');
      const score = this.score(ql, m.cveId, m.cveId, m.description + ' ' + m.capabilityGroup);
      results.push({ kind: 'cve', id: m.cveId, name: m.cveId, description: desc, url: `https://nvd.nist.gov/vuln/detail/${m.cveId}`, score: Math.max(score, 50), data: m });
    }

    // Frecency: recently/frequently chosen items float upward, then compute
    // match-highlight ranges for what survives the cut.
    this.results = results
      .sort((a, b) => (b.score + this.frecencyBoost(b.kind, b.id)) - (a.score + this.frecencyBoost(a.kind, a.id)))
      .slice(0, 60)
      .map(r => ({ ...r, nameMatch: this.matchRange(ql, r.name) }));
    this.activeResultIndex = -1;
    this.cdr.markForCheck();
  }

  private score(q: string, id: string, name: string, desc: string): number {
    const idL = id.toLowerCase(), nameL = name.toLowerCase(), descL = desc.toLowerCase();
    if (idL === q || nameL === q) return 100;
    if (idL.startsWith(q) || nameL.startsWith(q)) return 80;
    if (nameL.includes(q)) return 60;
    if (descL.includes(q)) return 40;
    // Fuzzy subsequence match on name or id
    if (this.fuzzyMatch(q, nameL) || this.fuzzyMatch(q, idL)) return 30;
    return 0;
  }

  get filteredResults(): SearchResult[] {
    return this.activeKindFilter === 'all' ? this.results : this.results.filter(r => r.kind === this.activeKindFilter);
  }

  get kindCounts(): Record<string, number> {
    const counts: Record<string, number> = { all: this.results.length };
    for (const r of this.results) counts[r.kind] = (counts[r.kind] ?? 0) + 1;
    return counts;
  }

  selectResult(r: SearchResult): void {
    this.recordUse(r);
    if (r.kind === 'nav') {
      this.panelNav.open(r.id);
      this.close();
    } else if (r.kind === 'action') {
      this.runAction(r.id);
      this.close();
    } else if (r.kind === 'technique' && r.data) {
      this.filterService.selectTechnique(r.data);
      this.close();
    } else if (r.kind === 'mitigation' && r.data) {
      this.filterService.filterByMitigation(r.data);
      this.close();
    } else if (r.kind === 'group' && r.data) {
      this.filterService.toggleThreatGroup(r.data.id);
      this.panelNav.open('threats');
      this.close();
    } else if (r.kind === 'campaign' && r.data) {
      this.filterService.toggleCampaign(r.data.id);
      this.close();
    } else if (r.kind === 'software' && r.data) {
      this.panelNav.open('software');
      this.close();
    } else if (r.kind === 'cve') {
      this.panelNav.open('cve');
      this.close();
    } else if (r.url) {
      window.open(r.url, '_blank', 'noopener');
    }
  }

  private runAction(id: string): void {
    switch (id) {
      case 'toggle-theme': this.themeService.toggle(); break;
      case 'clear-filters': this.filterService.clearAll(); break;
      case 'copy-share-link':
        void navigator.clipboard.writeText(this.urlStateService.getShareUrl());
        break;
      case 'keyboard-help': this.helpOverlay.open(); break;
      case 'export-csv': this.exportActions.exportCsv(); break;
      case 'export-xlsx': void this.exportActions.exportXlsxWorkbook(); break;
      case 'export-navigator': this.exportActions.exportNavigatorLayer(); break;
      case 'open-navigator': this.exportActions.openInNavigator(); break;
    }
  }

  kindIcon(kind: ResultKind): string {
    const icons: Record<ResultKind, string> = { nav: '→', action: '⚡', technique: '⚔', mitigation: '🛡', d3fend: '🛡', car: '🔬', atomic: '⚛', engage: '🎭', group: '👥', software: '🛠', campaign: '🎯', cve: '🔴' };
    return icons[kind];
  }

  kindColor(kind: ResultKind): string {
    const colors: Record<ResultKind, string> = { nav: '#6fd3ff', action: '#fbbf24', technique: '#58a6ff', mitigation: '#4caf50', d3fend: '#4caf50', car: '#58a6ff', atomic: '#e08030', engage: '#f0a040', group: '#9c70e0', software: '#f06060', campaign: '#e06090', cve: '#ef4444' };
    return colors[kind];
  }

  close(): void { this.palette.close(); }
  ngOnDestroy(): void { this.subs.unsubscribe(); }
}
