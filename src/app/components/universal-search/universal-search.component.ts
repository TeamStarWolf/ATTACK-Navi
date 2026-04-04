import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef, HostListener, ElementRef, ViewChild } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { debounceTime, distinctUntilChanged, Subject } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { D3fendService } from '../../services/d3fend.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { EngageService } from '../../services/engage.service';
import { Domain } from '../../models/domain';
import { Technique } from '../../models/technique';
import { Mitigation } from '../../models/mitigation';

type ResultKind = 'technique' | 'mitigation' | 'd3fend' | 'car' | 'atomic' | 'engage' | 'group' | 'software' | 'campaign';

interface SearchResult {
  kind: ResultKind;
  id: string;
  name: string;
  description?: string;
  url?: string;
  score: number;
  data?: any;
}

@Component({
  selector: 'app-universal-search',
  standalone: true,
  imports: [CommonModule, FormsModule],
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

  readonly kindFilterOptions: (ResultKind | 'all')[] = ['all', 'technique', 'mitigation', 'group', 'campaign', 'software', 'd3fend', 'car', 'atomic', 'engage'];
  readonly kindLabels: Record<ResultKind | 'all', string> = {
    all: 'All', technique: '⚔ Techniques', mitigation: '🛡 Mitigations',
    d3fend: '🛡 D3FEND', car: '🔬 CAR', atomic: '⚛ Atomic',
    engage: '🎭 Engage', group: '👥 Groups', software: '🛠 Software',
    campaign: '🎯 Campaigns',
  };

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private d3fendService: D3fendService,
    private carService: CARService,
    private atomicService: AtomicService,
    private engageService: EngageService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(this.filterService.activePanel$.subscribe(panel => {
      this.open = (panel as string) === 'search';
      if (!this.open) { this.query = ''; this.results = []; }
      this.cdr.markForCheck();
    }));
    this.subs.add(this.dataService.domain$.subscribe(d => { this.domain = d; }));
    this.subs.add(this.search$.pipe(debounceTime(150), distinctUntilChanged()).subscribe(q => this.runSearch(q)));
  }

  @HostListener('document:keydown', ['$event'])
  onKey(e: KeyboardEvent): void {
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'f') {
      e.preventDefault();
      this.filterService.togglePanel('search' as any);
    }
    if (e.key === 'Escape' && this.open) this.close();
  }

  onInput(): void {
    this.activeResultIndex = -1;
    this.search$.next(this.query);
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
    if (!q || q.length < 2) { this.results = []; this.activeResultIndex = -1; this.cdr.markForCheck(); return; }
    const ql = q.toLowerCase();
    const results: SearchResult[] = [];

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

    this.results = results.sort((a, b) => b.score - a.score).slice(0, 60);
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
    if (r.kind === 'technique' && r.data) {
      this.filterService.selectTechnique(r.data);
      this.close();
    } else if (r.kind === 'mitigation' && r.data) {
      this.filterService.filterByMitigation(r.data);
      this.close();
    } else if (r.kind === 'group' && r.data) {
      this.filterService.toggleThreatGroup(r.data.id);
      this.filterService.setActivePanel('threats');
    } else if (r.kind === 'campaign' && r.data) {
      this.filterService.toggleCampaign(r.data.id);
      this.close();
    } else if (r.kind === 'software' && r.data) {
      this.filterService.setActivePanel('software');
      this.close();
    } else if (r.url) {
      window.open(r.url, '_blank', 'noopener');
    }
  }

  kindIcon(kind: ResultKind): string {
    const icons: Record<ResultKind, string> = { technique: '⚔', mitigation: '🛡', d3fend: '🛡', car: '🔬', atomic: '⚛', engage: '🎭', group: '👥', software: '🛠', campaign: '🎯' };
    return icons[kind];
  }

  kindColor(kind: ResultKind): string {
    const colors: Record<ResultKind, string> = { technique: '#58a6ff', mitigation: '#4caf50', d3fend: '#4caf50', car: '#58a6ff', atomic: '#e08030', engage: '#f0a040', group: '#9c70e0', software: '#f06060', campaign: '#e06090' };
    return colors[kind];
  }

  close(): void { this.filterService.setActivePanel(null); }
  ngOnDestroy(): void { this.subs.unsubscribe(); }
}
