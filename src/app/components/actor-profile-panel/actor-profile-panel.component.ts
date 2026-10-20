// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef, Signal, inject } from '@angular/core';

import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { DataService } from '../../services/data.service';
import { GraphFocusService } from '../../services/graph-focus.service';
import { PostureService } from '../../services/posture.service';
import { postureBadge } from '../../models/posture/posture-vocabulary';
import type { PostureBucket, PostureTally } from '../../models/posture/posture.types';
import { ThreatGroup } from '../../models/group';
import { AttackSoftware } from '../../models/software';
import { Campaign } from '../../models/campaign';
import { Technique } from '../../models/technique';
import { Domain } from '../../models/domain';

interface GroupProfile {
  group: ThreatGroup;
  techniques: Technique[];
  software: AttackSoftware[];
  campaigns: Campaign[];
  tacticBreakdown: { tactic: string; count: number }[];
}

/** The row dot of one technique (P2-07): its posture bucket, never a mitigation fold. */
export type TechMark = 'yes' | 'partial' | 'no';

const BUCKET_MARK: Readonly<Record<PostureBucket, TechMark>> = {
  covered: 'yes', proven: 'yes', stale: 'yes', partial: 'partial', known: 'no', none: 'no',
};

const MARK_GLYPH: Readonly<Record<TechMark, string>> = { yes: '✅', partial: '◐', no: '🔴' };

@Component({
  selector: 'app-actor-profile-panel',
  standalone: true,
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './actor-profile-panel.component.html',
  styleUrl: './actor-profile-panel.component.scss',
})
export class ActorProfilePanelComponent implements OnInit, OnDestroy {
  domain: Domain | null = null;
  allGroups: ThreatGroup[] = [];
  filteredGroups: ThreatGroup[] = [];
  selectedProfile: GroupProfile | null = null;
  searchText = '';
  viewTab: 'overview' | 'techniques' | 'software' | 'campaigns' = 'overview';
  private subs = new Subscription();

  private readonly posture = inject(PostureService);
  /** Covered and Proven words render only when the owner has recorded data (§2.4). */
  readonly ownerWords: Signal<boolean> = this.posture.ownerWords;

  constructor(
    private filterService: FilterService,
    private panelNav: PanelNavService,
    private dataService: DataService,
    private graphFocus: GraphFocusService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(this.dataService.domain$.subscribe(domain => {
      this.domain = domain;
      if (domain) this.loadGroups();
      this.cdr.markForCheck();
    }));
  }

  private loadGroups(): void {
    if (!this.domain) return;
    this.allGroups = [...this.domain.groups].sort((a, b) => a.name.localeCompare(b.name));
    this.filterGroups();
  }

  filterGroups(): void {
    const q = this.searchText.toLowerCase();
    this.filteredGroups = q
      ? this.allGroups.filter(g => g.name.toLowerCase().includes(q) || g.attackId.toLowerCase().includes(q) || (g.aliases ?? []).some(a => a.toLowerCase().includes(q)))
      : this.allGroups;
    this.cdr.markForCheck();
  }

  selectGroup(group: ThreatGroup): void {
    const techniques = this.dataService.getTechniquesForGroup(group.id);
    const software = this.dataService.getSoftwareForGroup(group.id);
    const campaigns = this.dataService.getCampaignsForGroup(group.id);

    const tacticMap = new Map<string, number>();
    for (const t of techniques) {
      for (const tac of t.tacticShortnames) {
        tacticMap.set(tac, (tacticMap.get(tac) ?? 0) + 1);
      }
    }
    const tacticBreakdown = [...tacticMap.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([tactic, count]) => ({ tactic, count }));

    this.selectedProfile = { group, techniques, software, campaigns, tacticBreakdown };
    this.viewTab = 'overview';
    this.cdr.markForCheck();
  }

  backToList(): void { this.selectedProfile = null; this.cdr.markForCheck(); }

  filterByGroup(group: ThreatGroup): void {
    this.filterService.toggleThreatGroup(group.id);
    // Show the applied group filter on the matrix.
    this.panelNav.open('matrix');
  }

  /** Pivot to the relationship graph centered on this group. */
  viewInGraph(group: ThreatGroup): void {
    this.graphFocus.focusNode('group', group.id);
    this.panelNav.open('technique-graph');
  }

  selectTechnique(tech: Technique): void {
    this.filterService.selectTechnique(tech);
    // The technique sidebar opens over the matrix — keep the selection we just made.
    this.panelNav.open('matrix', { keepTechniqueSelection: true });
  }

  // ── Posture (S6, P2-07): counts from PostureService.tallyFor, never a
  // percentage. These read signals, so the OnPush template refreshes whenever
  // the posture states change.

  /** The posture tally over the profile's techniques. */
  tallyOf(p: GroupProfile): PostureTally {
    return this.posture.tallyFor(p.techniques);
  }

  /**
   * 'N of M techniques covered (self-attested), K partial' (the design's S6
   * string), where M is the tally's `assessable` (the profile's techniques
   * minus those a not-reproducible run with no proof excludes, R16; the
   * summary's title says so), or on a profile with no owner data
   * 'M techniques; no data of yours recorded'.
   */
  summaryLine(p: GroupProfile): string {
    const m = p.techniques.length;
    if (!this.ownerWords()) return `${m} techniques; no data of yours recorded`;
    const t = this.tallyOf(p);
    return `${t.covered} of ${t.assessable} techniques covered (self-attested), ${t.partial} partial`;
  }

  /**
   * The denominator note on the summary and ring: M counts the assessable
   * techniques, so a not-reproducible exclusion is named rather than hidden.
   * Null on a profile with no owner data.
   */
  denominatorNote(p: GroupProfile): string | null {
    if (!this.ownerWords()) return null;
    const t = this.tallyOf(p);
    const excluded = t.total - t.assessable;
    const base = `Out of ${t.assessable} assessable techniques`;
    return excluded > 0
      ? `${base} (${t.total} total; ${excluded} excluded by a not-reproducible run with no proof)`
      : `${base} (all ${t.total} of this group's techniques)`;
  }

  /** The ring's denominator with owner data: the profile's assessable techniques. */
  ringDenominator(p: GroupProfile): number {
    return this.tallyOf(p).assessable;
  }

  /** The Proven line, its words from the posture vocabulary. */
  provenLine(p: GroupProfile): string {
    const t = this.tallyOf(p);
    const proven = postureBadge({ bucket: 'proven', qualifiers: [], proofScope: null, covered: [] });
    const stale = postureBadge({ bucket: 'stale', qualifiers: [], proofScope: null, covered: [] });
    return `${proven}: ${t.proven} · ${stale}: ${t.stale}`;
  }

  /** The number in the ring: Covered with owner data, else the technique count. */
  ringCount(p: GroupProfile): number {
    return this.ownerWords() ? this.tallyOf(p).covered : p.techniques.length;
  }

  /** The row dot from the technique's posture bucket. */
  getTechCoverage(tech: Technique): TechMark {
    return BUCKET_MARK[this.posture.stateFor(tech).bucket];
  }

  techGlyph(tech: Technique): string {
    return MARK_GLYPH[this.getTechCoverage(tech)];
  }

  /** The partial dot's tooltip (the posture badge); null for the other dots. */
  techTitle(tech: Technique): string | null {
    const state = this.posture.stateFor(tech);
    return state.bucket === 'partial' ? postureBadge(state) : null;
  }

  /** Up to ten techniques without a full mark, most mitigations mapped first. */
  topExposed(p: GroupProfile): Technique[] {
    return p.techniques
      .filter(t => this.getTechCoverage(t) !== 'yes')
      .sort((a, b) => (b.mitigationCount ?? 0) - (a.mitigationCount ?? 0))
      .slice(0, 10);
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }
}
