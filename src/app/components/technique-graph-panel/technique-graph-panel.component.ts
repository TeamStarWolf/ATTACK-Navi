// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  HostListener,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { DataService } from '../../services/data.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { D3fendService } from '../../services/d3fend.service';
import { GraphFocusService, GraphFocus, GraphFocusKind } from '../../services/graph-focus.service';
import { Domain } from '../../models/domain';
import { Technique } from '../../models/technique';

export interface GraphNode {
  id: string;
  label: string;
  sublabel?: string;
  kind: GraphFocusKind;
  x: number;
  y: number;
  pinned?: boolean;
}

/** One neighbour node awaiting radial placement around the focused center. */
interface RingItem {
  id: string;
  label: string;
  sublabel?: string;
  kind: GraphFocusKind;
}

export interface GraphEdge {
  source: string;
  target: string;
  label?: string;
}

interface DragState {
  active: boolean;
  nodeId: string;
  startX: number;
  startY: number;
  nodeStartX: number;
  nodeStartY: number;
}

const KIND_COLORS: Record<GraphNode['kind'], string> = {
  technique:    '#58a6ff',
  subtechnique: '#79c0ff',
  parent:       '#1f6feb',
  mitigation:   '#3fb950',
  group:        '#f78166',
  software:     '#d2a8ff',
  cve:          'var(--accent-warm)',
  campaign:     '#e3b341',
  d3fend:       '#2f81f7',
  capec:        '#db6d28',
};

const KIND_ICONS: Record<GraphNode['kind'], string> = {
  technique:    '⚔',
  subtechnique: '↳',
  parent:       '▲',
  mitigation:   '🛡',
  group:        '👥',
  software:     '🛠',
  cve:          '🔴',
  campaign:     '📅',
  d3fend:       '🧱',
  capec:        '🎯',
};

@Component({
  selector: 'app-technique-graph-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './technique-graph-panel.component.html',
  styleUrl: './technique-graph-panel.component.scss',
})
export class TechniqueGraphPanelComponent implements OnInit, OnDestroy {
  domain: Domain | null = null;
  technique: Technique | null = null;

  /** The entity the graph is currently centered on (technique or otherwise). */
  focus: GraphFocus | null = null;
  /** Back-stack of previous focuses, newest last. */
  focusHistory: GraphFocus[] = [];

  nodes: GraphNode[] = [];
  edges: GraphEdge[] = [];

  // Legend
  readonly kindColors = KIND_COLORS;
  readonly kindIcons = KIND_ICONS;

  // View options
  showMitigations = true;
  showGroups = true;
  showSoftware = true;
  showCves = true;
  showCampaigns = true;
  showD3fend = false;
  showCapec = false;
  showSubtechniques = true;

  // Technique search
  searchQuery = '';
  searchResults: Technique[] = [];
  showSearchDropdown = false;

  // Zoom / pan
  zoomLevel = 1;
  readonly ZOOM_MIN = 0.4;
  readonly ZOOM_MAX = 2.5;
  readonly ZOOM_STEP = 0.15;
  panX = 0;
  panY = 0;
  private isPanning = false;
  private panStartX = 0;
  private panStartY = 0;
  private panNodeStartX = 0;
  private panNodeStartY = 0;

  // Dragging
  private drag: DragState = { active: false, nodeId: '', startX: 0, startY: 0, nodeStartX: 0, nodeStartY: 0 };

  // Stats
  get nodeCount(): number { return this.nodes.length; }
  get edgeCount(): number { return this.edges.length; }

  hoveredNode: GraphNode | null = null;

  private subs = new Subscription();

  readonly SVG_W = 900;
  readonly SVG_H = 560;
  readonly CENTER_X = 450;
  readonly CENTER_Y = 280;
  readonly NODE_R = 28;

  get svgTransform(): string {
    return `translate(${this.panX}, ${this.panY}) scale(${this.zoomLevel})`;
  }

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private cveService: AttackCveService,
    private d3fendService: D3fendService,
    private panelNav: PanelNavService,
    private graphFocus: GraphFocusService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.dataService.domain$.subscribe(d => {
        this.domain = d;
        if (d) {
          if (this.focus) {
            this.buildFor(this.focus);
          } else if (this.technique) {
            this.focus = { kind: 'technique', id: this.technique.id };
            this.buildFor(this.focus);
          }
        }
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.filterService.selectedTechnique$.subscribe(t => {
        this.technique = t;
        // GUARD: an external technique selection (matrix / sidebar / search)
        // only re-centers the graph when it isn't already focused on a
        // non-technique entity — otherwise it would clobber a group/software/
        // campaign/mitigation focus the user navigated to in the graph.
        if (t && this.isTechniqueFocus(this.focus)) {
          this.focus = { kind: 'technique', id: t.id };
          if (this.domain) this.buildFor(this.focus);
        }
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.cveService.loaded$.subscribe(loaded => {
        if (loaded && this.focus) this.buildFor(this.focus);
        this.cdr.markForCheck();
      }),
    );
    // Pivot channel: an entity panel (or anything else) requests a center.
    // Subscribed last so a pending pivot takes precedence over the current
    // technique selection on (re)creation of the panel.
    this.subs.add(
      this.graphFocus.focus$.subscribe(f => {
        if (!f) return;
        this.centerOnFocus(f);
      }),
    );
  }

  /** True when a focus is null or one of the technique-family kinds. */
  private isTechniqueFocus(focus: GraphFocus | null): boolean {
    return focus === null
      || focus.kind === 'technique'
      || focus.kind === 'subtechnique'
      || focus.kind === 'parent';
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  // -- Technique search --
  onSearchInput(query: string): void {
    this.searchQuery = query;
    if (!this.domain || query.trim().length < 2) {
      this.searchResults = [];
      this.showSearchDropdown = false;
      this.cdr.markForCheck();
      return;
    }
    const q = query.toLowerCase();
    this.searchResults = this.domain.techniques
      .filter(t => t.attackId.toLowerCase().includes(q) || t.name.toLowerCase().includes(q))
      .slice(0, 12);
    this.showSearchDropdown = this.searchResults.length > 0;
    this.cdr.markForCheck();
  }

  selectSearchResult(tech: Technique): void {
    this.searchQuery = '';
    this.searchResults = [];
    this.showSearchDropdown = false;
    // An in-graph search pick is an explicit re-center: pre-set the focus to a
    // technique so the selectedTechnique$ guard passes even when the graph was
    // centered on a non-technique, and remember the prior focus for Back.
    if (this.focus && this.focus.id !== tech.id) this.focusHistory.push(this.focus);
    this.focus = { kind: 'technique', id: tech.id };
    this.filterService.selectTechnique(tech);
    // build() fires via the selectedTechnique$ subscription
  }

  closeSearchDropdown(): void {
    // Small delay so click on result registers first
    setTimeout(() => {
      this.showSearchDropdown = false;
      this.cdr.markForCheck();
    }, 200);
  }

  // -- Zoom --
  zoomIn(): void {
    this.zoomLevel = Math.min(this.ZOOM_MAX, +(this.zoomLevel + this.ZOOM_STEP).toFixed(2));
    this.cdr.markForCheck();
  }

  zoomOut(): void {
    this.zoomLevel = Math.max(this.ZOOM_MIN, +(this.zoomLevel - this.ZOOM_STEP).toFixed(2));
    this.cdr.markForCheck();
  }

  resetView(): void {
    this.zoomLevel = 1;
    this.panX = 0;
    this.panY = 0;
    this.cdr.markForCheck();
  }

  onWheel(event: WheelEvent): void {
    event.preventDefault();
    if (event.deltaY < 0) {
      this.zoomIn();
    } else {
      this.zoomOut();
    }
  }

  // -- Pan (middle-click or shift+click on SVG background) --
  onSvgMouseDown(event: MouseEvent): void {
    // Only start pan if clicking on the SVG background (not a node)
    if (event.button === 1 || (event.button === 0 && event.shiftKey)) {
      event.preventDefault();
      this.isPanning = true;
      this.panStartX = event.clientX;
      this.panStartY = event.clientY;
      this.panNodeStartX = this.panX;
      this.panNodeStartY = this.panY;
    }
  }

  getColor(kind: GraphNode['kind']): string { return KIND_COLORS[kind]; }
  getIcon(kind: GraphNode['kind']): string { return KIND_ICONS[kind]; }

  build(): void {
    if (!this.domain || !this.technique) return;
    const domain = this.domain;
    const tech = this.technique;

    const edges: GraphEdge[] = [];

    // Center: selected technique
    const center: GraphNode = {
      id: tech.id,
      label: tech.attackId,
      sublabel: tech.name.length > 20 ? tech.name.substring(0, 18) + '…' : tech.name,
      kind: 'technique',
      x: this.CENTER_X,
      y: this.CENTER_Y,
      pinned: true,
    };

    const rings: { kind: GraphNode['kind']; items: Array<{ id: string; label: string; sublabel?: string }> }[] = [];

    // Ring 1: Parent technique (if subtechnique)
    if (this.showSubtechniques && tech.parentId) {
      const parent = domain.techniques.find(t => t.id === tech.parentId);
      if (parent) {
        rings.push({ kind: 'parent', items: [{ id: parent.id, label: parent.attackId, sublabel: parent.name.substring(0, 16) }] });
        edges.push({ source: parent.id, target: tech.id, label: 'parent' });
      }
    }

    // Ring: Sibling subtechniques (if center is a parent)
    if (this.showSubtechniques && !tech.parentId) {
      const subs = tech.subtechniques?.slice(0, 6) ?? [];
      if (subs.length > 0) {
        for (const s of subs) {
          rings.push({ kind: 'subtechnique', items: [{ id: s.id, label: s.attackId, sublabel: s.name.substring(0, 14) }] });
          edges.push({ source: tech.id, target: s.id, label: 'subtechnique' });
        }
      }
    }

    // Mitigations
    if (this.showMitigations) {
      const mits = (domain.mitigationsByTechnique.get(tech.id) ?? []).slice(0, 6);
      for (const mr of mits) {
        rings.push({ kind: 'mitigation', items: [{ id: mr.mitigation.id, label: mr.mitigation.attackId, sublabel: mr.mitigation.name.substring(0, 16) }] });
        edges.push({ source: tech.id, target: mr.mitigation.id, label: 'mitigates' });
      }
    }

    // Threat groups
    const shownGroups = this.showGroups ? (domain.groupsByTechnique.get(tech.id) ?? []).slice(0, 6) : [];
    for (const g of shownGroups) {
      rings.push({ kind: 'group', items: [{ id: g.id, label: g.attackId, sublabel: g.name.substring(0, 14) }] });
      edges.push({ source: g.id, target: tech.id, label: 'uses' });
    }

    // Software
    const shownSoftware = this.showSoftware ? (domain.softwareByTechnique.get(tech.id) ?? []).slice(0, 5) : [];
    for (const s of shownSoftware) {
      rings.push({ kind: 'software', items: [{ id: s.id, label: s.attackId, sublabel: s.name.substring(0, 14) }] });
      edges.push({ source: s.id, target: tech.id, label: 'uses' });
    }

    // Campaigns
    const shownCampaigns = this.showCampaigns ? (domain.campaignsByTechnique.get(tech.id) ?? []).slice(0, 5) : [];
    for (const c of shownCampaigns) {
      rings.push({ kind: 'campaign', items: [{ id: c.id, label: c.attackId, sublabel: c.name.substring(0, 14) }] });
      edges.push({ source: c.id, target: tech.id, label: 'uses' });
    }

    // Cross-entity relationships between nodes already in the graph:
    // which of these groups wield which of these software, and which
    // campaigns are attributed to which groups.
    const shownSoftwareIds = new Set(shownSoftware.map(s => s.id));
    for (const g of shownGroups) {
      for (const sw of domain.softwareByGroup.get(g.id) ?? []) {
        if (shownSoftwareIds.has(sw.id)) {
          edges.push({ source: g.id, target: sw.id, label: 'uses' });
        }
      }
    }
    const shownGroupIds = new Set(shownGroups.map(g => g.id));
    for (const c of shownCampaigns) {
      const campaign = domain.campaigns.find(dc => dc.id === c.id);
      for (const groupId of campaign?.attributedGroupIds ?? []) {
        if (shownGroupIds.has(groupId)) {
          edges.push({ source: c.id, target: groupId, label: 'attributed-to' });
        }
      }
    }

    // CVEs
    if (this.showCves) {
      const cves = this.cveService.getCvesForTechnique(tech.attackId).slice(0, 6);
      for (const cve of cves) {
        const cveId = `cve-${cve.cveId}`;
        rings.push({ kind: 'cve', items: [{ id: cveId, label: cve.cveId }] });
        edges.push({ source: cveId, target: tech.id, label: 'exploits' });
      }
    }

    // D3FEND countermeasures
    if (this.showD3fend) {
      const cms = this.d3fendService.getCountermeasures(tech.attackId).slice(0, 6);
      for (const cm of cms) {
        const d3Id = `d3f-${cm.id}`;
        rings.push({ kind: 'd3fend', items: [{ id: d3Id, label: cm.id, sublabel: cm.name.substring(0, 16) }] });
        edges.push({ source: d3Id, target: tech.id, label: 'counters' });
      }
    }

    // CAPEC attack patterns
    if (this.showCapec) {
      for (const capecId of (tech.capecIds ?? []).slice(0, 6)) {
        const cId = `capec-${capecId}`;
        rings.push({ kind: 'capec', items: [{ id: cId, label: capecId }] });
        edges.push({ source: cId, target: tech.id, label: 'enables' });
      }
    }

    // Lay the accumulated rings out radially around the center.
    const allRingItems: RingItem[] = rings.map(r => ({ ...r.items[0], kind: r.kind }));
    this.applyRadialLayout(center, allRingItems, edges);
  }

  // ── Focus dispatch + non-technique builders ──────────────────────────────

  /** Rebuild the graph centered on the given focus (dispatches by kind). */
  buildFor(focus: GraphFocus): void {
    if (!this.domain) return;
    switch (focus.kind) {
      case 'technique':
      case 'subtechnique':
      case 'parent':
        this.technique = this.domain.techniques.find(t => t.id === focus.id) ?? null;
        this.build();
        break;
      case 'group': this.buildGroup(focus.id); break;
      case 'software': this.buildSoftware(focus.id); break;
      case 'campaign': this.buildCampaign(focus.id); break;
      case 'mitigation': this.buildMitigation(focus.id); break;
      default:
        // cve / d3fend / capec have no reverse index — leaf only.
        break;
    }
    this.cdr.markForCheck();
  }

  /** Center on a threat group: its techniques, software toolkit, and campaigns. */
  private buildGroup(groupId: string): void {
    if (!this.domain) return;
    const group = this.domain.groups.find(g => g.id === groupId);
    if (!group) return;

    const edges: GraphEdge[] = [];
    const rings: RingItem[] = [];
    const center: GraphNode = {
      id: group.id, label: group.attackId, sublabel: this.trunc(group.name),
      kind: 'group', x: this.CENTER_X, y: this.CENTER_Y, pinned: true,
    };

    for (const t of this.dataService.getTechniquesForGroup(group.id).slice(0, 8)) {
      rings.push({ id: t.id, label: t.attackId, sublabel: t.name.substring(0, 14), kind: 'technique' });
      edges.push({ source: group.id, target: t.id, label: 'uses' });
    }
    if (this.showSoftware) {
      for (const s of this.dataService.getSoftwareForGroup(group.id).slice(0, 5)) {
        rings.push({ id: s.id, label: s.attackId, sublabel: s.name.substring(0, 14), kind: 'software' });
        edges.push({ source: group.id, target: s.id, label: 'uses' });
      }
    }
    if (this.showCampaigns) {
      for (const c of this.dataService.getCampaignsForGroup(group.id).slice(0, 5)) {
        rings.push({ id: c.id, label: c.attackId, sublabel: c.name.substring(0, 14), kind: 'campaign' });
        edges.push({ source: c.id, target: group.id, label: 'attributed-to' });
      }
    }
    this.applyRadialLayout(center, rings, edges);
  }

  /** Center on a piece of software: techniques it uses + groups wielding it. */
  private buildSoftware(softwareId: string): void {
    if (!this.domain) return;
    const sw = this.domain.software.find(s => s.id === softwareId);
    if (!sw) return;

    const edges: GraphEdge[] = [];
    const rings: RingItem[] = [];
    const center: GraphNode = {
      id: sw.id, label: sw.attackId, sublabel: this.trunc(sw.name),
      kind: 'software', x: this.CENTER_X, y: this.CENTER_Y, pinned: true,
    };

    for (const t of this.dataService.getTechniquesForSoftware(sw.id).slice(0, 8)) {
      rings.push({ id: t.id, label: t.attackId, sublabel: t.name.substring(0, 14), kind: 'technique' });
      edges.push({ source: sw.id, target: t.id, label: 'uses' });
    }
    if (this.showGroups) {
      for (const g of this.dataService.getGroupsForSoftware(sw.id).slice(0, 6)) {
        rings.push({ id: g.id, label: g.attackId, sublabel: g.name.substring(0, 14), kind: 'group' });
        edges.push({ source: g.id, target: sw.id, label: 'uses' });
      }
    }
    this.applyRadialLayout(center, rings, edges);
  }

  /** Center on a campaign: its techniques, software, and attributed groups. */
  private buildCampaign(campaignId: string): void {
    if (!this.domain) return;
    const domain = this.domain;
    const campaign = domain.campaigns.find(c => c.id === campaignId);
    if (!campaign) return;

    const edges: GraphEdge[] = [];
    const rings: RingItem[] = [];
    const center: GraphNode = {
      id: campaign.id, label: campaign.attackId, sublabel: this.trunc(campaign.name),
      kind: 'campaign', x: this.CENTER_X, y: this.CENTER_Y, pinned: true,
    };

    for (const t of this.dataService.getTechniquesForCampaign(campaign.id).slice(0, 8)) {
      rings.push({ id: t.id, label: t.attackId, sublabel: t.name.substring(0, 14), kind: 'technique' });
      edges.push({ source: campaign.id, target: t.id, label: 'uses' });
    }
    if (this.showSoftware) {
      for (const s of this.dataService.getSoftwareForCampaign(campaign.id).slice(0, 5)) {
        rings.push({ id: s.id, label: s.attackId, sublabel: s.name.substring(0, 14), kind: 'software' });
        edges.push({ source: campaign.id, target: s.id, label: 'uses' });
      }
    }
    if (this.showGroups) {
      for (const gid of campaign.attributedGroupIds.slice(0, 5)) {
        const g = domain.groups.find(gr => gr.id === gid);
        if (!g) continue;
        rings.push({ id: g.id, label: g.attackId, sublabel: g.name.substring(0, 14), kind: 'group' });
        edges.push({ source: campaign.id, target: g.id, label: 'attributed-to' });
      }
    }
    this.applyRadialLayout(center, rings, edges);
  }

  /** Center on a mitigation: the techniques it mitigates. */
  private buildMitigation(mitigationId: string): void {
    if (!this.domain) return;
    const mit = this.domain.mitigations.find(m => m.id === mitigationId);
    if (!mit) return;

    const edges: GraphEdge[] = [];
    const rings: RingItem[] = [];
    const center: GraphNode = {
      id: mit.id, label: mit.attackId, sublabel: this.trunc(mit.name),
      kind: 'mitigation', x: this.CENTER_X, y: this.CENTER_Y, pinned: true,
    };
    for (const t of this.dataService.getTechniquesForMitigation(mit.id).slice(0, 10)) {
      rings.push({ id: t.id, label: t.attackId, sublabel: t.name.substring(0, 14), kind: 'technique' });
      edges.push({ source: mit.id, target: t.id, label: 'mitigates' });
    }
    this.applyRadialLayout(center, rings, edges);
  }

  /** Place the center node plus its neighbour rings radially; sets nodes/edges. */
  private applyRadialLayout(center: GraphNode, ringItems: RingItem[], edges: GraphEdge[]): void {
    const nodes: GraphNode[] = [];
    const nodeIds = new Set<string>();
    const addNode = (node: GraphNode) => {
      if (!nodeIds.has(node.id)) {
        nodes.push(node);
        nodeIds.add(node.id);
      }
    };
    addNode(center);

    const total = ringItems.length;
    const innerCount = Math.min(total, 8);
    const outerStart = innerCount;
    const innerRadius = 160;
    const outerRadius = 270;

    ringItems.forEach((item, i) => {
      let radius: number;
      let angle: number;
      if (i < innerCount) {
        angle = (i / innerCount) * 2 * Math.PI - Math.PI / 2;
        radius = innerRadius;
      } else {
        const outerIdx = i - outerStart;
        const outerTotal = total - innerCount;
        angle = (outerIdx / outerTotal) * 2 * Math.PI - Math.PI / 2;
        radius = outerRadius;
      }
      addNode({
        id: item.id,
        label: item.label,
        sublabel: item.sublabel,
        kind: item.kind,
        x: this.CENTER_X + Math.cos(angle) * radius,
        y: this.CENTER_Y + Math.sin(angle) * radius,
      });
    });

    this.nodes = nodes;
    this.edges = edges;
    this.cdr.markForCheck();
  }

  private trunc(s: string, n = 18): string {
    return s.length > n ? s.substring(0, n) + '…' : s;
  }

  // ── Focus navigation (center / pivot / back) ─────────────────────────────

  /** Re-center on a clicked neighbour node, remembering the prior focus. */
  centerOnNode(node: GraphNode): void {
    if (this.focus && this.focus.id === node.id) return;
    if (this.focus) this.focusHistory.push(this.focus);
    this.focus = { kind: node.kind, id: node.id };
    if (this.isTechniqueFocus(this.focus)) {
      this.technique = this.domain?.techniques.find(t => t.id === node.id) ?? null;
    }
    this.buildFor(this.focus);
    this.cdr.markForCheck();
  }

  /** Center in response to an external pivot request (GraphFocusService). */
  private centerOnFocus(focus: GraphFocus): void {
    const sameTarget = this.focus && this.focus.id === focus.id && this.focus.kind === focus.kind;
    if (!sameTarget && this.focus) this.focusHistory.push(this.focus);
    this.focus = focus;
    if (this.isTechniqueFocus(focus)) {
      this.technique = this.domain?.techniques.find(t => t.id === focus.id) ?? null;
    }
    if (this.domain) this.buildFor(focus);
    this.cdr.markForCheck();
  }

  /** Return to the previous focus on the back-stack. */
  goBack(): void {
    const prev = this.focusHistory.pop();
    if (!prev) return;
    this.focus = prev;
    if (this.isTechniqueFocus(prev)) {
      this.technique = this.domain?.techniques.find(t => t.id === prev.id) ?? null;
    }
    this.buildFor(prev);
    this.cdr.markForCheck();
  }

  /** Human label for the currently focused center, for the header title. */
  get focusTitle(): string {
    if (this.technique && this.isTechniqueFocus(this.focus)) {
      return `${this.technique.attackId}: ${this.technique.name}`;
    }
    const center = this.nodes.find(n => n.pinned);
    if (center) return center.sublabel ? `${center.label}: ${center.sublabel}` : center.label;
    return '';
  }

  /** Short identifier for the currently focused center (empty-state message). */
  get focusCenterLabel(): string {
    return this.technique?.attackId ?? this.nodes.find(n => n.pinned)?.label ?? '';
  }

  rebuildWithOptions(): void { if (this.focus) this.buildFor(this.focus); }

  getNode(id: string): GraphNode | undefined {
    return this.nodes.find(n => n.id === id);
  }

  getEdgePath(edge: GraphEdge): string {
    const src = this.getNode(edge.source);
    const tgt = this.getNode(edge.target);
    if (!src || !tgt) return '';
    const dx = tgt.x - src.x;
    const dy = tgt.y - src.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist < 1) return '';
    const ux = dx / dist;
    const uy = dy / dist;
    // Curve control point (slight arc)
    const mx = (src.x + tgt.x) / 2 - uy * 20;
    const my = (src.y + tgt.y) / 2 + ux * 20;
    const sx = src.x + ux * this.NODE_R;
    const sy = src.y + uy * this.NODE_R;
    const ex = tgt.x - ux * this.NODE_R;
    const ey = tgt.y - uy * this.NODE_R;
    return `M ${sx} ${sy} Q ${mx} ${my} ${ex} ${ey}`;
  }

  getEdgeMidpoint(edge: GraphEdge): { x: number; y: number } | null {
    const src = this.getNode(edge.source);
    const tgt = this.getNode(edge.target);
    if (!src || !tgt) return null;
    const mx = (src.x + tgt.x) / 2;
    const my = (src.y + tgt.y) / 2;
    return { x: mx, y: my };
  }

  // Dragging
  onNodeMouseDown(event: MouseEvent, node: GraphNode): void {
    if (event.button !== 0) return;
    event.preventDefault();
    this.drag = {
      active: true,
      nodeId: node.id,
      startX: event.clientX,
      startY: event.clientY,
      nodeStartX: node.x,
      nodeStartY: node.y,
    };
  }

  @HostListener('document:mousemove', ['$event'])
  onMouseMove(event: MouseEvent): void {
    if (this.isPanning) {
      this.panX = this.panNodeStartX + (event.clientX - this.panStartX);
      this.panY = this.panNodeStartY + (event.clientY - this.panStartY);
      this.cdr.markForCheck();
      return;
    }
    if (!this.drag.active) return;
    const node = this.nodes.find(n => n.id === this.drag.nodeId);
    if (!node) return;
    const scale = this.zoomLevel || 1;
    node.x = this.drag.nodeStartX + (event.clientX - this.drag.startX) / scale;
    node.y = this.drag.nodeStartY + (event.clientY - this.drag.startY) / scale;
    this.cdr.markForCheck();
  }

  @HostListener('document:mouseup')
  onMouseUp(): void {
    this.drag.active = false;
    this.isPanning = false;
  }

  onNodeClick(event: MouseEvent, node: GraphNode): void {
    if (this.drag.active) return;

    // Secondary control (preserves the pre-existing group behavior): Ctrl/Cmd-
    // click a group node to toggle it as a matrix filter and open the Threat
    // Groups panel, instead of re-centering the graph on it.
    if (node.kind === 'group' && (event.ctrlKey || event.metaKey)) {
      this.filterService.toggleThreatGroup(node.id);
      this.panelNav.open('threats');
      return;
    }

    if (node.kind === 'technique' || node.kind === 'subtechnique' || node.kind === 'parent') {
      const tech = this.domain?.techniques.find(t => t.id === node.id);
      if (tech) {
        // Explicit in-graph navigation: pre-set focus so the guard passes,
        // remember the prior focus for Back, and keep sidebar/matrix synced.
        if (this.focus && this.focus.id !== tech.id) this.focusHistory.push(this.focus);
        this.focus = { kind: 'technique', id: tech.id };
        this.technique = tech;
        this.filterService.selectTechnique(tech);
        this.buildFor(this.focus);
        this.cdr.markForCheck();
      }
      return;
    }

    // Centerable non-technique nodes re-center the graph (reverse index).
    if (node.kind === 'group' || node.kind === 'software' || node.kind === 'campaign' || node.kind === 'mitigation') {
      this.centerOnNode(node);
      return;
    }
    // cve / d3fend / capec remain inert leaves (no reverse index).
  }

  onNodeHover(node: GraphNode): void { this.hoveredNode = node; this.cdr.markForCheck(); }
  onNodeLeave(): void { this.hoveredNode = null; this.cdr.markForCheck(); }

  trackByNode(_: number, n: GraphNode): string { return n.id; }
  trackByEdge(_: number, e: GraphEdge): string { return e.source + '-' + e.target; }

  get legendKinds(): Array<GraphNode['kind']> {
    return ['technique', 'subtechnique', 'parent', 'mitigation', 'group', 'software', 'cve', 'campaign', 'd3fend', 'capec'];
  }
}
