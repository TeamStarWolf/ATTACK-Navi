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
import { DataService } from '../../services/data.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { Domain } from '../../models/domain';
import { Technique } from '../../models/technique';

export interface GraphNode {
  id: string;
  label: string;
  sublabel?: string;
  kind: 'technique' | 'subtechnique' | 'mitigation' | 'group' | 'software' | 'cve' | 'campaign' | 'parent';
  x: number;
  y: number;
  pinned?: boolean;
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
  cve:          '#ffa657',
  campaign:     '#e3b341',
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
  open = false;
  domain: Domain | null = null;
  technique: Technique | null = null;

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
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.open = p === 'technique-graph';
        if (this.open && this.domain && this.technique) this.build();
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.dataService.domain$.subscribe(d => {
        this.domain = d;
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.filterService.selectedTechnique$.subscribe(t => {
        this.technique = t;
        if (this.open && this.domain && t) this.build();
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.cveService.loaded$.subscribe(loaded => {
        if (loaded && this.open && this.technique) this.build();
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  close(): void { this.filterService.setActivePanel(null); }

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
    this.filterService.selectTechnique(tech);
    // build() will fire via subscription
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

    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    const nodeIds = new Set<string>();

    const addNode = (node: GraphNode) => {
      if (!nodeIds.has(node.id)) {
        nodes.push(node);
        nodeIds.add(node.id);
      }
    };

    // Center: selected technique
    addNode({
      id: tech.id,
      label: tech.attackId,
      sublabel: tech.name.length > 20 ? tech.name.substring(0, 18) + '…' : tech.name,
      kind: 'technique',
      x: this.CENTER_X,
      y: this.CENTER_Y,
      pinned: true,
    });

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
    if (this.showGroups) {
      const groups = (domain.groupsByTechnique.get(tech.id) ?? []).slice(0, 6);
      for (const g of groups) {
        rings.push({ kind: 'group', items: [{ id: g.id, label: g.attackId, sublabel: g.name.substring(0, 14) }] });
        edges.push({ source: g.id, target: tech.id, label: 'uses' });
      }
    }

    // Software
    if (this.showSoftware) {
      const sw = (domain.softwareByTechnique.get(tech.id) ?? []).slice(0, 5);
      for (const s of sw) {
        rings.push({ kind: 'software', items: [{ id: s.id, label: s.attackId, sublabel: s.name.substring(0, 14) }] });
        edges.push({ source: s.id, target: tech.id, label: 'uses' });
      }
    }

    // Campaigns
    if (this.showCampaigns) {
      const camps = (domain.campaignsByTechnique.get(tech.id) ?? []).slice(0, 5);
      for (const c of camps) {
        rings.push({ kind: 'campaign', items: [{ id: c.id, label: c.attackId, sublabel: c.name.substring(0, 14) }] });
        edges.push({ source: c.id, target: tech.id, label: 'uses' });
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

    // Layout all nodes in a radial pattern
    const allRingItems = rings.map(r => ({ ...r.items[0], kind: r.kind }));
    const total = allRingItems.length;
    const angleStep = total > 0 ? (2 * Math.PI) / total : 0;

    // Use two rings for large counts
    const innerCount = Math.min(total, 8);
    const outerStart = innerCount;
    const innerRadius = 160;
    const outerRadius = 270;

    allRingItems.forEach((item, i) => {
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

  rebuildWithOptions(): void { this.build(); }

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

  onNodeClick(node: GraphNode): void {
    if (this.drag.active) return;
    if (node.kind === 'technique' || node.kind === 'subtechnique' || node.kind === 'parent') {
      const tech = this.domain?.techniques.find(t => t.id === node.id);
      if (tech) this.filterService.selectTechnique(tech);
    }
    if (node.kind === 'group') {
      this.filterService.toggleThreatGroup(node.id);
      this.filterService.setActivePanel('threats');
    }
  }

  onNodeHover(node: GraphNode): void { this.hoveredNode = node; this.cdr.markForCheck(); }
  onNodeLeave(): void { this.hoveredNode = null; this.cdr.markForCheck(); }

  trackByNode(_: number, n: GraphNode): string { return n.id; }
  trackByEdge(_: number, e: GraphEdge): string { return e.source + '-' + e.target; }

  get legendKinds(): Array<GraphNode['kind']> {
    return ['technique', 'subtechnique', 'parent', 'mitigation', 'group', 'software', 'cve', 'campaign'];
  }

  @HostListener('document:keydown.escape')
  onEsc(): void { if (this.open) this.close(); }
}
