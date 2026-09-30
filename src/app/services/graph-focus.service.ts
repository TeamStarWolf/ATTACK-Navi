// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

/**
 * The kinds of node the relationship graph can render. Mirrors
 * GraphNode['kind'] in TechniqueGraphPanelComponent; declared here so the
 * pivot channel has no dependency on the component (the component imports
 * this type, not the other way around).
 */
export type GraphFocusKind =
  | 'technique'
  | 'subtechnique'
  | 'parent'
  | 'mitigation'
  | 'group'
  | 'software'
  | 'cve'
  | 'campaign'
  | 'd3fend'
  | 'capec';

/** A request to center the relationship graph on a specific entity. */
export interface GraphFocus {
  kind: GraphFocusKind;
  id: string;
}

/**
 * Pivot channel for the relationship graph. Entity panels (actor / software /
 * campaign) and the graph itself push a GraphFocus here to re-center the graph
 * on any node, not just techniques. Kept deliberately separate from
 * FilterService.selectedTechnique$ so a non-technique pivot never rides on — or
 * clobbers — the matrix's selected-technique state (which is foundation-hot).
 */
@Injectable({ providedIn: 'root' })
export class GraphFocusService {
  /** Last requested focus, or null when nothing has been requested yet. */
  readonly focus$ = new BehaviorSubject<GraphFocus | null>(null);

  /** Request the graph center on a node of the given kind + STIX id. */
  focusNode(kind: GraphFocusKind, id: string): void {
    this.focus$.next({ kind, id });
  }

  /** Clear the pending focus. */
  clear(): void {
    this.focus$.next(null);
  }
}
