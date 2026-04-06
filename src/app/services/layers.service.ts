// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import { DocumentationService, MitigationDoc } from './documentation.service';
import { FilterService, FilterStateSnapshot } from './filter.service';
import { ImplementationService, ImplStatus } from './implementation.service';

export interface LayerStateSnapshot extends FilterStateSnapshot {
  implStatus: Record<string, ImplStatus>;
  techNotes: Record<string, string>;
  mitDocs: Record<string, MitigationDoc>;
}

export interface LayerSnapshot {
  id: string;
  name: string;
  description: string;
  createdAt: string; // ISO
  state: LayerStateSnapshot;
}

@Injectable({ providedIn: 'root' })
export class LayersService {
  private readonly KEY = 'mitre-nav-layers-v1';
  private sub = new BehaviorSubject<LayerSnapshot[]>(this.load());
  layers$ = this.sub.asObservable();

  private load(): LayerSnapshot[] {
    try {
      const parsed = JSON.parse(localStorage.getItem(this.KEY) ?? '[]') as unknown;
      if (!Array.isArray(parsed)) return [];
      return parsed.filter((entry): entry is LayerSnapshot => this.isLayerSnapshot(entry));
    } catch {
      return [];
    }
  }

  private persist(layers: LayerSnapshot[]): void {
    localStorage.setItem(this.KEY, JSON.stringify(layers));
    this.sub.next(layers);
  }

  saveLayer(
    name: string,
    description: string,
    filterService: FilterService,
    implService: ImplementationService,
    docService: DocumentationService,
  ): void {
    const id = crypto.randomUUID();
    const documentation = this.parseDocumentationExport(docService.exportJson());
    const snapshot: LayerSnapshot = {
      id,
      name,
      description,
      createdAt: new Date().toISOString(),
      state: {
        ...filterService.getStateSnapshot(),
        implStatus: Object.fromEntries(implService.getStatusMap()),
        techNotes: documentation.techniques,
        mitDocs: documentation.mitigations,
      },
    };
    this.persist([snapshot, ...this.sub.value]);
  }

  loadLayer(id: string, filterService: FilterService, implService: ImplementationService, docService: DocumentationService): void {
    const layer = this.sub.value.find(l => l.id === id);
    if (!layer) return;
    filterService.restoreStateSnapshot(layer.state);
    const implEntries = Object.entries(layer.state.implStatus ?? {});
    implService.importJson(JSON.stringify(implEntries));
    docService.importJson(JSON.stringify({
      mitigations: layer.state.mitDocs ?? {},
      techniques: layer.state.techNotes ?? {},
    }));
  }

  deleteLayer(id: string): void {
    this.persist(this.sub.value.filter(l => l.id !== id));
  }

  exportLayer(layer: LayerSnapshot): void {
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), {
      href: url,
      download: `layer-${layer.name.replace(/\s+/g, '-')}.json`,
    });
    a.click();
    URL.revokeObjectURL(url);
  }

  importLayer(json: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      throw new Error('Invalid JSON');
    }
    if (!this.isLayerSnapshot(parsed)) {
      throw new Error('Invalid layer payload');
    }
    const layer: LayerSnapshot = {
      ...parsed,
      state: {
        ...parsed.state,
        activeThreatGroupIds: [...parsed.state.activeThreatGroupIds],
        activeSoftwareIds: [...parsed.state.activeSoftwareIds],
        activeCampaignIds: [...parsed.state.activeCampaignIds],
        activeMitigationFilterIds: [...parsed.state.activeMitigationFilterIds],
        whatIfMitigationIds: [...parsed.state.whatIfMitigationIds],
        hiddenTacticIds: [...parsed.state.hiddenTacticIds],
        implStatus: { ...parsed.state.implStatus },
        techNotes: { ...parsed.state.techNotes },
        mitDocs: { ...parsed.state.mitDocs },
      },
    };
    layer.id = crypto.randomUUID();
    this.persist([layer, ...this.sub.value]);
  }

  duplicateLayer(id: string): void {
    const layer = this.sub.value.find(l => l.id === id);
    if (!layer) return;
    this.persist([
      { ...layer, id: crypto.randomUUID(), name: `${layer.name} (copy)`, createdAt: new Date().toISOString() },
      ...this.sub.value,
    ]);
  }

  private parseDocumentationExport(json: string): { mitigations: Record<string, MitigationDoc>; techniques: Record<string, string> } {
    try {
      const parsed = JSON.parse(json) as unknown;
      if (!parsed || typeof parsed !== 'object') {
        return { mitigations: {}, techniques: {} };
      }
      const data = parsed as { mitigations?: unknown; techniques?: unknown };
      return {
        mitigations: this.isMitigationDocRecord(data.mitigations) ? data.mitigations : {},
        techniques: this.isStringRecord(data.techniques) ? data.techniques : {},
      };
    } catch {
      return { mitigations: {}, techniques: {} };
    }
  }

  private isLayerSnapshot(value: unknown): value is LayerSnapshot {
    if (!value || typeof value !== 'object') return false;
    const layer = value as Partial<LayerSnapshot>;
    return typeof layer.id === 'string'
      && typeof layer.name === 'string'
      && typeof layer.description === 'string'
      && typeof layer.createdAt === 'string'
      && this.isLayerStateSnapshot(layer.state);
  }

  private isLayerStateSnapshot(value: unknown): value is LayerStateSnapshot {
    if (!value || typeof value !== 'object') return false;
    const state = value as Partial<LayerStateSnapshot>;
    return typeof state.heatmapMode === 'string'
      && Array.isArray(state.activeThreatGroupIds) && state.activeThreatGroupIds.every(id => typeof id === 'string')
      && Array.isArray(state.activeSoftwareIds) && state.activeSoftwareIds.every(id => typeof id === 'string')
      && Array.isArray(state.activeCampaignIds) && state.activeCampaignIds.every(id => typeof id === 'string')
      && Array.isArray(state.activeMitigationFilterIds) && state.activeMitigationFilterIds.every(id => typeof id === 'string')
      && Array.isArray(state.whatIfMitigationIds) && state.whatIfMitigationIds.every(id => typeof id === 'string')
      && (typeof state.platformFilter === 'string' || state.platformFilter === null)
      && typeof state.sortMode === 'string'
      && typeof state.dimUncovered === 'boolean'
      && typeof state.searchFilterMode === 'boolean'
      && Array.isArray(state.hiddenTacticIds) && state.hiddenTacticIds.every(id => typeof id === 'string')
      && this.isImplStatusRecord(state.implStatus)
      && this.isStringRecord(state.techNotes)
      && this.isMitigationDocRecord(state.mitDocs);
  }

  private isImplStatusRecord(value: unknown): value is Record<string, ImplStatus> {
    const validStatuses = new Set<ImplStatus>(['implemented', 'in-progress', 'planned', 'not-started']);
    return this.isRecord(value) && Object.values(value).every(status => typeof status === 'string' && validStatuses.has(status as ImplStatus));
  }

  private isStringRecord(value: unknown): value is Record<string, string> {
    return this.isRecord(value) && Object.values(value).every(entry => typeof entry === 'string');
  }

  private isMitigationDocRecord(value: unknown): value is Record<string, MitigationDoc> {
    return this.isRecord(value) && Object.values(value).every(entry =>
      !!entry
      && typeof entry === 'object'
      && typeof (entry as MitigationDoc).notes === 'string'
      && typeof (entry as MitigationDoc).owner === 'string'
      && typeof (entry as MitigationDoc).dueDate === 'string'
      && typeof (entry as MitigationDoc).controlRefs === 'string'
      && typeof (entry as MitigationDoc).evidenceUrl === 'string',
    );
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return !!value && typeof value === 'object' && !Array.isArray(value);
  }
}
