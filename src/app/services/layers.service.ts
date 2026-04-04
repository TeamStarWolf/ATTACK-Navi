import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface LayerSnapshot {
  id: string;
  name: string;
  description: string;
  createdAt: string; // ISO
  state: {
    heatmapMode: string;
    activeThreatGroupIds: string[];
    activeSoftwareIds: string[];
    activeCampaignIds: string[];
    activeMitigationFilterIds: string[];
    whatIfMitigationIds: string[];
    platformFilter: string | null;
    sortMode: string;
    dimUncovered: boolean;
    searchFilterMode: boolean;
    hiddenTacticIds: string[];
    implStatus: Record<string, string>;
    techNotes: Record<string, string>;
    mitDocs: Record<string, any>;
  };
}

@Injectable({ providedIn: 'root' })
export class LayersService {
  private readonly KEY = 'mitre-nav-layers-v1';
  private sub = new BehaviorSubject<LayerSnapshot[]>(this.load());
  layers$ = this.sub.asObservable();

  private load(): LayerSnapshot[] {
    try { return JSON.parse(localStorage.getItem(this.KEY) ?? '[]'); }
    catch { return []; }
  }

  private persist(layers: LayerSnapshot[]): void {
    localStorage.setItem(this.KEY, JSON.stringify(layers));
    this.sub.next(layers);
  }

  saveLayer(name: string, description: string, filterService: any, implService: any, docService: any): void {
    const id = crypto.randomUUID();
    const snapshot: LayerSnapshot = {
      id,
      name,
      description,
      createdAt: new Date().toISOString(),
      state: filterService.getStateSnapshot(),
    };
    // Merge impl + doc state into snapshot.state
    const impl = implService.getStatusMap();
    snapshot.state.implStatus = Object.fromEntries(impl);
    const docExport = docService.exportJson();
    const parsed = JSON.parse(docExport);
    snapshot.state.techNotes = Object.fromEntries(
      Object.entries(parsed.techniques ?? {})
    );
    snapshot.state.mitDocs = parsed.mitigations ?? {};
    this.persist([snapshot, ...this.sub.value]);
  }

  loadLayer(id: string, filterService: any, implService: any, docService: any): void {
    const layer = this.sub.value.find(l => l.id === id);
    if (!layer) return;
    filterService.restoreStateSnapshot(layer.state);
    // Convert Record<string,string> → array of [id, status] pairs for importJson
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
    try {
      const layer = JSON.parse(json) as LayerSnapshot;
      layer.id = crypto.randomUUID(); // fresh ID to avoid collision
      this.persist([layer, ...this.sub.value]);
    } catch { /* ignore malformed JSON */ }
  }

  duplicateLayer(id: string): void {
    const layer = this.sub.value.find(l => l.id === id);
    if (!layer) return;
    this.persist([
      { ...layer, id: crypto.randomUUID(), name: layer.name + ' (copy)', createdAt: new Date().toISOString() },
      ...this.sub.value,
    ]);
  }
}
