import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface SavedView {
  id: string;
  name: string;
  description: string;
  createdAt: string;
  urlHash: string;
  heatmapMode: string;
  thumbnail: string;
}

@Injectable({ providedIn: 'root' })
export class SavedViewsService {
  private readonly STORAGE_KEY = 'mitre-nav-views-v1';
  private viewsSubject = new BehaviorSubject<SavedView[]>(this.load());
  views$ = this.viewsSubject.asObservable();

  get all(): SavedView[] { return this.viewsSubject.value; }

  saveCurrentView(name: string, description: string): SavedView {
    const view: SavedView = {
      id: Date.now().toString(),
      name,
      description,
      createdAt: new Date().toISOString(),
      urlHash: window.location.hash,
      heatmapMode: this.getHeatmapModeFromHash(),
      thumbnail: this.getHeatmapModeFromHash(),
    };
    const updated = [view, ...this.viewsSubject.value];
    this.viewsSubject.next(updated);
    this.save(updated);
    return view;
  }

  restoreView(view: SavedView): void {
    window.location.hash = view.urlHash.startsWith('#')
      ? view.urlHash.slice(1)
      : view.urlHash;
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  }

  deleteView(id: string): void {
    const updated = this.viewsSubject.value.filter(v => v.id !== id);
    this.viewsSubject.next(updated);
    this.save(updated);
  }

  private getHeatmapModeFromHash(): string {
    const hash = window.location.hash;
    const paramStr = hash.startsWith('#') ? hash.slice(1) : hash;
    try {
      const params = new URLSearchParams(paramStr);
      return params.get('heat') ?? 'coverage';
    } catch {
      return 'coverage';
    }
  }

  private load(): SavedView[] {
    try { return JSON.parse(localStorage.getItem(this.STORAGE_KEY) ?? '[]'); }
    catch { return []; }
  }

  private save(views: SavedView[]): void {
    localStorage.setItem(this.STORAGE_KEY, JSON.stringify(views));
  }
}
