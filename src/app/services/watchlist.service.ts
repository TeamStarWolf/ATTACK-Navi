import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { Technique } from '../models/technique';

export interface WatchlistEntry {
  techniqueId: string;    // ATT&CK ID (T1234)
  stixId: string;         // STIX ID for lookups
  name: string;
  addedAt: string;        // ISO date
  note: string;           // optional quick note
  priority: 'high' | 'medium' | 'low';
}

@Injectable({ providedIn: 'root' })
export class WatchlistService {
  private readonly STORAGE_KEY = 'mitre-nav-watchlist-v1';
  private entriesSubject = new BehaviorSubject<WatchlistEntry[]>(this.load());
  entries$: Observable<WatchlistEntry[]> = this.entriesSubject.asObservable();

  get all(): WatchlistEntry[] {
    return this.entriesSubject.value;
  }

  isWatched(techniqueId: string): boolean {
    return this.entriesSubject.value.some(e => e.techniqueId === techniqueId);
  }

  add(technique: Technique, priority: WatchlistEntry['priority'] = 'medium'): void {
    if (this.isWatched(technique.attackId)) return;
    const entry: WatchlistEntry = {
      techniqueId: technique.attackId,
      stixId: technique.id,
      name: technique.name,
      addedAt: new Date().toISOString(),
      note: '',
      priority,
    };
    const next = [...this.entriesSubject.value, entry];
    this.entriesSubject.next(next);
    this.save(next);
  }

  remove(techniqueId: string): void {
    const next = this.entriesSubject.value.filter(e => e.techniqueId !== techniqueId);
    this.entriesSubject.next(next);
    this.save(next);
  }

  toggle(technique: Technique): void {
    if (this.isWatched(technique.attackId)) {
      this.remove(technique.attackId);
    } else {
      this.add(technique);
    }
  }

  updateNote(techniqueId: string, note: string): void {
    const next = this.entriesSubject.value.map(e =>
      e.techniqueId === techniqueId ? { ...e, note } : e,
    );
    this.entriesSubject.next(next);
    this.save(next);
  }

  updatePriority(techniqueId: string, priority: WatchlistEntry['priority']): void {
    const next = this.entriesSubject.value.map(e =>
      e.techniqueId === techniqueId ? { ...e, priority } : e,
    );
    this.entriesSubject.next(next);
    this.save(next);
  }

  private load(): WatchlistEntry[] {
    try {
      const raw = localStorage.getItem(this.STORAGE_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch {
      return [];
    }
  }

  private save(entries: WatchlistEntry[]): void {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(entries));
    } catch {}
  }
}
