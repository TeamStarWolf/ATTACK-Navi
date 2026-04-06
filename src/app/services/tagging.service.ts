// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

export interface TechniqueTag {
  techniqueId: string;  // STIX id
  tags: string[];
}

const STORAGE_KEY = 'mitre-nav-tags-v1';

const PRESET_TAGS = ['in-scope', 'out-of-scope', 'priority-q1', 'priority-q2', 'tested', 'excluded', 'review'];

@Injectable({ providedIn: 'root' })
export class TaggingService {
  private tagsMap = new Map<string, Set<string>>(); // techniqueId → tags
  private tagsSubject = new BehaviorSubject<Map<string, Set<string>>>(this.tagsMap);
  readonly tags$: Observable<Map<string, Set<string>>> = this.tagsSubject.asObservable();
  readonly presetTags = PRESET_TAGS;

  constructor() { this.load(); }

  private load(): void {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const data: Record<string, string[]> = JSON.parse(raw);
        for (const [id, tags] of Object.entries(data)) {
          this.tagsMap.set(id, new Set(tags));
        }
      }
    } catch {}
  }

  private save(): void {
    try {
      const data: Record<string, string[]> = {};
      for (const [id, tags] of this.tagsMap.entries()) {
        if (tags.size > 0) data[id] = [...tags];
      }
      localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    } catch {}
  }

  getTags(techniqueId: string): string[] {
    return [...(this.tagsMap.get(techniqueId) ?? [])];
  }

  hasTags(techniqueId: string): boolean {
    const t = this.tagsMap.get(techniqueId);
    return !!t && t.size > 0;
  }

  addTag(techniqueId: string, tag: string): void {
    if (!this.tagsMap.has(techniqueId)) this.tagsMap.set(techniqueId, new Set());
    this.tagsMap.get(techniqueId)!.add(tag.trim().toLowerCase());
    this.save();
    this.tagsSubject.next(new Map(this.tagsMap));
  }

  removeTag(techniqueId: string, tag: string): void {
    this.tagsMap.get(techniqueId)?.delete(tag);
    this.save();
    this.tagsSubject.next(new Map(this.tagsMap));
  }

  toggleTag(techniqueId: string, tag: string): void {
    const tags = this.tagsMap.get(techniqueId);
    if (tags?.has(tag)) this.removeTag(techniqueId, tag);
    else this.addTag(techniqueId, tag);
  }

  clearTags(techniqueId: string): void {
    this.tagsMap.delete(techniqueId);
    this.save();
    this.tagsSubject.next(new Map(this.tagsMap));
  }

  getAllUsedTags(): string[] {
    const all = new Set<string>();
    for (const tags of this.tagsMap.values()) for (const t of tags) all.add(t);
    return [...all].sort();
  }

  getTechniquesWithTag(tag: string): string[] {
    return [...this.tagsMap.entries()].filter(([, tags]) => tags.has(tag)).map(([id]) => id);
  }

  exportTags(): void {
    const data: Record<string, string[]> = {};
    for (const [id, tags] of this.tagsMap.entries()) if (tags.size > 0) data[id] = [...tags];
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'technique_tags.json'; a.click();
    URL.revokeObjectURL(url);
  }
}
