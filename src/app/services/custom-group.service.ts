// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface CustomGroup {
  id: string;              // "CG-001", etc.
  name: string;
  aliases: string[];
  description: string;
  techniqueIds: string[];  // ATT&CK IDs this group uses
  createdAt: string;
  updatedAt: string;
}

@Injectable({ providedIn: 'root' })
export class CustomGroupService {
  private readonly STORAGE_KEY = 'mitre-nav-custom-groups-v1';
  private groupsSubject = new BehaviorSubject<CustomGroup[]>(this.load());
  groups$ = this.groupsSubject.asObservable();

  private countSubject = new BehaviorSubject<number>(this.load().length);
  count$ = this.countSubject.asObservable();

  get all(): CustomGroup[] { return this.groupsSubject.value; }

  private nextId(): string {
    const existing = this.groupsSubject.value;
    if (existing.length === 0) return 'CG-001';
    const nums = existing
      .map(g => parseInt(g.id.replace('CG-', ''), 10))
      .filter(n => !isNaN(n));
    const max = nums.length ? Math.max(...nums) : 0;
    return `CG-${String(max + 1).padStart(3, '0')}`;
  }

  create(data: Omit<CustomGroup, 'id' | 'createdAt' | 'updatedAt'>): CustomGroup {
    const now = new Date().toISOString();
    const group: CustomGroup = {
      ...data,
      id: this.nextId(),
      createdAt: now,
      updatedAt: now,
    };
    const updated = [...this.groupsSubject.value, group];
    this.save(updated);
    this.groupsSubject.next(updated);
    this.countSubject.next(updated.length);
    return group;
  }

  update(id: string, data: Partial<CustomGroup>): void {
    const updated = this.groupsSubject.value.map(g =>
      g.id === id
        ? { ...g, ...data, id: g.id, createdAt: g.createdAt, updatedAt: new Date().toISOString() }
        : g
    );
    this.save(updated);
    this.groupsSubject.next(updated);
    this.countSubject.next(updated.length);
  }

  delete(id: string): void {
    const updated = this.groupsSubject.value.filter(g => g.id !== id);
    this.save(updated);
    this.groupsSubject.next(updated);
    this.countSubject.next(updated.length);
  }

  getAll(): CustomGroup[] {
    return this.groupsSubject.value;
  }

  getById(id: string): CustomGroup | undefined {
    return this.groupsSubject.value.find(g => g.id === id);
  }

  getForTechnique(techniqueId: string): CustomGroup[] {
    return this.groupsSubject.value.filter(g =>
      g.techniqueIds.includes(techniqueId)
    );
  }

  private load(): CustomGroup[] {
    try {
      const raw = localStorage.getItem(this.STORAGE_KEY);
      if (!raw) return [];
      return JSON.parse(raw) as CustomGroup[];
    } catch {
      return [];
    }
  }

  private save(groups: CustomGroup[]): void {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(groups));
    } catch { /* ignore quota errors */ }
  }
}
