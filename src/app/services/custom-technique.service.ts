// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface CustomTechnique {
  id: string;              // "CT-001", "CT-002", etc.
  attackId: string;        // User-specified, e.g. "T9001"
  name: string;
  description: string;
  tacticShortnames: string[];  // e.g. ["execution", "persistence"]
  platforms: string[];     // e.g. ["Windows", "Linux"]
  dataSources: string[];
  isSubtechnique: boolean;
  parentId: string | null;
  createdAt: string;       // ISO
  updatedAt: string;       // ISO
}

@Injectable({ providedIn: 'root' })
export class CustomTechniqueService {
  private readonly STORAGE_KEY = 'mitre-nav-custom-techniques-v1';
  private techniquesSubject = new BehaviorSubject<CustomTechnique[]>(this.load());
  techniques$ = this.techniquesSubject.asObservable();

  private countSubject = new BehaviorSubject<number>(this.load().length);
  count$ = this.countSubject.asObservable();

  get all(): CustomTechnique[] { return this.techniquesSubject.value; }

  private nextId(): string {
    const existing = this.techniquesSubject.value;
    if (existing.length === 0) return 'CT-001';
    const nums = existing
      .map(t => parseInt(t.id.replace('CT-', ''), 10))
      .filter(n => !isNaN(n));
    const max = nums.length ? Math.max(...nums) : 0;
    return `CT-${String(max + 1).padStart(3, '0')}`;
  }

  create(data: Omit<CustomTechnique, 'id' | 'createdAt' | 'updatedAt'>): CustomTechnique {
    const now = new Date().toISOString();
    const technique: CustomTechnique = {
      ...data,
      id: this.nextId(),
      createdAt: now,
      updatedAt: now,
    };
    const updated = [...this.techniquesSubject.value, technique];
    this.save(updated);
    this.techniquesSubject.next(updated);
    this.countSubject.next(updated.length);
    return technique;
  }

  update(id: string, data: Partial<CustomTechnique>): void {
    const updated = this.techniquesSubject.value.map(t =>
      t.id === id
        ? { ...t, ...data, id: t.id, createdAt: t.createdAt, updatedAt: new Date().toISOString() }
        : t
    );
    this.save(updated);
    this.techniquesSubject.next(updated);
    this.countSubject.next(updated.length);
  }

  delete(id: string): void {
    const updated = this.techniquesSubject.value.filter(t => t.id !== id);
    this.save(updated);
    this.techniquesSubject.next(updated);
    this.countSubject.next(updated.length);
  }

  getAll(): CustomTechnique[] {
    return this.techniquesSubject.value;
  }

  getById(id: string): CustomTechnique | undefined {
    return this.techniquesSubject.value.find(t => t.id === id);
  }

  getForTactic(shortname: string): CustomTechnique[] {
    return this.techniquesSubject.value.filter(t =>
      t.tacticShortnames.includes(shortname)
    );
  }

  private load(): CustomTechnique[] {
    try {
      const raw = localStorage.getItem(this.STORAGE_KEY);
      if (!raw) return [];
      return JSON.parse(raw) as CustomTechnique[];
    } catch {
      return [];
    }
  }

  private save(techniques: CustomTechnique[]): void {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(techniques));
    } catch { /* ignore quota errors */ }
  }
}
