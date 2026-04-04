import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface TechniqueAnnotation {
  techniqueId: string;
  note: string;
  color: 'default' | 'red' | 'yellow' | 'green' | 'blue';
  isPinned: boolean;
  updatedAt: string;
}

@Injectable({ providedIn: 'root' })
export class AnnotationService {
  private readonly STORAGE_KEY = 'mitre-nav-annotations-v1';
  private annotationsSubject = new BehaviorSubject<Map<string, TechniqueAnnotation>>(this.load());
  annotations$ = this.annotationsSubject.asObservable();

  get all(): Map<string, TechniqueAnnotation> {
    return this.annotationsSubject.value;
  }

  setAnnotation(techniqueId: string, note: string, color?: string, isPinned?: boolean): void {
    const map = new Map(this.annotationsSubject.value);
    const validColor = (['default', 'red', 'yellow', 'green', 'blue'].includes(color ?? ''))
      ? (color as TechniqueAnnotation['color'])
      : 'default';
    map.set(techniqueId, {
      techniqueId,
      note,
      color: validColor,
      isPinned: isPinned ?? false,
      updatedAt: new Date().toISOString(),
    });
    this.annotationsSubject.next(map);
    this.save(map);
  }

  getAnnotation(techniqueId: string): TechniqueAnnotation | undefined {
    return this.annotationsSubject.value.get(techniqueId);
  }

  deleteAnnotation(techniqueId: string): void {
    const map = new Map(this.annotationsSubject.value);
    map.delete(techniqueId);
    this.annotationsSubject.next(map);
    this.save(map);
  }

  hasAnnotation(techniqueId: string): boolean {
    return this.annotationsSubject.value.has(techniqueId);
  }

  private load(): Map<string, TechniqueAnnotation> {
    try {
      const raw = localStorage.getItem(this.STORAGE_KEY);
      if (!raw) return new Map();
      const arr: TechniqueAnnotation[] = JSON.parse(raw);
      return new Map(arr.map(a => [a.techniqueId, a]));
    } catch {
      return new Map();
    }
  }

  private save(map: Map<string, TechniqueAnnotation>): void {
    try {
      const arr = Array.from(map.values());
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(arr));
    } catch { /* ignore quota errors */ }
  }
}
