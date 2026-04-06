// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

export interface MitigationDoc {
  notes: string;
  owner: string;
  dueDate: string;       // ISO date string "YYYY-MM-DD"
  controlRefs: string;   // Comma-separated: "NIST AC-2, CIS 5.1, ISO A.9.2"
  evidenceUrl: string;
}

export interface TechniqueNote {
  notes: string;
}

const MIT_STORAGE_KEY = 'mitre-nav-docs-mit-v1';
const TECH_STORAGE_KEY = 'mitre-nav-docs-tech-v1';

const EMPTY_DOC: MitigationDoc = { notes: '', owner: '', dueDate: '', controlRefs: '', evidenceUrl: '' };

@Injectable({ providedIn: 'root' })
export class DocumentationService {
  private mitDocsSubject = new BehaviorSubject<Map<string, MitigationDoc>>(this.loadMitDocs());
  private techNotesSubject = new BehaviorSubject<Map<string, string>>(this.loadTechNotes());

  mitDocs$: Observable<Map<string, MitigationDoc>> = this.mitDocsSubject.asObservable();
  techNotes$: Observable<Map<string, string>> = this.techNotesSubject.asObservable();

  getMitDoc(mitigationId: string): MitigationDoc {
    return this.mitDocsSubject.value.get(mitigationId) ?? { ...EMPTY_DOC };
  }

  setMitDoc(mitigationId: string, doc: MitigationDoc): void {
    const next = new Map(this.mitDocsSubject.value);
    const isEmpty = !doc.notes && !doc.owner && !doc.dueDate && !doc.controlRefs && !doc.evidenceUrl;
    if (isEmpty) next.delete(mitigationId);
    else next.set(mitigationId, doc);
    this.mitDocsSubject.next(next);
    this.saveMitDocs(next);
  }

  getTechNote(techniqueId: string): string {
    return this.techNotesSubject.value.get(techniqueId) ?? '';
  }

  setTechNote(techniqueId: string, note: string): void {
    const next = new Map(this.techNotesSubject.value);
    if (note.trim()) next.set(techniqueId, note);
    else next.delete(techniqueId);
    this.techNotesSubject.next(next);
    this.saveTechNotes(next);
  }

  exportJson(): string {
    return JSON.stringify({
      mitigations: Object.fromEntries(this.mitDocsSubject.value),
      techniques: Object.fromEntries(this.techNotesSubject.value),
    }, null, 2);
  }

  importJson(json: string): void {
    let data: any;
    try {
      data = JSON.parse(json);
    } catch {
      throw new Error('Invalid JSON');
    }
    if (!data || typeof data !== 'object') throw new Error('Invalid documentation data');
    if (data.mitigations && typeof data.mitigations === 'object') {
      const map = new Map<string, MitigationDoc>();
      for (const [k, v] of Object.entries(data.mitigations)) {
        if (typeof k === 'string' && v && typeof v === 'object') {
          map.set(k, {
            notes: typeof (v as any).notes === 'string' ? (v as any).notes : '',
            owner: typeof (v as any).owner === 'string' ? (v as any).owner : '',
            dueDate: typeof (v as any).dueDate === 'string' ? (v as any).dueDate : '',
            controlRefs: typeof (v as any).controlRefs === 'string' ? (v as any).controlRefs : '',
            evidenceUrl: typeof (v as any).evidenceUrl === 'string' ? (v as any).evidenceUrl : '',
          });
        }
      }
      this.mitDocsSubject.next(map);
      this.saveMitDocs(map);
    }
    if (data.techniques && typeof data.techniques === 'object') {
      const map = new Map<string, string>();
      for (const [k, v] of Object.entries(data.techniques)) {
        if (typeof k === 'string' && typeof v === 'string') map.set(k, v);
      }
      this.techNotesSubject.next(map);
      this.saveTechNotes(map);
    }
  }

  private loadMitDocs(): Map<string, MitigationDoc> {
    try {
      const raw = localStorage.getItem(MIT_STORAGE_KEY);
      if (!raw) return new Map();
      return new Map(Object.entries(JSON.parse(raw)));
    } catch { return new Map(); }
  }

  private saveMitDocs(map: Map<string, MitigationDoc>): void {
    try { localStorage.setItem(MIT_STORAGE_KEY, JSON.stringify(Object.fromEntries(map))); } catch { /* quota */ }
  }

  private loadTechNotes(): Map<string, string> {
    try {
      const raw = localStorage.getItem(TECH_STORAGE_KEY);
      if (!raw) return new Map();
      return new Map(Object.entries(JSON.parse(raw)));
    } catch { return new Map(); }
  }

  private saveTechNotes(map: Map<string, string>): void {
    try { localStorage.setItem(TECH_STORAGE_KEY, JSON.stringify(Object.fromEntries(map))); } catch { /* quota */ }
  }
}
