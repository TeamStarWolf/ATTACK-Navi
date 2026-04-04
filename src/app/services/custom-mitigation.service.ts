import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import { ImplStatus } from './implementation.service';

export interface CustomMitigation {
  id: string;           // "CM-001", "CM-002" etc (auto-generated, user-readable)
  name: string;         // "EDR - Suspicious PowerShell Block"
  description: string;  // what this control does
  category: string;     // "EDR", "SIEM", "Network", "Email", "IAM", "Endpoint", "Custom"
  techniqueIds: string[]; // ATT&CK technique IDs this applies to (T1059, T1078.001 etc)
  createdAt: string;    // ISO date
  updatedAt: string;    // ISO date
  implStatus: ImplStatus | null; // implementation status of this custom mitigation
}

@Injectable({ providedIn: 'root' })
export class CustomMitigationService {
  private readonly STORAGE_KEY = 'mitre-nav-custom-mitigations-v1';
  private mitigationsSubject = new BehaviorSubject<CustomMitigation[]>(this.load());
  mitigations$ = this.mitigationsSubject.asObservable();

  get all(): CustomMitigation[] { return this.mitigationsSubject.value; }

  private nextId(): string {
    const existing = this.mitigationsSubject.value;
    if (existing.length === 0) return 'CM-001';
    const nums = existing
      .map(m => parseInt(m.id.replace('CM-', ''), 10))
      .filter(n => !isNaN(n));
    const max = nums.length ? Math.max(...nums) : 0;
    return `CM-${String(max + 1).padStart(3, '0')}`;
  }

  create(data: Omit<CustomMitigation, 'id' | 'createdAt' | 'updatedAt'>): CustomMitigation {
    const now = new Date().toISOString();
    const mit: CustomMitigation = {
      ...data,
      id: this.nextId(),
      createdAt: now,
      updatedAt: now,
    };
    const updated = [...this.mitigationsSubject.value, mit];
    this.save(updated);
    this.mitigationsSubject.next(updated);
    return mit;
  }

  update(id: string, data: Partial<CustomMitigation>): void {
    const updated = this.mitigationsSubject.value.map(m =>
      m.id === id
        ? { ...m, ...data, id: m.id, createdAt: m.createdAt, updatedAt: new Date().toISOString() }
        : m
    );
    this.save(updated);
    this.mitigationsSubject.next(updated);
  }

  delete(id: string): void {
    const updated = this.mitigationsSubject.value.filter(m => m.id !== id);
    this.save(updated);
    this.mitigationsSubject.next(updated);
  }

  getForTechnique(techniqueId: string): CustomMitigation[] {
    return this.mitigationsSubject.value.filter(m =>
      m.techniqueIds.includes(techniqueId)
    );
  }

  getTechniqueIds(mitigationId: string): string[] {
    return this.mitigationsSubject.value.find(m => m.id === mitigationId)?.techniqueIds ?? [];
  }

  private load(): CustomMitigation[] {
    try {
      const raw = localStorage.getItem(this.STORAGE_KEY);
      if (!raw) return [];
      return JSON.parse(raw) as CustomMitigation[];
    } catch {
      return [];
    }
  }

  private save(mits: CustomMitigation[]): void {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(mits));
    } catch { /* ignore quota errors */ }
  }
}
