// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { SecurityControl, ControlStatus, FrameworkTemplate } from '../models/security-control';
import { Domain } from '../models/domain';

@Injectable({ providedIn: 'root' })
export class ControlsService {
  private readonly STORAGE_KEY = 'mitre-nav-controls-v1';
  private controlsSubject: BehaviorSubject<SecurityControl[]>;

  controls$: Observable<SecurityControl[]>;

  constructor() {
    this.controlsSubject = new BehaviorSubject<SecurityControl[]>(this.load());
    this.controls$ = this.controlsSubject.asObservable();
  }

  private load(): SecurityControl[] {
    try { return JSON.parse(localStorage.getItem(this.STORAGE_KEY) ?? '[]'); } catch { return []; }
  }

  private save(): void {
    localStorage.setItem(this.STORAGE_KEY, JSON.stringify(this.controlsSubject.value));
  }

  private newId(): string {
    return typeof crypto !== 'undefined' && crypto.randomUUID
      ? crypto.randomUUID()
      : Math.random().toString(36).slice(2);
  }

  addControl(ctrl: Omit<SecurityControl, 'id'>): void {
    this.controlsSubject.next([...this.controlsSubject.value, { ...ctrl, id: this.newId() }]);
    this.save();
  }

  updateControl(id: string, updates: Partial<Omit<SecurityControl, 'id'>>): void {
    this.controlsSubject.next(
      this.controlsSubject.value.map((c) => (c.id === id ? { ...c, ...updates } : c)),
    );
    this.save();
  }

  removeControl(id: string): void {
    this.controlsSubject.next(this.controlsSubject.value.filter((c) => c.id !== id));
    this.save();
  }

  /** Import all controls from a framework template, resolving ATT&CK IDs → STIX IDs via domain */
  importFromTemplate(template: FrameworkTemplate, domain: Domain, status: ControlStatus): number {
    const attackIdMap = new Map<string, string>();
    for (const m of domain.mitigations) attackIdMap.set(m.attackId, m.id);

    // Avoid duplicates: skip if same framework + ref already exists
    const existing = new Set(
      this.controlsSubject.value
        .filter((c) => c.framework === template.framework)
        .map((c) => c.controlRef),
    );

    const toAdd: SecurityControl[] = [];
    for (const ctrl of template.controls) {
      if (existing.has(ctrl.ref)) continue;
      const mitigationIds = ctrl.mitigationAttackIds
        .map((aid) => attackIdMap.get(aid))
        .filter((id): id is string => id !== undefined);
      toAdd.push({
        id: this.newId(),
        name: ctrl.name,
        framework: template.framework,
        controlRef: ctrl.ref,
        description: '',
        mitigationIds,
        status,
      });
    }

    if (toAdd.length > 0) {
      this.controlsSubject.next([...this.controlsSubject.value, ...toAdd]);
      this.save();
    }
    return toAdd.length;
  }

  clearAll(): void {
    this.controlsSubject.next([]);
    this.save();
  }

  exportJson(): string {
    return JSON.stringify(this.controlsSubject.value, null, 2);
  }

  importJson(json: string): void {
    try {
      const data = JSON.parse(json);
      if (Array.isArray(data)) {
        this.controlsSubject.next(data as SecurityControl[]);
        this.save();
      }
    } catch { /* ignore */ }
  }

  /** Compute sets of technique IDs covered by implemented/planned controls */
  computeCoverage(controls: SecurityControl[], domain: Domain): {
    coveredIds: Set<string>;
    plannedIds: Set<string>;
  } {
    const coveredIds = new Set<string>();
    const plannedIds = new Set<string>();

    for (const ctrl of controls) {
      const target = ctrl.status === 'implemented' ? coveredIds : plannedIds;
      for (const mitId of ctrl.mitigationIds) {
        const techs = domain.techniquesByMitigation.get(mitId) ?? [];
        for (const t of techs) target.add(t.id);
      }
    }

    // Planned shouldn't include already-covered
    for (const id of coveredIds) plannedIds.delete(id);

    return { coveredIds, plannedIds };
  }
}
