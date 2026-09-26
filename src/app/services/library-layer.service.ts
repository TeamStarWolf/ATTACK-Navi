// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, catchError, of } from 'rxjs';

/** One entry in the library-layers manifest (index.json). */
export interface LibraryLayerMeta {
  file: string;
  name: string;
  description: string;
  /** Short human-readable tooltip text (optional; falls back to description). */
  blurb?: string;
}

interface LayerTechnique {
  techniqueID: string;
  tactic?: string;
  score?: number;
  comment?: string;
}
interface LibraryLayerFile {
  name: string;
  description: string;
  techniques: LayerTechnique[];
}

const BASE = 'assets/data/library-layers/';

/**
 * Loads the curated "library layers" (MITRE Navigator layer JSON authored in
 * the TeamStarWolf reference library, e.g. Web Application Attacks, CWE
 * weakness classes) and exposes the active layer's per-technique scores so the
 * matrix can color by it under the `library` heatmap mode.
 */
@Injectable({ providedIn: 'root' })
export class LibraryLayerService {
  private manifestSubject = new BehaviorSubject<LibraryLayerMeta[]>([]);
  readonly manifest$ = this.manifestSubject.asObservable();

  private activeFileSubject = new BehaviorSubject<string | null>(null);
  readonly activeFile$ = this.activeFileSubject.asObservable();

  /** Emits whenever the active layer's score map changes (loaded or switched). */
  private changedSubject = new BehaviorSubject<boolean>(false);
  readonly changed$ = this.changedSubject.asObservable();

  private scores = new Map<string, number>();
  private cache = new Map<string, Map<string, number>>();

  constructor(private http: HttpClient) {
    this.http
      .get<LibraryLayerMeta[]>(`${BASE}index.json`)
      .pipe(catchError(() => of([] as LibraryLayerMeta[])))
      .subscribe(list => this.manifestSubject.next(Array.isArray(list) ? list : []));
  }

  get manifest(): LibraryLayerMeta[] {
    return this.manifestSubject.value;
  }
  get activeFile(): string | null {
    return this.activeFileSubject.value;
  }
  activeMeta(): LibraryLayerMeta | undefined {
    return this.manifest.find(m => m.file === this.activeFile);
  }

  getScore(attackId: string): number {
    return this.scores.get(attackId) ?? 0;
  }
  maxScore(): number {
    return this.scores.size ? Math.max(...this.scores.values()) : 1;
  }

  /** Select a layer by manifest file name and load its scores (cached). */
  setActive(file: string): void {
    this.activeFileSubject.next(file);
    const cached = this.cache.get(file);
    if (cached) {
      this.scores = cached;
      this.changedSubject.next(true);
      return;
    }
    this.http
      .get<LibraryLayerFile>(`${BASE}${file}`)
      .pipe(catchError(() => of(null)))
      .subscribe(data => {
        const map = new Map<string, number>();
        for (const t of data?.techniques ?? []) {
          if (t.techniqueID) map.set(t.techniqueID, t.score ?? 100);
        }
        this.cache.set(file, map);
        this.scores = map;
        this.changedSubject.next(true);
      });
  }
}
