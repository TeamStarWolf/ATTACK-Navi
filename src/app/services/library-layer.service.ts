// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { SourceRegistryService, describeLoadError } from './source-registry.service';

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

  /** True once the manifest has loaded. A failed request never sets it; see manifestError$. */
  private manifestLoadedSubject = new BehaviorSubject<boolean>(false);
  readonly manifestLoaded$ = this.manifestLoadedSubject.asObservable();

  /** Why the manifest did not load, or null. */
  private manifestErrorSubject = new BehaviorSubject<string | null>(null);
  readonly manifestError$ = this.manifestErrorSubject.asObservable();

  private activeFileSubject = new BehaviorSubject<string | null>(null);
  readonly activeFile$ = this.activeFileSubject.asObservable();

  /** Emits whenever the active layer's score map changes (loaded or switched). */
  private changedSubject = new BehaviorSubject<boolean>(false);
  readonly changed$ = this.changedSubject.asObservable();

  private scores = new Map<string, number>();
  private cache = new Map<string, Map<string, number>>();

  /**
   * Set when a library view was requested before the manifest arrived, so the
   * default layer can be selected the moment it does rather than never.
   */
  private pendingDefault = false;

  constructor(
    private http: HttpClient,
    private sources: SourceRegistryService = new SourceRegistryService(),
  ) {
    this.loadManifest();
  }

  /**
   * Load again after a failure: the data-health Retry (E1.3). A failed manifest is
   * fetched again; otherwise the active layer file (never cached after a failure) is.
   */
  retry(): void {
    if (!this.manifestLoaded) this.loadManifest();
    else if (this.activeFile) this.setActive(this.activeFile);
  }

  private loadManifest(): void {
    this.sources.begin('library-layers');
    this.manifestErrorSubject.next(null);
    this.http
      .get<LibraryLayerMeta[]>(`${BASE}index.json`)
      .subscribe({
        next: list => {
          const layers = Array.isArray(list) ? list : [];
          this.manifestSubject.next(layers);
          this.sources.succeed('library-layers', layers.length);
          this.manifestLoadedSubject.next(true);
          if (this.pendingDefault) {
            this.pendingDefault = false;
            this.ensureActive();
          }
        },
        error: err => {
          // Recorded as failed; the matrix controls show the reason, not an empty list.
          this.sources.fail('library-layers', err);
          this.manifestErrorSubject.next(this.sources.get('library-layers').lastError);
        },
      });
  }

  get manifest(): LibraryLayerMeta[] {
    return this.manifestSubject.value;
  }
  get manifestLoaded(): boolean {
    return this.manifestLoadedSubject.value;
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

  /**
   * Make sure some layer is active for a library view: keep the current one,
   * otherwise select the manifest's first entry, and if the manifest has not
   * arrived yet, do so as soon as it does. Before this, a `heat=library` share
   * link opened before index.json resolved painted every cell "not in layer"
   * and nothing ever selected a layer.
   */
  ensureActive(): void {
    if (this.activeFile) return;
    if (this.manifest.length) {
      this.setActive(this.manifest[0].file);
    } else if (!this.manifestLoaded) {
      this.pendingDefault = true;
    }
  }

  /** Select a layer by manifest file name and load its scores (cached). */
  setActive(file: string): void {
    this.pendingDefault = false;
    this.activeFileSubject.next(file);
    const cached = this.cache.get(file);
    if (cached) {
      this.scores = cached;
      this.changedSubject.next(true);
      return;
    }
    this.http
      .get<LibraryLayerFile>(`${BASE}${file}`)
      .subscribe({
        next: data => {
          const map = new Map<string, number>();
          for (const t of data?.techniques ?? []) {
            if (t.techniqueID) map.set(t.techniqueID, t.score ?? 100);
          }
          this.cache.set(file, map);
          // Ordering guard: a slow response for a layer the user has since moved
          // away from populates the cache but must not replace the active scores.
          if (this.activeFileSubject.value !== file) return;
          this.scores = map;
          this.changedSubject.next(true);
        },
        error: err => {
          // A layer file that failed is recorded as failed and not cached as an empty
          // layer, so choosing it again retries.
          this.sources.fail('library-layers', `${file}: ${describeLoadError(err)}`);
          if (this.activeFileSubject.value !== file) return;
          this.scores = new Map();
          this.changedSubject.next(true);
        },
      });
  }
}
