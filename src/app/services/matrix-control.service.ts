// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, Signal, signal } from '@angular/core';
import { BehaviorSubject, Observable, Subject } from 'rxjs';

/** The slice of MatrixComponent's API that global chrome may drive. */
export interface MatrixApi {
  expandAll(): void;
  collapseAll(): void;
  toggleMultiSelectMode(): void;
  readonly multiSelectMode: boolean;
}

/**
 * The matrix's score for the selected technique on the legacy lens on screen
 * (P2-18): what the evidence card's "Why this colour" reads as
 * 'score N of max M'. Legacy lenses are scored inside MatrixComponent only.
 */
export interface LegacyLensReadout {
  /** STIX id of the technique. */
  readonly techId: string;
  /** The heatmap mode (lens id) the score belongs to. */
  readonly mode: string;
  readonly score: number;
  /** The highest score in the loaded domain (or the top of an absolute ramp). */
  readonly max: number;
}

function sameReadout(a: LegacyLensReadout | null, b: LegacyLensReadout | null): boolean {
  if (a === null || b === null) return a === b;
  return a.techId === b.techId && a.mode === b.mode && a.score === b.score && a.max === b.max;
}

/**
 * Decouples the toolbar (global chrome) from the matrix (a routed page).
 * The matrix registers itself while mounted; the toolbar invokes actions
 * through this service instead of a ViewChild reference. Calls while no
 * matrix is registered (user is on another workspace) are no-ops.
 */
@Injectable({ providedIn: 'root' })
export class MatrixControlService {
  private matrix: MatrixApi | null = null;
  private readonly multiSelectModeSubject = new BehaviorSubject<boolean>(false);
  readonly multiSelectMode$: Observable<boolean> = this.multiSelectModeSubject.asObservable();

  register(matrix: MatrixApi): void {
    this.matrix = matrix;
    this.multiSelectModeSubject.next(matrix.multiSelectMode);
  }

  unregister(matrix: MatrixApi): void {
    if (this.matrix === matrix) {
      this.matrix = null;
      this.multiSelectModeSubject.next(false);
      this.readoutSig.set(null);
    }
  }

  private readonly readoutSig = signal<LegacyLensReadout | null>(null);
  /** The matrix's legacy-lens score for the selected technique; null while no matrix has scored one. */
  readonly legacyReadout: Signal<LegacyLensReadout | null> = this.readoutSig.asReadonly();

  /** The matrix publishes its readout here; an unchanged readout writes nothing. */
  publishReadout(readout: LegacyLensReadout | null): void {
    if (!sameReadout(readout, this.readoutSig())) this.readoutSig.set(readout);
  }

  /** True when `readout` equals the published one (the matrix checks before it schedules a publish). */
  isPublished(readout: LegacyLensReadout | null): boolean {
    return sameReadout(readout, this.readoutSig());
  }

  get isAvailable(): boolean {
    return this.matrix !== null;
  }

  expandAll(): void {
    this.matrix?.expandAll();
  }

  collapseAll(): void {
    this.matrix?.collapseAll();
  }

  toggleMultiSelect(): void {
    this.matrix?.toggleMultiSelectMode();
    this.multiSelectModeSubject.next(this.matrix?.multiSelectMode ?? false);
  }

  /** Matrix pushes state changes it makes on its own (e.g. Escape clears). */
  notifyMultiSelectMode(value: boolean): void {
    this.multiSelectModeSubject.next(value);
  }

  /** Gap-view overlay requests (the overlay is hosted by AppComponent). */
  private readonly gapViewSubject = new Subject<void>();
  readonly gapViewRequests$: Observable<void> = this.gapViewSubject.asObservable();

  requestGapView(): void {
    this.gapViewSubject.next();
  }
}
