// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, Subject } from 'rxjs';

/** The slice of MatrixComponent's API that global chrome may drive. */
export interface MatrixApi {
  expandAll(): void;
  collapseAll(): void;
  toggleMultiSelectMode(): void;
  readonly multiSelectMode: boolean;
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
    }
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
