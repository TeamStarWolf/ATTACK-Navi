// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, catchError, of } from 'rxjs';

/**
 * CTID's F3 Fraud Framework (ctid.mitre.org/fraud) — ATT&CK-convention STIX.
 *
 * The framework reuses ATT&CK technique ids for the techniques it shares with
 * Enterprise ATT&CK (T-prefixed external ids) and mints its own F-prefixed ids for
 * fraud-native techniques. This service loads the bundled F3 bundle once and indexes
 * ONLY the shared (T-prefixed) techniques — those are exactly the ATT&CK techniques that
 * also carry a fraud interpretation, so a CVE's ATT&CK technique "has an F3 mapping" iff
 * its id is in that set.
 *
 * Kept separate from DataService (which treats F3 as a whole switchable domain) so the
 * dossier can answer "does this Enterprise technique overlap F3?" without leaving the
 * Enterprise domain or triggering a domain switch. Never throws: a failed load leaves the
 * overlap set empty, so the dossier's F3 section renders "none found", not an error.
 */
export interface F3Overlap {
  /** The shared ATT&CK technique id (e.g. "T1557"). */
  id: string;
  /** The technique's name in the F3 Fraud Framework (may differ from ATT&CK's). */
  name: string;
  /** Link to the technique on the F3 Fraud Framework site. */
  url: string;
}

const F3_ASSET = 'assets/data/f3-attack.json';

@Injectable({ providedIn: 'root' })
export class F3FraudService {
  /** attackId -> F3 overlap, for the T-prefixed (ATT&CK-shared) F3 techniques only. */
  private overlap = new Map<string, F3Overlap>();
  private started = false;
  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$: Observable<boolean> = this.loadedSubject.asObservable();

  constructor(private http: HttpClient) {}

  /** True once the bundle has been parsed (success or failure). */
  get loaded(): boolean {
    return this.loadedSubject.value;
  }

  /** Number of ATT&CK techniques that carry an F3 fraud interpretation. */
  get overlapCount(): number {
    return this.overlap.size;
  }

  /** Begin loading the F3 bundle once. Idempotent. */
  ensureLoaded(): void {
    if (this.started) return;
    this.started = true;
    this.http
      .get<{ objects?: any[] }>(F3_ASSET)
      .pipe(catchError(() => of(null)))
      .subscribe(bundle => {
        this.index(bundle?.objects ?? []);
        this.loadedSubject.next(true);
      });
  }

  /**
   * The F3 overlap for an ATT&CK technique, or null when it has none. A sub-technique
   * (T1110.001) falls back to its parent (T1110): the F3 framework maps at the parent
   * level, so a sub-technique still inherits the parent's fraud interpretation.
   */
  getOverlap(attackId: string): F3Overlap | null {
    if (!attackId) return null;
    const direct = this.overlap.get(attackId);
    if (direct) return direct;
    const dot = attackId.indexOf('.');
    if (dot > 0) return this.overlap.get(attackId.slice(0, dot)) ?? null;
    return null;
  }

  hasOverlap(attackId: string): boolean {
    return this.getOverlap(attackId) !== null;
  }

  private index(objects: any[]): void {
    for (const obj of objects) {
      if (obj?.type !== 'attack-pattern' || obj.revoked || obj.x_mitre_deprecated) continue;
      for (const ref of obj.external_references ?? []) {
        const id: string | undefined = ref?.external_id;
        // Only the shared, ATT&CK-convention (T-prefixed) ids are an overlap.
        if (ref?.source_name?.startsWith('mitre-') && id && id.startsWith('T')) {
          this.overlap.set(id, {
            id,
            name: obj.name ?? id,
            url: ref.url ?? `https://ctid.mitre.org/fraud/techniques/${id}`,
          });
          break;
        }
      }
    }
  }
}
