// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The Live Defense lens's data source. It loads two bundled, same-origin assets
// that scripts/build-live-defense.mjs generates from the CISA KEV snapshot:
//
//   live-defense.layer.json     per-technique heat (0-100) for the matrix lens;
//   live-defense.evidence.json  the sourced items + brief behind each heat, for
//                               the cell-detail panel (LiveDefenseEvidenceComponent).
//
// Both are dated to the KEV snapshot the brain read, and keyed by techniqueID.
// Loading is fail-quiet: a fetch that fails leaves the scores empty, so no cell
// heats and the lens reads as "no data" rather than a false zero. Nothing here
// recomputes heat — the number a cell shows is exactly what the gated, committed
// artifact says, so the matrix and the panel can never disagree.
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, forkJoin, of } from 'rxjs';
import { catchError } from 'rxjs/operators';

const LAYER_URL = 'assets/data/live-defense/live-defense.layer.json';
const EVIDENCE_URL = 'assets/data/live-defense/live-defense.evidence.json';

/** One sourced KEV item behind a technique's heat. */
export interface LiveDefenseItem {
  cve: string;
  source: string;
  url: string;
  dateAdded: string;
  knownRansomware: boolean;
  confidence: 'high' | 'medium';
  quote: string;
  cwes: string[];
  via: string;
  weight: number;
}

/** The evidence for one technique's heat (evidence.json value). */
export interface LiveDefenseEvidence {
  techniqueID: string;
  name: string;
  rank: number;
  score: number;
  heat: number;
  confidence: 'high' | 'medium';
  itemCount: number;
  ransomwareCount: number;
  breakdown: { halfLifeDays: number; ransomwareBonus: number; asOf: string; itemsShown: number };
  brief: string;
  items: LiveDefenseItem[];
}

interface LayerDoc {
  techniques: Array<{ techniqueID: string; score?: number }>;
  __meta?: { snapshotDate?: string };
}
interface EvidenceDoc {
  __meta?: { snapshotDate?: string };
  techniques: Record<string, LiveDefenseEvidence>;
}

@Injectable({ providedIn: 'root' })
export class LiveDefenseService {
  private readonly http = inject(HttpClient);

  private readonly scoresSubject = new BehaviorSubject<Map<string, number>>(new Map());
  /** techniqueID -> 0-100 heat score; empty until (and unless) the layer loads. */
  readonly scores$ = this.scoresSubject.asObservable();

  private readonly loadedSubject = new BehaviorSubject<boolean>(false);
  /** True only once both artifacts have genuinely parsed. */
  readonly loaded$ = this.loadedSubject.asObservable();

  private readonly asOfSubject = new BehaviorSubject<string | null>(null);
  /** The KEV snapshot date the artifacts were built from (the "updated <date>" stamp); null until loaded. */
  readonly asOf$ = this.asOfSubject.asObservable();

  private evidence = new Map<string, LiveDefenseEvidence>();
  private loading = false;

  /**
   * Load both artifacts once, the first time the Live Defense lens is chosen
   * (MatrixComponent calls this on the mode switch, like the KEV and PoC lenses);
   * never at app start. Idempotent, and any failure leaves the lens empty (fail quiet).
   */
  load(): void {
    if (this.loading || this.loadedSubject.value) return;
    this.loading = true;
    forkJoin({
      layer: this.http.get<LayerDoc>(LAYER_URL).pipe(catchError(() => of(null))),
      evidence: this.http.get<EvidenceDoc>(EVIDENCE_URL).pipe(catchError(() => of(null))),
    }).subscribe(({ layer, evidence }) => {
      this.loading = false;
      if (!layer?.techniques?.length || !evidence?.techniques) return; // fail quiet; a later call may retry
      const scores = new Map<string, number>();
      for (const t of layer.techniques) {
        const score = t.score ?? 0;
        if (t.techniqueID && score > 0) scores.set(t.techniqueID, score);
      }
      // Keep only well-shaped entries, so a truncated or hand-edited file cannot throw
      // in the drawer's change detection (the panel then shows nothing for that id).
      const entries = Object.entries(evidence.techniques).filter(
        ([, e]) => e && e.breakdown && Array.isArray(e.items) && typeof e.brief === 'string',
      );
      this.evidence = new Map(entries);
      this.asOfSubject.next(evidence.__meta?.snapshotDate ?? layer.__meta?.snapshotDate ?? null);
      this.scoresSubject.next(scores);
      this.loadedSubject.next(true);
    });
  }

  /** 0-100 heat for a technique, 0 when it is below the confidence bar or absent (fail quiet). */
  getScore(attackId: string): number {
    return this.scoresSubject.value.get(attackId) ?? 0;
  }

  /** The highest heat on hand, or 1 when nothing loaded (keeps the relative ramp well-defined). */
  get maxScore(): number {
    const values = [...this.scoresSubject.value.values()];
    return values.length ? Math.max(...values) : 1;
  }

  /** The sourced evidence behind a technique's heat, or null when it does not heat. */
  getEvidence(attackId: string): LiveDefenseEvidence | null {
    return this.evidence.get(attackId) ?? null;
  }

  /** The "updated <date>" stamp, or null before the artifacts load. */
  get asOf(): string | null {
    return this.asOfSubject.value;
  }
}
