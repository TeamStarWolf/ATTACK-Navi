// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// One place that starts a technique's per-technique live fetches (technique
// page design 4.4, PR 1): the D3FEND live countermeasures and the Atomic Red
// Team YAML. Both hosts call it: the drawer's selection subscriber and the
// technique page once its technique resolves. Before it, only the drawer asked
// for the live D3FEND answer, so a pasted #/technique link counted the bundled
// seed (T1037: 0) while the same link reached through the drawer's Full page
// counted the live answer (T1037: 20).
//
// Each fetch runs once per technique. D3fendService already dedupes its live
// request and records a failure on the 'd3fend-technique-api' source (the
// data-health Retry fetches it again). The Atomic YAML is shared: every caller
// for one technique gets the one request's answer. A failed Atomic request is
// recorded on the 'atomic-tests' source by AtomicService and is not kept, so
// the next prime for that technique asks again, as the drawer did on every
// selection before. The coordinator holds no data of its own and makes no
// request at construction, so creating it moves no boot load.
import { Injectable, inject } from '@angular/core';
import { Observable, ReplaySubject, finalize } from 'rxjs';
import type { Technique } from '../models/technique';
import { AtomicLiveTest, AtomicService } from './atomic.service';
import { D3fendService } from './d3fend.service';

/** How many Atomic tests the drawer lists by name (its section shows the first five). */
export const ATOMIC_LIVE_LIMIT = 5;

/** Where one technique's Atomic YAML stands. */
export type AtomicFetchState = 'loading' | 'loaded' | 'failed';

@Injectable({ providedIn: 'root' })
export class TechniqueFetchCoordinator {
  private readonly d3fend = inject(D3fendService);
  private readonly atomic = inject(AtomicService);

  /** Techniques whose D3FEND live call has been asked for this session. */
  private readonly d3fendAsked = new Set<string>();
  /** One shared Atomic answer per technique, while in flight or once answered. */
  private readonly atomicLive = new Map<string, ReplaySubject<AtomicLiveTest[]>>();
  private readonly atomicStates = new Map<string, AtomicFetchState>();

  /**
   * Start the technique's per-technique live fetches: the D3FEND live call (for a
   * sub-technique, its parent's too, as D3fendService does) and the Atomic YAML.
   * A second prime for the same technique starts nothing.
   */
  prime(technique: Pick<Technique, 'attackId'>): void {
    const id = technique.attackId;
    if (!id) return;
    if (!this.d3fendAsked.has(id)) {
      this.d3fendAsked.add(id);
      this.d3fend.getCountermeasures(id, true);
    }
    this.atomicTests(technique);
  }

  /**
   * The technique's live Atomic tests (the first ATOMIC_LIVE_LIMIT), primed if no
   * one has asked yet. Every subscriber for one technique shares one request; the
   * answer is replayed to a later subscriber.
   */
  atomicTests(technique: Pick<Technique, 'attackId'>): Observable<AtomicLiveTest[]> {
    const id = technique.attackId;
    const existing = this.atomicLive.get(id);
    if (existing) return existing.asObservable();
    const shared = new ReplaySubject<AtomicLiveTest[]>(1);
    this.atomicLive.set(id, shared);
    this.atomicStates.set(id, 'loading');
    this.atomic.fetchLiveTests(id, ATOMIC_LIVE_LIMIT).pipe(
      finalize(() => {
        // AtomicService answers [] on a failure too; only a kept answer is one.
        const answered = this.atomic.hasLiveAnswer(id);
        this.atomicStates.set(id, answered ? 'loaded' : 'failed');
        if (!answered) this.atomicLive.delete(id);
      }),
    ).subscribe(shared);
    return shared.asObservable();
  }

  /** Where the technique's Atomic YAML stands; null when no one has asked for it. */
  atomicState(attackId: string): AtomicFetchState | null {
    return this.atomicStates.get(attackId) ?? null;
  }

  /** True once prime has run for the technique this session. */
  isPrimed(attackId: string): boolean {
    return this.d3fendAsked.has(attackId);
  }
}
