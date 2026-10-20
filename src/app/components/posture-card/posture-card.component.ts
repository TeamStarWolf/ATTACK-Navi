// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The posture card (Phase 2 design §3 P2-07, E2.1-d1): Known / Covered /
// partial / Proven / stale over every parent technique of the loaded domain,
// from PostureService.rollup. It is the Home stand-in on the CTEM board and the
// summary of the Validation panel (the Detect > Coverage stand-in), so the
// equality spec (src/app/testing/posture-count-equality.spec.ts) can hold every
// count surface to the same numbers.
//
// Covered and Proven words render only when PostureService.ownerWords() is
// true (§1.3, §2.4); otherwise the card shows Known only. Every Proven word
// comes from the vocabulary module.
import { ChangeDetectionStrategy, Component, Input, Signal, computed, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { DataService } from '../../services/data.service';
import { PostureService } from '../../services/posture.service';
import { tallyPosture } from '../../models/posture/derive-posture';
import { PROVEN } from '../../models/posture/posture-vocabulary';

export type PostureCardScope = 'all' | 'threat-relevant';

/**
 * The numbers the card shows. `mapped` and `total` are the Known numbers;
 * `assessable` (total minus excluded, R16) is the Covered denominator.
 */
export interface PostureCardTally {
  total: number;
  assessable: number;
  mapped: number;
  covered: number;
  partial: number;
  proven: number;
  stale: number;
}

@Component({
  selector: 'app-posture-card',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './posture-card.component.html',
  styleUrl: './posture-card.component.scss',
})
export class PostureCardComponent {
  private readonly posture = inject(PostureService);
  private readonly domain = toSignal(inject(DataService).domain$, { initialValue: null });
  private readonly scopeSig = signal<PostureCardScope>('all');

  /**
   * 'all': every parent technique (the rollup, subs off). 'threat-relevant':
   * the parents with a threat weight above 0 (all ATT&CK groups until P2-10
   * binds the threat profile).
   */
  @Input() set scope(v: PostureCardScope | null | undefined) { this.scopeSig.set(v ?? 'all'); }
  get scope(): PostureCardScope { return this.scopeSig(); }

  readonly provenLabel = PROVEN;
  readonly ownerWords: Signal<boolean> = this.posture.ownerWords;

  readonly tally: Signal<PostureCardTally> = computed(() => {
    if (this.scopeSig() === 'all') {
      const o = this.posture.rollup().overall;
      return { total: o.total, assessable: o.assessable, mapped: o.mapped, covered: o.covered, partial: o.partial, proven: o.proven, stale: o.stale };
    }
    const parents = (this.domain()?.techniques ?? []).filter(t => !t.isSubtechnique);
    const states = parents.map(t => this.posture.stateFor(t)).filter(s => s.threatWeight > 0);
    const t = tallyPosture(states);
    // Known 'mapped' is referenceSignalCount > 0, the same test as isReferenceMapped.
    const mapped = states.filter(s => s.knownSignals > 0).length;
    return { total: t.total, assessable: t.assessable, mapped, covered: t.covered, partial: t.partial, proven: t.proven, stale: t.stale };
  });
}
