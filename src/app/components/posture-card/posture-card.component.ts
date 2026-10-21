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
import { THREAT_WEIGHT_PROVIDER } from '../../models/posture/threat-weight';
import { tallyPosture } from '../../models/posture/derive-posture';
import { PROVEN, postureBadge } from '../../models/posture/posture-vocabulary';

export type PostureCardScope = 'all' | 'threat-relevant';

/**
 * The row labels of a posture line on the Known surfaces that add one under
 * ownerWords() (P2-08: tactic-summary, analytics, timeline, roadmap). The rung
 * words come from the vocabulary module: Known and Covered through
 * postureBadge, Proven from PROVEN; 'partial' and 'stale' are the sub-state
 * words the card uses.
 */
export const POSTURE_LINE_LABELS = {
  known: postureBadge({ bucket: 'known', qualifiers: [], proofScope: null, covered: [] }),
  covered: postureBadge({ bucket: 'covered', qualifiers: ['self-attested'], proofScope: null, covered: [] }),
  partial: 'partial',
  proven: PROVEN,
  stale: 'stale',
} as const;

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
  // P2-10: the threat-relevant scope counts the profile's parent techniques
  // (parentTechniqueIds is THE denominator, §2.6), read through the shared
  // THREAT_WEIGHT_PROVIDER token so the card stays decoupled from ThreatProfileService;
  // `parents` is a signal, so the tally recomputes on setSource.
  private readonly threatWeight = inject(THREAT_WEIGHT_PROVIDER);
  private readonly scopeSig = signal<PostureCardScope>('all');

  /**
   * 'all': every parent technique (the rollup, subs off). 'threat-relevant':
   * the parent techniques of the shared threat profile (parentTechniqueIds, §2.6),
   * so the count equals the profile denominator for every profile kind.
   */
  @Input() set scope(v: PostureCardScope | null | undefined) { this.scopeSig.set(v ?? 'all'); }
  get scope(): PostureCardScope { return this.scopeSig(); }

  readonly provenLabel = PROVEN;
  /**
   * True until a domain is loaded (domain$ is null at boot and during a switch).
   * The threat-relevant line then says it is loading instead of a transient
   * 'threat-relevant techniques: 0' (RP-F item 6).
   */
  readonly domainLoading: Signal<boolean> = computed(() => this.domain() === null);
  readonly ownerWords: Signal<boolean> = this.posture.ownerWords;

  readonly tally: Signal<PostureCardTally> = computed(() => {
    if (this.scopeSig() === 'all') {
      const o = this.posture.rollup().overall;
      return { total: o.total, assessable: o.assessable, mapped: o.mapped, covered: o.covered, partial: o.partial, proven: o.proven, stale: o.stale };
    }
    const inProfile = this.threatWeight.parents();
    const parents = (this.domain()?.techniques ?? []).filter(t => !t.isSubtechnique && inProfile.has(t.id));
    const states = parents.map(t => this.posture.stateFor(t));
    const t = tallyPosture(states);
    // Known 'mapped' is referenceSignalCount > 0, the same test as isReferenceMapped.
    const mapped = states.filter(s => s.knownSignals > 0).length;
    return { total: t.total, assessable: t.assessable, mapped, covered: t.covered, partial: t.partial, proven: t.proven, stale: t.stale };
  });
}
