// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The cross-domain threat-profile notice (RP-F decision 6). When some groups of the
// stored profile have no use in the loaded domain, every profile surface says so in
// the same sentence ("1 of 2 groups present in ICS: FIN7; APT29 has no ICS use")
// instead of silently narrowing. The sentence is built once (profileDomainNotice in
// models/threat-profile) and read here through the THREAT_WEIGHT_PROVIDER seam, so a
// surface adds <app-profile-domain-notice /> and never copies the membership rule or
// the wording. It renders nothing when every stored group is present.
import { ChangeDetectionStrategy, Component, Signal, computed, inject } from '@angular/core';
import { THREAT_WEIGHT_PROVIDER } from '../../models/posture/threat-weight';

@Component({
  selector: 'app-profile-domain-notice',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `@if (notice(); as n) {<p class="profile-domain-notice" role="note" data-testid="profile-domain-notice">{{ n }}</p>}`,
  styles: [`
    :host { display: contents; }
    .profile-domain-notice {
      margin: 4px 0 8px;
      padding: 4px 8px;
      border-left: 2px solid var(--accent-warm, #fbbf24);
      font-size: 0.75rem;
      line-height: 1.4;
      color: var(--text-muted, #b6bcc4);
    }
  `],
})
export class ProfileDomainNoticeComponent {
  private readonly provider = inject(THREAT_WEIGHT_PROVIDER);
  /** The provider's sentence, or null (a provider without domainNotice shows nothing). */
  readonly notice: Signal<string | null> = computed(() => this.provider.domainNotice?.() ?? null);
}
