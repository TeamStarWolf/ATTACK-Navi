// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The thin technique page, #/technique/:domain/:id (Phase 2 design §3 P2-18,
// E2.3-b; S15): a pasted link opens one technique with its evidence card and
// no drawer (AppComponent hides the drawer on this route; the page owns the
// card). It resolves the id through the AttackIdResolver (a retired id opens
// the technique that replaced it), switches the ATT&CK domain when the link
// names another one, the way the toolbar's domain picker does (filters are
// cleared, then the domain loads), and selects the technique, so "Open in
// matrix" lands on the matrix with its drawer open. The link's heat= survives
// that switch: clearing the filters resets the lens, so the page re-applies
// the pasted lens after it (RP-F item 4). It is a FACTS "detail page", not a
// workspace (scripts/gen-facts.mjs).
import { ChangeDetectionStrategy, Component, computed, effect, inject, input, untracked } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { DataService, type AttackDomain } from '../../services/data.service';
import { ATTACK_DOMAIN_NAMES, FilterService, firstValidHeat, isAttackDomain, normalizeUrlTechId } from '../../services/filter.service';
import { AttackIdResolverService } from '../../services/attack-id-resolver.service';
import { PanelNavService } from '../../services/panel-nav.service';
import type { Technique } from '../../models/technique';
import { TechniqueEvidenceCardComponent } from '../../components/technique-evidence-card/technique-evidence-card.component';

/** What the page shows: the technique, a wait for its domain, or an empty state. */
export type TechniquePageView =
  | { readonly kind: 'found'; readonly technique: Technique; readonly domainName: string }
  | { readonly kind: 'loading'; readonly domainName: string }
  | { readonly kind: 'elsewhere'; readonly domainName: string }
  | { readonly kind: 'unknown'; readonly id: string; readonly domainName: string | null };

@Component({
  selector: 'app-technique-page',
  standalone: true,
  imports: [TechniqueEvidenceCardComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './technique-page.component.html',
  styleUrl: './technique-page.component.scss',
})
export class TechniquePageComponent {
  /** Route params, bound by withComponentInputBinding (app.config.ts). */
  readonly domain = input<string>('');
  readonly id = input<string>('');
  /**
   * The link's heat= query param, bound by withComponentInputBinding. The URL
   * reader has applied it by the time the domain switch runs; loadTarget puts
   * it back after clearAll, which resets the lens to the default. A repeated key
   * (`heat=bogus&heat=coverage`) binds as an array of its values.
   */
  readonly heat = input<string | readonly string[] | undefined>(undefined);

  private readonly data = inject(DataService);
  private readonly filter = inject(FilterService);
  private readonly resolver = inject(AttackIdResolverService);
  private readonly panelNav = inject(PanelNavService);

  private readonly loaded = toSignal(this.data.domain$, { initialValue: null });
  private readonly current = toSignal(this.data.currentDomain$, { initialValue: this.data.getCurrentAttackDomain() });
  private readonly selected = toSignal(this.filter.selectedTechnique$, { initialValue: null });
  /** The link this page last loaded a domain for, so a later manual switch is not undone. */
  private switchedFor: string | null = null;

  /** The ATT&CK domain the link names; null when it names none. */
  readonly target = computed<AttackDomain | null>(() => {
    const d = (this.domain() ?? '').toLowerCase();
    return isAttackDomain(d) ? d : null;
  });

  readonly view = computed<TechniquePageView>(() => {
    const target = this.target();
    // Only a normalised id is ever echoed (#118's pattern): a crafted link cannot put its own text on the page.
    const id = normalizeUrlTechId(this.id() ?? '');
    if (!target || !id) return { kind: 'unknown', id: id ?? '', domainName: target ? ATTACK_DOMAIN_NAMES[target] : null };
    const domainName = ATTACK_DOMAIN_NAMES[target];
    const d = this.loaded();
    // Another domain chosen in the toolbar after the link loaded: say so, never switch back by itself.
    if (this.current() !== target) return { kind: 'elsewhere', domainName };
    if (!d || d.name !== domainName) return { kind: 'loading', domainName };
    // DataService publishes this domain's revoked-by map before domain$ emits it.
    const live = this.resolver.resolve(id);
    const technique = d.techniques.find(t => t.attackId === live);
    return technique ? { kind: 'found', technique, domainName: `${d.name} ${d.attackVersion}` } : { kind: 'unknown', id, domainName };
  });

  /** The found technique, for the template. */
  readonly technique = computed(() => {
    const v = this.view();
    return v.kind === 'found' ? v.technique : null;
  });

  /** The words of the loading and empty states. */
  readonly stateText = computed(() => {
    const v = this.view();
    if (v.kind === 'loading') return `Loading ${v.domainName}…`;
    if (v.kind === 'elsewhere') return `This link is for ${v.domainName}; another ATT&CK domain is on screen.`;
    if (v.kind === 'unknown') return `No technique ${v.id || 'with that id'} in ${v.domainName ?? 'any ATT&CK domain this app loads'}. Check the domain and id in the link.`;
    return v.domainName;
  });

  constructor() {
    // Load the link's domain when another one is on screen: clear the filters,
    // then switch (AppComponent.onDomainChange), once per link.
    effect(() => {
      const target = this.target();
      const key = target ? `${target}/${this.id()}` : null;
      if (!target || key === this.switchedFor) return;
      untracked(() => {
        this.switchedFor = key;
        this.loadTarget();
      });
    });
    // Select the technique, so the URL carries it and "Open in matrix" opens its drawer.
    effect(() => {
      const t = this.technique();
      if (t && this.selected()?.id !== t.id) untracked(() => this.filter.selectTechnique(t));
    });
  }

  /**
   * Load the link's domain the way the toolbar's domain picker does: clear the
   * filters, then switch. clearAll resets the lens to the default (Posture with
   * owner data, else Frequency), so a valid heat= in the link is applied again
   * after the switch: #/technique/ics/T0883?heat=coverage stays on Mitigations
   * mapped, and "Open in matrix" carries heat=coverage (RP-F item 4). An invalid
   * heat= is not a lens choice, so the default stays (RP-F item 1). The lens is read
   * by firstValidHeat, the matrix's reading of a repeated key (RP-F decisions 26 and
   * 30a): #/technique/ics/T0883?heat=bogus&heat=coverage is Mitigations mapped on
   * every domain, where round 5 dropped the array value and fell back to the default.
   */
  loadTarget(): void {
    const target = this.target();
    if (!target || this.data.getCurrentAttackDomain() === target) return;
    const heat = firstValidHeat(this.heat());
    this.filter.clearAll();
    this.data.switchDomain(target);
    if (heat !== null) this.filter.setHeatmapMode(heat);
  }

  /** Back to the matrix with this technique's drawer open (the selection travels with the navigation). */
  openInMatrix(): void {
    this.panelNav.open('matrix', { keepTechniqueSelection: true });
  }
}
