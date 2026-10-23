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
//
// Technique page design PR 1 (fix-first): the host takes the workspace's width
// and is the page's scroll container (container queries on it, design 4.2); the
// h1 is plain text that takes focus, with the scroll reset, when a technique
// resolves or the page moves to another one, and the document title names the
// technique; tactics read "TA0003 Persistence" and open the matrix; the ATT&CK
// page is an external action. Once the technique resolves the page primes the
// TechniqueFetchCoordinator, the one the drawer calls, so a pasted link and the
// drawer's Full page count the same live D3FEND and Atomic answers.
import {
  ChangeDetectionStrategy, Component, ElementRef, Injector, afterNextRender, computed, effect, inject, input, untracked,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { Title } from '@angular/platform-browser';
import { Router, RouterLink, TitleStrategy } from '@angular/router';
import { DataService, type AttackDomain } from '../../services/data.service';
import {
  ATTACK_DOMAIN_NAMES, DEFAULT_HEATMAP_MODE, FilterService, firstValidHeat, isAttackDomain, normalizeUrlTechId,
} from '../../services/filter.service';
import { TechniqueFetchCoordinator } from '../../services/technique-fetch-coordinator.service';
import { APP_TITLE_BRAND, AppTitleStrategy } from '../../services/app-title.strategy';
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

/** One tactic of the technique, as the header names it: "TA0003 Persistence", a link to the matrix. */
export interface TechniquePageTactic {
  readonly attackId: string;
  readonly name: string;
  readonly queryParams: { readonly dom: AttackDomain; readonly heat: string; readonly tech: string };
}

@Component({
  selector: 'app-technique-page',
  standalone: true,
  imports: [TechniqueEvidenceCardComponent, RouterLink],
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
  private readonly coordinator = inject(TechniqueFetchCoordinator);
  private readonly router = inject(Router);
  private readonly title = inject(Title);
  private readonly titleStrategy = inject(TitleStrategy);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly injector = inject(Injector);
  private readonly mode = toSignal(this.filter.heatmapMode$, { initialValue: DEFAULT_HEATMAP_MODE });

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

  /**
   * The technique's tactics in matrix order, by their ATT&CK names ("TA0003
   * Persistence", never the shortname), each a link to the matrix with the domain,
   * the lens on screen and this technique; the navigation keeps the selection, so
   * the matrix opens with this technique's drawer.
   */
  readonly tactics = computed<readonly TechniquePageTactic[]>(() => {
    const t = this.technique();
    const domain = this.loaded();
    const dom = this.target();
    if (!t || !dom) return [];
    const heat = this.mode();
    const byShort = new Map((domain?.tactics ?? []).map(tac => [tac.shortname, tac]));
    return t.tacticShortnames
      .map(short => byShort.get(short) ?? null)
      .filter((tac): tac is NonNullable<typeof tac> => tac !== null)
      .sort((a, b) => a.order - b.order)
      .map(tac => ({ attackId: tac.attackId, name: tac.name, queryParams: { dom, heat, tech: t.attackId } }));
  });

  /** The document title once the technique resolves: "T1037 Boot or Logon Initialization Scripts". */
  readonly documentTitle = computed(() => {
    const t = this.technique();
    return t ? `${t.attackId} ${t.name}` : null;
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
    // Start the technique's per-technique live fetches (D3FEND live, Atomic YAML) through
    // the coordinator the drawer uses: once per technique, shared by both hosts.
    effect(() => {
      const t = this.technique();
      if (t) untracked(() => this.coordinator.prime(t));
    });
    // Name the technique in the document title, held for this page's path so a
    // query-only navigation (the URL writer) keeps it.
    effect(() => {
      const label = this.documentTitle();
      if (label) untracked(() => this.setTitle(label));
    });
    // A technique resolved, or the page moved to another one (Angular reuses this
    // component): back to the top, and focus on the h1 once it has rendered.
    let shownId: string | null = null;
    effect(() => {
      const id = this.technique()?.id ?? null;
      if (id === null || id === shownId) return;
      shownId = id;
      untracked(() => afterNextRender(() => this.resetToTop(), { injector: this.injector }));
    });
  }

  private setTitle(label: string): void {
    if (this.titleStrategy instanceof AppTitleStrategy) this.titleStrategy.setDetailTitle(this.router.url, label);
    else this.title.setTitle(`${label} · ${APP_TITLE_BRAND}`);
  }

  /**
   * Scroll the page (its host is the scroll container) to the top and move focus to
   * the h1, so a keyboard or screen-reader user starts at the technique's name. Focus
   * is not taken from a dialog or a field elsewhere that holds it (the first-visit
   * onboarding, a search box): only from the body or from inside this page.
   */
  private resetToTop(): void {
    const host = this.host.nativeElement;
    host.scrollTop = 0;
    const h1 = host.querySelector<HTMLElement>('#tp-h1');
    const active = document.activeElement;
    if (!h1 || (active && active !== document.body && !host.contains(active))) return;
    h1.focus({ preventScroll: true });
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
