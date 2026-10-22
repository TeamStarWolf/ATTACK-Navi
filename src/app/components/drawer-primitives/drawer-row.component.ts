// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// One row of a drawer section, in one of three kinds:
//
//   entity  a head line: id chip, badges, name, one line of secondary text
//   detail  the same head line, then a description paragraph and any projected
//           body (code blocks, actions, forms)
//   plain   a line of text (summaries, counts, hints, key/value pairs): the
//           projected content only
//
// The entity id is always the monospace id chip. Links keep the target and rel the
// host gives them (default _blank / noopener). Extra badges whose colour comes from
// the host (for example an EPSS score) are projected with the sbBadge attribute;
// extra head items (an action button, a status chip) with sbHead. Presentational
// and standalone: it renders outside the drawer too.
import { ChangeDetectionStrategy, Component, ViewEncapsulation, input, output } from '@angular/core';
import { RouterLink } from '@angular/router';

/** The badge tones: each resolves to a theme token, so both themes stay legible. */
export type DrawerBadgeTone = 'accent' | 'warm' | 'success' | 'danger' | 'purple' | 'blue' | 'orange' | 'neutral';

export interface DrawerBadge {
  label: string;
  tone?: DrawerBadgeTone;
  title?: string;
}

export type DrawerRowKind = 'entity' | 'detail' | 'plain';

@Component({
  selector: 'app-drawer-row',
  standalone: true,
  imports: [RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  styleUrl: './drawer-primitives.scss',
  host: {
    class: 'sb-row',
    '[class.sb-row--entity]': "kind() === 'entity'",
    '[class.sb-row--detail]': "kind() === 'detail'",
    '[class.sb-row--plain]': "kind() === 'plain'",
    '[class.sb-row--clickable]': 'clickable()',
    '[attr.data-row-kind]': 'kind()',
    '(click)': 'onRowClick($event)',
  },
  template: `
    @if (kind() !== 'plain') {
      <div class="sb-row-head">
        @if (entityId()) {
          @if (idHref()) {
            <a class="sb-id" [class]="idClass()" [href]="idHref()" [attr.target]="target()" [attr.rel]="rel()" [attr.title]="idTitle()">{{ entityId() }}</a>
          } @else {
            <span class="sb-id" [class]="idClass()" [attr.title]="idTitle()">{{ entityId() }}</span>
          }
        }
        @for (b of badges(); track $index) {
          <span class="sb-badge" [attr.data-tone]="b.tone ?? 'neutral'" [attr.title]="b.title ?? null">{{ b.label }}</span>
        }
        <ng-content select="[sbBadge]" />
        @if (name()) {
          @if (nameLink()) {
            <a class="sb-name" [class]="nameClass()" [routerLink]="nameLink()" queryParamsHandling="preserve">{{ name() }}</a>
          } @else if (nameHref()) {
            <a class="sb-name" [class]="nameClass()" [href]="nameHref()" [attr.target]="target()" [attr.rel]="rel()">{{ name() }}</a>
          } @else {
            <span class="sb-name" [class]="nameClass()">{{ name() }}</span>
          }
        }
        <ng-content select="[sbHead]" />
        @if (secondary()) {
          <span class="sb-secondary" [attr.title]="secondary()">{{ secondary() }}</span>
        }
      </div>
      @if (description()) {
        <p class="sb-desc">{{ description() }}</p>
      }
      @if (descriptionHtml()) {
        <p class="sb-desc" [innerHTML]="descriptionHtml()"></p>
      }
    }
    <ng-content />
  `,
})
export class DrawerRowComponent {
  readonly kind = input<DrawerRowKind>('entity');
  /** The entity id (ATT&CK, control, CVE, CAPEC ...), shown as the monospace id chip. */
  readonly entityId = input<string | null | undefined>('');
  /** The id chip's link; the chip is plain text without one. */
  readonly idHref = input<string | null | undefined>('');
  readonly idTitle = input<string | null>(null);
  /** Extra classes on the id chip (kept hooks such as d3fend-id, mit-id). */
  readonly idClass = input<string | null | undefined>('');
  readonly badges = input<readonly DrawerBadge[]>([]);
  readonly name = input<string | null | undefined>('');
  /** Extra classes on the name (kept hooks such as mit-name). */
  readonly nameClass = input<string | null | undefined>('');
  /** The name's external link. */
  readonly nameHref = input<string | null | undefined>('');
  /** The name's in-app link (routerLink); the query is preserved. */
  readonly nameLink = input<string | unknown[] | null>(null);
  /** One line of secondary text; the full text is the tooltip. */
  readonly secondary = input<string | null | undefined>('');
  /** The detail row's description, as text. */
  readonly description = input<string | null | undefined>('');
  /** The detail row's description, as already-formatted HTML (sanitised by Angular). */
  readonly descriptionHtml = input<string | null | undefined>('');
  /** Link target and rel for the id chip and an external name link. */
  readonly target = input<string>('_blank');
  readonly rel = input<string>('noopener');
  /** A clickable row has a hover state and emits rowClick (links inside it keep their own clicks). */
  readonly clickable = input<boolean>(false);
  readonly rowClick = output<void>();

  onRowClick(event: Event): void {
    if (!this.clickable()) return;
    if ((event.target as Element | null)?.closest?.('a, button, input, textarea, select')) return;
    this.rowClick.emit();
  }
}
