// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// One section of the technique drawer: the card, its header and its body. Every
// drawer section renders through this component, so every header has the same
// type, chevron, icon slot and count pill, and every card the same border,
// radius and padding. It is presentational and standalone: it holds no data and
// renders outside the drawer too (the technique page can use it as is).
//
// The section's open state is a model: bind [expanded] and listen to
// (expandedChange) to keep the state outside (the drawer keeps it in its
// collapsedSections Set), or leave it unbound for a section that keeps its own.
// The body is not rendered while the section is collapsed; a host that renders
// expensive content should also wrap it in its own @if, because projected
// content is created by the host whether or not it is shown.
import { ChangeDetectionStrategy, Component, ViewEncapsulation, input, model } from '@angular/core';

@Component({
  selector: 'app-drawer-section',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  // The primitives' stylesheet is global (every class is prefixed sb-), so the
  // shared row, chip, show-more and footer classes also style content a host
  // projects into the body.
  encapsulation: ViewEncapsulation.None,
  styleUrl: './drawer-primitives.scss',
  host: {
    class: 'sb-section',
    '[attr.data-section]': 'sectionId() || null',
    '[class.sb-section--collapsed]': 'collapsible() && !expanded()',
  },
  template: `
    <h3
      class="sb-head section-title upgrade-section-title"
      [class.collapsible-title]="collapsible()"
      [class.sb-head--curated]="curated()"
      [attr.id]="sectionId() ? 'sb-sec-' + sectionId() : null"
      [attr.role]="collapsible() ? 'button' : null"
      [attr.tabindex]="collapsible() ? 0 : null"
      [attr.aria-expanded]="collapsible() ? expanded() : null"
      (click)="onClick($event)"
      (keydown.enter)="onKey($event)"
      (keydown.space)="onKey($event)"
    >
      @if (collapsible()) {
        <span class="section-chevron sb-chevron" aria-hidden="true">{{ expanded() ? '▾' : '▸' }}</span>
      }
      @if (icon()) {
        <span class="section-icon sb-icon" aria-hidden="true">{{ icon() }}</span>
      }
      <span class="sb-title">{{ heading() }}</span>
      @if (hasCount()) {
        <span
          class="count-badge upgrade-section-count sb-count"
          [attr.data-state]="countState()"
          [attr.title]="countTitle()"
        >{{ count() }}</span>
      }
      <span class="sb-trailing"><ng-content select="[sbTrailing]" /></span>
    </h3>
    @if (!collapsible() || expanded()) {
      <div class="sb-body"><ng-content /></div>
    }
  `,
})
export class DrawerSectionComponent {
  /** The section key: the header gets id="sb-sec-<sectionId>" (the jump index and the e2e use it). */
  readonly sectionId = input<string>('');
  /** The section's label, as written today (no new strings). */
  readonly heading = input.required<string>();
  /** The section's existing emoji, shown in the icon slot; empty for none. */
  readonly icon = input<string>('');
  /** The count pill's value: a number, a marker such as '●', or a short state text. Null, undefined or '' hides it. */
  readonly count = input<string | number | null | undefined>(null);
  /** Rendered as data-state on the count pill (the Rule sources failure states). */
  readonly countState = input<string | null>(null);
  /** The count pill's tooltip. */
  readonly countTitle = input<string | null>(null);
  /** A collapsible section has a chevron, role=button and aria-expanded; a fixed one has none of them. */
  readonly collapsible = input<boolean>(true);
  /** Hand-curated editorial mapping: the header carries the 'curated' marker. */
  readonly curated = input<boolean>(false);
  /** Open or closed; two-way bindable. */
  readonly expanded = model<boolean>(true);

  hasCount(): boolean {
    const c = this.count();
    return c !== null && c !== undefined && c !== '';
  }

  toggle(): void {
    if (!this.collapsible()) return;
    this.expanded.set(!this.expanded());
  }

  onClick(event: Event): void {
    // A control in the trailing slot (a link, a button) does its own thing.
    const target = event.target as Element | null;
    if (target && target !== event.currentTarget && target.closest('a, button, input, select, textarea')) return;
    this.toggle();
  }

  onKey(event: Event): void {
    if (!this.collapsible()) return;
    // Only the header itself: a key pressed in a control in the trailing slot is that control's.
    if (event.target !== event.currentTarget) return;
    event.preventDefault();
    this.toggle();
  }
}
