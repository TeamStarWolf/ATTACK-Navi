// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, Component, Input } from '@angular/core';
import { IconComponent } from '../../shared/icons/icon.component';
import { IconName } from '../../shared/icons/icon-registry';

/**
 * Card-style content section for routed pages. Styles are global in
 * src/styles/_workspace.scss (.page-section*). Project actions into the
 * header with the `section-actions` attribute.
 */
@Component({
  selector: 'app-page-section',
  standalone: true,
  imports: [IconComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="page-section">
      @if (title) {
        <header class="page-section-head">
          @if (icon) {
            <app-icon [name]="icon" [size]="14" />
          }
          <h2>{{ title }}</h2>
          <ng-content select="[section-actions]" />
        </header>
      }
      <div class="page-section-body">
        <ng-content />
      </div>
    </section>
  `,
})
export class PageSectionComponent {
  @Input() title = '';
  @Input() icon?: IconName;
}
