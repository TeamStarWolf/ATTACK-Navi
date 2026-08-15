// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, Component, Input, inject, isDevMode } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { FALLBACK_ICON, ICONS, IconName, isIconName } from './icon-registry';

/**
 * Inline SVG icon. Usage: <app-icon name="radar" [size]="16" />
 * Decorative by default (aria-hidden); pass [label] to expose it to AT.
 * Registry content is compile-time constant markup, so trusting it is safe.
 */
@Component({
  selector: 'app-icon',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="2"
    stroke-linecap="round"
    stroke-linejoin="round"
    [attr.width]="size"
    [attr.height]="size"
    [attr.role]="label ? 'img' : null"
    [attr.aria-label]="label || null"
    [attr.aria-hidden]="label ? null : 'true'"
    [innerHTML]="content"
  ></svg>`,
  styles: [':host { display: inline-flex; line-height: 0; flex-shrink: 0; }'],
})
export class IconComponent {
  private readonly sanitizer = inject(DomSanitizer);

  @Input() size = 16;
  @Input() label = '';

  content: SafeHtml = '';

  @Input({ required: true })
  set name(value: IconName | string) {
    if (!isIconName(value)) {
      if (isDevMode()) {
        console.warn(`[app-icon] Unknown icon name "${value}" — using fallback.`);
      }
      value = FALLBACK_ICON;
    }
    this.content = this.sanitizer.bypassSecurityTrustHtml(ICONS[value as IconName]);
  }
}
