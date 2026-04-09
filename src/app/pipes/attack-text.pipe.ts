// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Pipe, PipeTransform } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Pipe({ name: 'attackText', standalone: true, pure: true })
export class AttackTextPipe implements PipeTransform {
  constructor(private sanitizer: DomSanitizer) {}

  transform(text: string | null | undefined): SafeHtml {
    if (!text) return '';
    // Strip all existing HTML tags to prevent XSS from external/imported data
    const stripped = text.replace(/<[^>]*>/g, '');
    // Strip citation markers: (Citation: XYZ)
    const cleaned = stripped.replace(/\s*\(Citation:[^)]+\)/g, '');
    // Convert [text](url) markdown links to anchors — escape captured values
    const html = cleaned.replace(
      /\[([^\]]+)\]\((https?:\/\/[^)"'<>]+)\)/g,
      (_m, label: string, url: string) => {
        const safeUrl = url.replace(/"/g, '&quot;');
        const safeLabel = label.replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return `<a href="${safeUrl}" target="_blank" rel="noopener" class="desc-link">${safeLabel}</a>`;
      }
    );
    return this.sanitizer.bypassSecurityTrustHtml(html);
  }
}
