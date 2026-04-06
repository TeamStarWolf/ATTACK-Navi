// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Pipe, PipeTransform } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Pipe({ name: 'attackText', standalone: true, pure: true })
export class AttackTextPipe implements PipeTransform {
  constructor(private sanitizer: DomSanitizer) {}

  transform(text: string | null | undefined): SafeHtml {
    if (!text) return '';
    const html = text
      // Strip citation markers: (Citation: XYZ)
      .replace(/\s*\(Citation:[^)]+\)/g, '')
      // Convert [text](url) markdown links to anchors
      .replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener" class="desc-link">$1</a>');
    return this.sanitizer.bypassSecurityTrustHtml(html);
  }
}
