// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Pipe, PipeTransform } from '@angular/core';

/**
 * Renders ATT&CK description text: strips markup, removes (Citation: ...) markers,
 * and turns [label](https-url) markdown into safe anchors.
 *
 * SECURITY: this pipe no longer calls DomSanitizer.bypassSecurityTrustHtml. The
 * previous implementation stripped tags with a regex (bypassable by malformed/unclosed
 * tags) and then marked the result as trusted, which allowed stored/DOM XSS from
 * imported CTI / layer data. It now (1) reduces the input to plain text with the DOM
 * parser (robust against malformed tags), (2) HTML-escapes it, (3) re-introduces only
 * anchors it constructs itself from https markdown links, and (4) returns a plain
 * string. Bound via [innerHTML], Angular's built-in sanitizer runs on the result, so
 * there is no trusted-HTML bypass anywhere in the path.
 */
@Pipe({ name: 'attackText', standalone: true, pure: true })
export class AttackTextPipe implements PipeTransform {
  transform(text: string | null | undefined): string {
    if (!text) return '';

    // 1. Reduce to plain text. DOMParser removes markup robustly (an unclosed
    //    "<img onerror=..." leaves no live element), unlike a /<[^>]*>/ regex.
    let plain: string;
    if (typeof DOMParser !== 'undefined') {
      plain = new DOMParser().parseFromString(text, 'text/html').body.textContent ?? '';
    } else {
      // No DOM (SSR / non-browser): keep the raw text and let the full HTML-escape
      // below neutralize any markup completely. We deliberately do NOT regex-strip
      // tags here — a single-pass /<[^>]*>/ replace is incomplete (e.g. "<scr<script>ipt>"
      // collapses to "<script>") and escaping is the complete, correct sanitizer.
      plain = text;
    }

    // 2. Remove ATT&CK citation markers: (Citation: XYZ)
    const cleaned = plain.replace(/\s*\(Citation:[^)]+\)/g, '');

    // 3. HTML-escape the now tag-free text so nothing can be interpreted as markup.
    const escaped = cleaned
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');

    // 4. Re-introduce ONLY anchors we build ourselves, from [label](https-url) markdown.
    //    The URL pattern forbids attribute-breaking characters; the label is already
    //    HTML-escaped above. The returned string is bound with [innerHTML], which Angular
    //    sanitizes on binding — so this is defense-in-depth, not a trust bypass.
    return escaped.replace(
      /\[([^\]]+)\]\((https?:\/\/[^)"'<>`\s]+)\)/g,
      (_match, label: string, url: string) =>
        `<a href="${url}" target="_blank" rel="noopener noreferrer" class="desc-link">${label}</a>`
    );
  }
}
