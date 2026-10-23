// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { Title } from '@angular/platform-browser';
import { ActivatedRouteSnapshot, RouterStateSnapshot, TitleStrategy } from '@angular/router';

/** The brand every document title ends with. */
export const APP_TITLE_BRAND = 'ATT&CK-Navi';

/** A router URL without its query string and fragment: the key a detail title is held under. */
export function titlePath(url: string): string {
  return url.split(/[?#]/)[0];
}

/**
 * Builds document titles like "Validation · Detection · ATT&CK-Navi" from the
 * route tree's data.tab / data.title entries.
 *
 * A detail page names its object once it has resolved it (the technique page:
 * "T1037 Boot or Logon Initialization Scripts · ATT&CK-Navi"; technique page
 * design 4.9) through setDetailTitle. The title is held for that page's path, so
 * a later navigation that only rewrites the query (the URL writer adding tech=
 * or heat=) keeps it instead of falling back to the route's "Technique".
 */
@Injectable({ providedIn: 'root' })
export class AppTitleStrategy extends TitleStrategy {
  private detail: { readonly path: string; readonly label: string } | null = null;

  constructor(private readonly title: Title) {
    super();
  }

  override updateTitle(snapshot: RouterStateSnapshot): void {
    if (this.detail && this.detail.path === titlePath(snapshot.url)) {
      this.title.setTitle(`${this.detail.label} · ${APP_TITLE_BRAND}`);
      return;
    }
    const parts: string[] = [];
    let route: ActivatedRouteSnapshot | null = snapshot.root;
    while (route) {
      const tab = route.data['tab'] as string | undefined;
      const title = route.data['title'] as string | undefined;
      const label = tab ?? title;
      if (label && parts[0] !== label) parts.unshift(label);
      route = route.firstChild;
    }
    parts.push(APP_TITLE_BRAND);
    this.title.setTitle(parts.join(' · '));
  }

  /** Name the detail page at `url` (its query and fragment ignored) and set the title now. */
  setDetailTitle(url: string, label: string): void {
    this.detail = { path: titlePath(url), label };
    this.title.setTitle(`${label} · ${APP_TITLE_BRAND}`);
  }
}
