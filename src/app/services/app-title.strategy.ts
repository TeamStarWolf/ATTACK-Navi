// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { Title } from '@angular/platform-browser';
import { ActivatedRouteSnapshot, RouterStateSnapshot, TitleStrategy } from '@angular/router';

/**
 * Builds document titles like "Validation · Detection · ATTACK Navi" from the
 * route tree's data.tab / data.title entries.
 */
@Injectable({ providedIn: 'root' })
export class AppTitleStrategy extends TitleStrategy {
  constructor(private readonly title: Title) {
    super();
  }

  override updateTitle(snapshot: RouterStateSnapshot): void {
    const parts: string[] = [];
    let route: ActivatedRouteSnapshot | null = snapshot.root;
    while (route) {
      const tab = route.data['tab'] as string | undefined;
      const title = route.data['title'] as string | undefined;
      const label = tab ?? title;
      if (label && parts[0] !== label) parts.unshift(label);
      route = route.firstChild;
    }
    parts.push('ATTACK Navi');
    this.title.setTitle(parts.join(' · '));
  }
}
