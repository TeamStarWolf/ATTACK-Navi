// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { DefaultUrlSerializer } from '@angular/router';

/**
 * Build a shareable link to the current view with a technique selected.
 *
 * Filter state lives in router query params inside the location hash, for
 * example `#/matrix?heat=sigma&grp=G0007`. A share link is that same URL with a
 * `tech=` param added, so the recipient lands on the same route and heatmap
 * with the technique selected.
 *
 * Parsing goes through the router's own DefaultUrlSerializer, so the route path
 * and every existing query param survive. The earlier implementation ran
 * `URLSearchParams` over the whole hash (`/matrix?heat=sigma&grp=G0007`), which
 * folded the route into an encoded param key and dropped `heat`.
 *
 * @param origin      `window.location.origin`
 * @param pathname    `window.location.pathname` (carries the deployment base href)
 * @param routerUrl   the router's current in-hash URL, e.g. `Router.url`
 * @param techniqueId the ATT&CK id to select, e.g. `T1059`
 */
export function buildTechniqueShareUrl(
  origin: string,
  pathname: string,
  routerUrl: string,
  techniqueId: string,
): string {
  const serializer = new DefaultUrlSerializer();
  const tree = serializer.parse(routerUrl);
  tree.queryParams = { ...tree.queryParams, tech: techniqueId };
  return `${origin}${pathname}#${serializer.serialize(tree)}`;
}
