// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { DefaultUrlSerializer } from '@angular/router';
import { buildTechniqueShareUrl } from './share-link';

describe('buildTechniqueShareUrl', () => {
  const origin = 'https://teamstarwolf.github.io';
  const pathname = '/ATTACK-Navi/';

  it('keeps the route path and every query param, and adds tech', () => {
    const url = buildTechniqueShareUrl(origin, pathname, '/matrix?heat=sigma&grp=G0007', 'T1059');
    expect(url).toBe('https://teamstarwolf.github.io/ATTACK-Navi/#/matrix?heat=sigma&grp=G0007&tech=T1059');
  });

  it('round-trips: parsing the share link back yields the same route and params', () => {
    const url = buildTechniqueShareUrl(origin, pathname, '/matrix?heat=sigma&grp=G0007', 'T1059');
    const hash = url.slice(url.indexOf('#') + 1);
    const tree = new DefaultUrlSerializer().parse(hash);
    expect(tree.toString().split('?')[0]).toBe('/matrix');
    expect(tree.queryParams).toEqual({ heat: 'sigma', grp: 'G0007', tech: 'T1059' });
  });

  it('does not fold the route into an encoded param key (the old bug)', () => {
    const url = buildTechniqueShareUrl(origin, pathname, '/matrix?heat=kev', 'T1566');
    // The route must stay a path segment, never become an encoded key like %2Fmatrix%3Fheat.
    expect(url).toContain('#/matrix?');
    expect(url).not.toContain('%2F');
    expect(url).toContain('heat=kev');
    expect(url).toContain('tech=T1566');
  });

  it('works on a non-matrix route', () => {
    const url = buildTechniqueShareUrl(origin, pathname, '/exposure/cve?heat=cve', 'T1190');
    expect(url).toBe('https://teamstarwolf.github.io/ATTACK-Navi/#/exposure/cve?heat=cve&tech=T1190');
  });

  it('adds tech when there are no existing query params', () => {
    const url = buildTechniqueShareUrl(origin, pathname, '/matrix', 'T1078');
    expect(url).toBe('https://teamstarwolf.github.io/ATTACK-Navi/#/matrix?tech=T1078');
  });

  it('overwrites a stale tech param rather than duplicating it', () => {
    const url = buildTechniqueShareUrl(origin, pathname, '/matrix?heat=sigma&tech=T1000', 'T1059');
    expect(url).toBe('https://teamstarwolf.github.io/ATTACK-Navi/#/matrix?heat=sigma&tech=T1059');
  });

  it('preserves a subtechnique id with its dot', () => {
    const url = buildTechniqueShareUrl(origin, pathname, '/matrix?heat=sigma', 'T1059.001');
    const tree = new DefaultUrlSerializer().parse(url.slice(url.indexOf('#') + 1));
    expect(tree.queryParams['tech']).toBe('T1059.001');
  });
});
