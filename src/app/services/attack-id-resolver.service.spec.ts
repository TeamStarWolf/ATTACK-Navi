// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { AttackIdResolverService } from './attack-id-resolver.service';

describe('AttackIdResolverService', () => {
  let resolver: AttackIdResolverService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    resolver = TestBed.inject(AttackIdResolverService);
  });

  it('is the identity before any domain has loaded', () => {
    expect(resolver.resolve('T1562.001')).toBe('T1562.001');
  });

  it('translates a retired id to its replacement and leaves live ids alone', () => {
    resolver.setSupersededBy(new Map([['T1562.001', 'T1685']]));
    expect(resolver.resolve('T1562.001')).toBe('T1685');
    expect(resolver.resolve('T1059')).toBe('T1059');
  });

  it('bumps the version only when the map changes', () => {
    const map = new Map([['T1070.001', 'T1685.005']]);
    const v0 = resolver.version;
    resolver.setSupersededBy(map);
    expect(resolver.version).toBe(v0 + 1);
    resolver.setSupersededBy(map);
    expect(resolver.version).toBe(v0 + 1);
    resolver.setSupersededBy(null);
    expect(resolver.version).toBe(v0 + 2);
    expect(resolver.resolve('T1070.001')).toBe('T1070.001');
  });
});
