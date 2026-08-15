// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { rewriteLegacyHash } from './legacy-hash-shim';

describe('rewriteLegacyHash', () => {
  it('rewrites a legacy technique deep-link to the matrix route', () => {
    expect(rewriteLegacyHash('#tech=T1059', null)).toBe('#/matrix?tech=T1059');
  });

  it('rewrites legacy filter-key hashes to the matrix route, preserving all params', () => {
    expect(rewriteLegacyHash('#mit=M1038&heat=kev&grp=G0016', null))
      .toBe('#/matrix?mit=M1038&heat=kev&grp=G0016');
  });

  it('leaves already-routed hashes untouched', () => {
    expect(rewriteLegacyHash('#/detect/validation?heat=kev', null)).toBeNull();
    expect(rewriteLegacyHash('#/matrix', null)).toBeNull();
  });

  it('migrates the persisted library view-mode when there is no hash', () => {
    expect(rewriteLegacyHash('', 'library')).toBe('#/library');
    expect(rewriteLegacyHash('#', 'library')).toBe('#/library');
  });

  it('returns null for an empty hash with no stored view mode', () => {
    expect(rewriteLegacyHash('', null)).toBeNull();
    expect(rewriteLegacyHash('', 'workbench')).toBeNull();
  });
});
