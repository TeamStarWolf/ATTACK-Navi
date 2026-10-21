// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { readPref, writePref } from './local-pref';

describe('local-pref', () => {
  const KEY = 'local-pref-spec-key';

  afterEach(() => localStorage.removeItem(KEY));

  it('round-trips a value and removes it on null', () => {
    expect(readPref(KEY)).toBeNull();
    writePref(KEY, '512');
    expect(readPref(KEY)).toBe('512');
    writePref(KEY, null);
    expect(readPref(KEY)).toBeNull();
  });

  it('returns null when storage throws on read', () => {
    spyOn(Storage.prototype, 'getItem').and.throwError('SecurityError');
    expect(readPref(KEY)).toBeNull();
  });

  it('swallows a write that throws', () => {
    spyOn(Storage.prototype, 'setItem').and.throwError('QuotaExceededError');
    const remove = spyOn(Storage.prototype, 'removeItem').and.throwError('SecurityError');
    expect(() => writePref(KEY, '1')).not.toThrow();
    expect(() => writePref(KEY, null)).not.toThrow();
    // afterEach runs before Jasmine uninstalls spies; let its cleanup through.
    remove.and.callThrough();
  });
});
