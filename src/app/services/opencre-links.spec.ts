// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { OPENCRE_SMARTLINK_BASE, openCreSmartlink } from './opencre-links';

describe('opencre-links', () => {
  it('builds the smartlink route OpenCRE serves for CAPEC and CWE', () => {
    expect(openCreSmartlink('CAPEC', 'CAPEC-66')).toBe('https://opencre.org/smartlink/standard/CAPEC/66');
    expect(openCreSmartlink('CWE', 'CWE-79')).toBe('https://opencre.org/smartlink/standard/CWE/79');
  });

  it('accepts the bare number, any case and surrounding space', () => {
    expect(openCreSmartlink('CWE', '79')).toBe(`${OPENCRE_SMARTLINK_BASE}/CWE/79`);
    expect(openCreSmartlink('CAPEC', ' capec-112 ')).toBe(`${OPENCRE_SMARTLINK_BASE}/CAPEC/112`);
  });

  it('returns null for an id without a number or with the other standard\'s prefix', () => {
    expect(openCreSmartlink('CAPEC', '')).toBeNull();
    expect(openCreSmartlink('CAPEC', undefined)).toBeNull();
    expect(openCreSmartlink('CWE', 'NVD-CWE-noinfo')).toBeNull();
    expect(openCreSmartlink('CAPEC', 'CAPEC-66; CAPEC-67')).toBeNull();
    expect(openCreSmartlink('CAPEC', 'CWE-79')).toBeNull();
    expect(openCreSmartlink('CWE', 'CAPEC-66')).toBeNull();
  });

  it('only ever emits the opencre.org host', () => {
    const urls = [openCreSmartlink('CAPEC', 'CAPEC-1'), openCreSmartlink('CWE', 'CWE-1')];
    expect(new Set(urls.map(u => new URL(u!).host))).toEqual(new Set(['opencre.org']));
  });
});
