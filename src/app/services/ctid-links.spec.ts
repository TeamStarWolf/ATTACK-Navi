// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { CTID_BASE, CTID_DATASETS, ctidControlUrl, ctidDatasetUrl } from './ctid-links';

describe('ctid-links', () => {
  it('builds the deep link format the site actually serves', () => {
    expect(ctidControlUrl('m365', 'DEF-SECA-E3')).toBe(
      'https://ctid.mitre.org/mappings/external/m365/attack-16.1/domain-enterprise/m365-07.18.2025/DEF-SECA-E3/',
    );
  });

  it('never emits the github.io host, which 404s on every deep path', () => {
    const urls = Object.keys(CTID_DATASETS).flatMap(k => [
      ctidDatasetUrl(k),
      ctidControlUrl(k, 'X-1'),
    ]);
    expect(urls.every(u => u.startsWith(CTID_BASE))).toBe(true);
    expect(urls.some(u => u.includes('github.io'))).toBe(false);
  });

  it('falls back to the dataset page where no per-control page exists', () => {
    // Linking a control under these would 404; a working broader page is better.
    expect(ctidControlUrl('nist', 'AC-2')).toBe(ctidDatasetUrl('nist'));
    expect(ctidControlUrl('csaCcm', 'IAM-01')).toBe(ctidDatasetUrl('csaCcm'));
  });

  it('uses the site slug, which differs from the data repository slug', () => {
    // Data lives under nist_800_53/...-rev5; the site publishes nist/...nist-rev5.
    expect(ctidDatasetUrl('nist')).toContain('/external/nist/');
    expect(ctidDatasetUrl('nist')).toContain('nist-rev5');
    expect(ctidDatasetUrl('nist')).not.toContain('nist_800_53');
  });

  it('escapes capability ids', () => {
    expect(ctidControlUrl('m365', 'A B')).toContain('A%20B');
  });

  it('degrades to the explorer root for an unknown framework', () => {
    expect(ctidDatasetUrl('nope')).toBe(`${CTID_BASE}/`);
  });
});
