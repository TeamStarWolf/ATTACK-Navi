// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { WorkspaceBundleService } from './workspace-bundle.service';

describe('WorkspaceBundleService', () => {
  let service: WorkspaceBundleService;
  const cleanup = () => {
    for (const key of WorkspaceBundleService.BUNDLED_KEYS) localStorage.removeItem(key);
    localStorage.removeItem('misp_config');
  };

  beforeEach(() => {
    cleanup();
    service = new WorkspaceBundleService();
  });

  afterEach(cleanup);

  it('round-trips workspace keys', () => {
    localStorage.setItem('mitre-nav-watchlist-v1', '["T1059"]');
    localStorage.setItem('mitre-nav-tags-v1', '{"T1059":["quarterly"]}');
    const bundle = service.exportBundle();
    cleanup();
    const applied = service.importBundle(bundle);
    expect(applied).toBe(2);
    expect(localStorage.getItem('mitre-nav-watchlist-v1')).toBe('["T1059"]');
    expect(localStorage.getItem('mitre-nav-tags-v1')).toBe('{"T1059":["quarterly"]}');
  });

  it('strips the NVD API key from exported settings', () => {
    localStorage.setItem('mitre-nav-settings-v1', JSON.stringify({ orgName: 'ACME', nvdApiKey: 'sk-secret' }));
    const bundle = JSON.parse(service.exportBundle());
    const settings = JSON.parse(bundle.data['mitre-nav-settings-v1']);
    expect(settings.orgName).toBe('ACME');
    expect(settings.nvdApiKey).toBeUndefined();
  });

  it('never exports integration credentials', () => {
    localStorage.setItem('misp_config', '{"apiKey":"secret"}');
    const bundle = service.exportBundle();
    expect(bundle).not.toContain('misp_config');
    expect(bundle).not.toContain('secret');
  });

  it('rejects non-bundle payloads', () => {
    expect(() => service.importBundle('{"hello":1}')).toThrowError(/workspace bundle/);
    expect(() => service.importBundle('not json')).toThrowError(/JSON/);
  });

  it('ignores non-whitelisted keys in a crafted bundle', () => {
    const crafted = JSON.stringify({
      format: 'attack-navi-workspace',
      version: 1,
      data: { 'misp_config': '{"apiKey":"evil"}', 'mitre-nav-watchlist-v1': '[]' },
    });
    const applied = service.importBundle(crafted);
    expect(applied).toBe(1);
    expect(localStorage.getItem('misp_config')).toBeNull();
  });
});
