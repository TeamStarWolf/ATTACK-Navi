// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf - MIT License
import { UserLayerService } from './user-layer.service';

/** A representative MITRE ATT&CK Navigator v4.5 layer. */
function v45Layer(): string {
  return JSON.stringify({
    name: 'APT29 Coverage',
    versions: { attack: '16', navigator: '4.9.1', layer: '4.5' },
    domain: 'enterprise-attack',
    description: 'Test layer',
    filters: { platforms: ['Windows', 'Linux'] },
    gradient: { colors: ['#ff0000', '#00ff00'], minValue: 0, maxValue: 100 },
    legendItems: [{ label: 'Used', color: '#ff0000' }],
    metadata: [{ name: 'source', value: 'unit-test' }, { divider: true }],
    links: [{ label: 'ref', url: 'https://example.com' }],
    techniques: [
      {
        techniqueID: 'T1059',
        tactic: 'execution',
        score: 75,
        color: '',
        comment: 'Observed in the wild',
        enabled: true,
        metadata: [{ name: 'confidence', value: 'high' }, { divider: true }],
        links: [{ label: 'atomic', url: 'https://atomicredteam.io' }],
      },
      { techniqueID: 'T1055', color: '#abcdef', enabled: true },
      { techniqueID: 'T1027', color: '#123456', enabled: false },
      { tactic: 'no-id' },
    ],
  });
}

describe('UserLayerService', () => {
  let service: UserLayerService;

  beforeEach(() => {
    service = new UserLayerService();
  });

  it('converts a v4.5 layer, preserving rich per-technique and layer-level data', () => {
    const { layer, warnings } = service.convert(v45Layer());

    expect(warnings.length).toBe(0);
    expect(layer.name).toBe('APT29 Coverage');
    expect(layer.domain).toBe('enterprise');
    expect(layer.navigatorDomain).toBe('enterprise-attack');
    expect(layer.attackVersion).toBe('16');
    expect(layer.layerVersion).toBe('4.5');
    expect(layer.sourceFormat).toBe('navigator-4.5');
    expect(layer.filters.platforms).toEqual(['Windows', 'Linux']);
    expect(layer.gradient).toEqual({ colors: ['#ff0000', '#00ff00'], minValue: 0, maxValue: 100 });
    expect(layer.legendItems).toEqual([{ label: 'Used', color: '#ff0000' }]);
    // Layer-level metadata keeps name/value pairs and drops divider entries.
    expect(layer.metadata).toEqual([{ name: 'source', value: 'unit-test' }]);
    expect(layer.links).toEqual([{ label: 'ref', url: 'https://example.com' }]);

    // Rows without a techniqueID are skipped.
    expect(layer.techniques.length).toBe(3);
    const t1059 = layer.techniques[0];
    expect(t1059.techniqueID).toBe('T1059');
    expect(t1059.tactic).toBe('execution');
    expect(t1059.score).toBe(75);
    expect(t1059.comment).toBe('Observed in the wild');
    expect(t1059.enabled).toBeTrue();
    expect(t1059.metadata).toEqual([{ name: 'confidence', value: 'high' }]);
    expect(t1059.links).toEqual([{ label: 'atomic', url: 'https://atomicredteam.io' }]);

    const t1027 = layer.techniques[2];
    expect(t1027.color).toBe('#123456');
    expect(t1027.enabled).toBeFalse();
    expect(t1027.score).toBeNull();
  });

  it('tolerates a v3 layer (single version string, legacy domain, no links)', () => {
    const json = JSON.stringify({
      name: 'Legacy',
      version: '3.0',
      domain: 'mitre-mobile',
      techniques: [{ techniqueID: 'T1409', score: 1, comment: 'x' }],
    });
    const { layer } = service.convert(json);
    expect(layer.domain).toBe('mobile');
    expect(layer.layerVersion).toBe('3.0');
    expect(layer.sourceFormat).toBe('navigator-3.0');
    expect(layer.techniques[0].links).toEqual([]);
  });

  it('maps every domain spelling and warns on unknown ones', () => {
    const mk = (d: string) => service.convert(JSON.stringify({ domain: d, techniques: [] }));
    expect(mk('ics-attack').layer.domain).toBe('ics');
    expect(mk('mobile-attack').layer.domain).toBe('mobile');
    expect(mk('f3').layer.domain).toBe('f3');
    const unknown = mk('something-else');
    expect(unknown.layer.domain).toBe('enterprise');
    expect(unknown.warnings.length).toBe(1);
  });

  it('fails gracefully on malformed input', () => {
    expect(() => service.convert('')).toThrowError(/Empty/);
    expect(() => service.convert('not json')).toThrowError(/parse/i);
    expect(() => service.convert('123')).toThrowError(/not a JSON object/);
    expect(() => service.convert('{}')).toThrowError(/missing techniques/);
  });

  it('honors an explicit color, then interpolates the gradient by score', () => {
    const { layer } = service.convert(v45Layer());
    service.applyActive(layer);

    // Explicit per-technique color wins outright (enabled technique).
    expect(service.getGradientColor('T1055')?.toLowerCase()).toBe('#abcdef');
    // Disabled technique yields no color even though it has one set.
    expect(service.getGradientColor('T1027')).toBeNull();
    // Scored technique interpolates across the red→green gradient (75/100).
    const scored = service.getGradientColor('T1059');
    expect(scored).toBeTruthy();
    expect(scored).not.toBe('#ff0000');
    // Absent technique -> null.
    expect(service.getGradientColor('T9999')).toBeNull();
    // Score accessor and max reflect the layer.
    expect(service.getScore('T1059')).toBe(75);
    expect(service.maxScore()).toBe(75);
  });
});
