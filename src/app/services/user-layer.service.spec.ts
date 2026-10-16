// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf - MIT License
import { TestBed } from '@angular/core/testing';
import { firstValueFrom } from 'rxjs';
import { Domain } from '../models/domain';
import { USER_LAYER_DB_NAME, UserLayerService } from './user-layer.service';

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

/** The parts of a loaded Domain that id resolution reads. */
function v19Domain(): Domain {
  return {
    name: 'Enterprise ATT&CK',
    attackVersion: '19.2',
    techniques: [
      { id: 'tech-1059', attackId: 'T1059' },
      { id: 'tech-1055', attackId: 'T1055' },
      { id: 'tech-1027', attackId: 'T1027' },
      { id: 'tech-1685-005', attackId: 'T1685.005' },
    ],
    supersededBy: new Map([['T1070.001', 'T1685.005']]),
  } as unknown as Domain;
}

/**
 * Waits for IndexedDB to drop the spec's database. The service closes every
 * connection when its transaction settles, so a `blocked` event (the
 * constructor's initial list refresh may still be in flight) only delays
 * `success`; it never prevents it.
 */
function deleteDatabase(name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(name);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

describe('UserLayerService', () => {
  let service: UserLayerService;
  let dbName: string;

  beforeEach(() => {
    // A fresh database per spec keeps the persistence specs order-independent.
    dbName = `attack-navi-user-layers-spec-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    TestBed.configureTestingModule({
      providers: [{ provide: USER_LAYER_DB_NAME, useValue: dbName }],
    });
    service = TestBed.inject(UserLayerService);
  });

  afterEach(async () => {
    await deleteDatabase(dbName);
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

  // ── Resolution against the loaded domain ───────────────────────────────────

  it('warns when none of a layer\'s ids exist in the loaded domain (an ATLAS layer against Enterprise)', () => {
    const atlas = JSON.stringify({
      name: 'Lylat Coverage — ATLAS (AI/ML)',
      domain: 'atlas',
      techniques: [
        { techniqueID: 'AML.T0014', tactic: 'discovery', score: 1 },
        { techniqueID: 'AML.T0040', tactic: 'ai-model-access', score: 1 },
      ],
    });
    const { warnings } = service.convert(atlas, v19Domain());
    // One warning for the unknown domain string, one because nothing resolves.
    expect(warnings.length).toBe(2);
    const resolution = warnings.find(w => w.includes('None of this layer'))!;
    expect(resolution).toContain('2 technique ids');
    expect(resolution).toContain('Enterprise ATT&CK v19.2');
    expect(resolution).toContain('AML.T0014');
    expect(resolution).toContain('color no cells');
  });

  it('warns about the subset of ids that do not resolve, and stays quiet when all do', () => {
    const partial = JSON.stringify({
      domain: 'enterprise-attack',
      techniques: [{ techniqueID: 'T1059' }, { techniqueID: 'T9999' }, { techniqueID: 'T1070.001' }],
    });
    const { warnings } = service.convert(partial, v19Domain());
    expect(warnings).toEqual([jasmine.stringContaining('1 of 3 technique ids do not exist in Enterprise ATT&CK v19.2')]);
    expect(warnings[0]).toContain('T9999');
    expect(warnings[0]).not.toContain('T1070.001');

    expect(service.convert(v45Layer(), v19Domain()).warnings).toEqual([]);
  });

  it('resolve() classifies ids as live, remapped via supersededBy, or unresolved', () => {
    const { layer } = service.convert(JSON.stringify({
      domain: 'enterprise-attack',
      techniques: [
        { techniqueID: 'T1059', tactic: 'execution' },
        { techniqueID: 'T1059', tactic: 'persistence' }, // same id in a second tactic: counted once
        { techniqueID: 'T1070.001' },
        { techniqueID: 'AML.T0014' },
      ],
    }));
    expect(service.resolve(layer, v19Domain())).toEqual({
      total: 3,
      resolved: 1,
      remapped: [{ from: 'T1070.001', to: 'T1685.005' }],
      unresolved: ['AML.T0014'],
    });
  });

  it('applyActive with the domain also serves a retired id\'s entry under its live replacement', () => {
    const { layer } = service.convert(JSON.stringify({
      domain: 'enterprise-attack',
      techniques: [{ techniqueID: 'T1070.001', score: 42, color: '#112233', comment: 'legacy' }],
    }));

    service.applyActive(layer);
    expect(service.getEntry('T1685.005')).toBeNull();

    service.applyActive(layer, v19Domain());
    expect(service.getEntry('T1685.005')?.comment).toBe('legacy');
    expect(service.getScore('T1685.005')).toBe(42);
    expect(service.getGradientColor('T1685.005')).toBe('#112233');
    // The retired id itself is still served.
    expect(service.getEntry('T1070.001')?.comment).toBe('legacy');
  });

  it('applyActive never lets a retired alias shadow a direct entry for the replacement', () => {
    const { layer } = service.convert(JSON.stringify({
      domain: 'enterprise-attack',
      techniques: [
        { techniqueID: 'T1685.005', comment: 'current' },
        { techniqueID: 'T1070.001', comment: 'legacy' },
      ],
    }));
    service.applyActive(layer, v19Domain());
    expect(service.getEntry('T1685.005')?.comment).toBe('current');
  });

  // ── Active-layer accessors ─────────────────────────────────────────────────

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

  it('does not score disabled techniques and excludes them from the max', () => {
    const json = JSON.stringify({
      domain: 'enterprise-attack',
      gradient: { colors: ['#ff0000', '#00ff00'], minValue: 0, maxValue: 100 },
      techniques: [
        { techniqueID: 'T1059', score: 40, enabled: true },
        { techniqueID: 'T1071', score: 90, enabled: false }, // disabled but carries a score
      ],
    });
    const { layer } = service.convert(json);
    service.applyActive(layer);
    // A disabled-but-scored technique contributes no heatmap score or color…
    expect(service.getScore('T1071')).toBe(0);
    expect(service.getGradientColor('T1071')).toBeNull();
    // …and does not inflate the relative-coloring max.
    expect(service.maxScore()).toBe(40);
    // The enabled technique is unaffected.
    expect(service.getScore('T1059')).toBe(40);
  });

  it('safeColor validates untrusted layer colors and rejects CSS injection', () => {
    expect(service.safeColor('#3572b0')).toBe('#3572b0');
    expect(service.safeColor('red')).toBe('#ff0000');
    // A hostile "color" that is really a CSS url() beacon is dropped, not passed through.
    expect(service.safeColor('url(https://attacker.example/beacon.png)')).toBe('');
    expect(service.safeColor('notacolor')).toBe('');
    expect(service.safeColor('')).toBe('');
    expect(service.safeColor(null)).toBe('');
  });

  // ── IndexedDB persistence (real IndexedDB in ChromeHeadless) ───────────────

  it('saveLayer persists the layer and the list exposes its metadata', async () => {
    const { layer } = service.convert(v45Layer());
    await service.saveLayer(layer);

    const metas = await firstValueFrom(service.layers$);
    expect(metas).toEqual([jasmine.objectContaining({
      id: layer.id, name: 'APT29 Coverage', domain: 'enterprise', techniqueCount: 3, sourceFormat: 'navigator-4.5',
    })]);
    expect(service.layers.length).toBe(1);
  });

  it('getLayer round-trips the full converted layer and returns null for an unknown id', async () => {
    const { layer } = service.convert(v45Layer());
    await service.saveLayer(layer);

    const stored = await service.getLayer(layer.id);
    expect(stored).toEqual(layer);
    expect(await service.getLayer('layer-does-not-exist')).toBeNull();
  });

  it('lists saved layers newest first and survives a fresh service instance', async () => {
    const older = service.convert(JSON.stringify({ name: 'Older', domain: 'enterprise-attack', techniques: [] })).layer;
    older.importedAt = '2026-01-01T00:00:00.000Z';
    const newer = service.convert(JSON.stringify({ name: 'Newer', domain: 'ics-attack', techniques: [] })).layer;
    newer.importedAt = '2026-02-01T00:00:00.000Z';
    await service.saveLayer(older);
    await service.saveLayer(newer);
    expect(service.layers.map(m => m.name)).toEqual(['Newer', 'Older']);

    // Persistence is in the browser, not in the instance.
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({ providers: [{ provide: USER_LAYER_DB_NAME, useValue: dbName }] });
    const fresh = TestBed.inject(UserLayerService);
    await fresh.refreshList();
    expect(fresh.layers.map(m => m.name)).toEqual(['Newer', 'Older']);
  });

  it('setActive loads a saved layer and makes it the active layer', async () => {
    const { layer } = service.convert(v45Layer());
    await service.saveLayer(layer);
    expect(service.activeLayer).toBeNull();

    const activated = await service.setActive(layer.id);
    expect(activated?.id).toBe(layer.id);
    expect(service.activeLayer?.id).toBe(layer.id);
    expect(service.getScore('T1059')).toBe(75);
    expect(await firstValueFrom(service.activeLayer$)).toEqual(jasmine.objectContaining({ id: layer.id }));

    expect(await service.setActive('layer-does-not-exist')).toBeNull();
    expect(service.activeLayer?.id).toBe(layer.id);
  });

  it('deleteLayer removes the layer and clears it when it was active', async () => {
    const keep = service.convert(JSON.stringify({ name: 'Keep', domain: 'enterprise-attack', techniques: [] })).layer;
    const drop = service.convert(v45Layer()).layer;
    await service.saveLayer(keep);
    await service.saveLayer(drop);
    await service.setActive(drop.id);

    await service.deleteLayer(drop.id);

    expect(service.layers.map(m => m.id)).toEqual([keep.id]);
    expect(await service.getLayer(drop.id)).toBeNull();
    expect(service.activeLayer).toBeNull();
    expect(service.getEntry('T1059')).toBeNull();
    expect(service.maxScore()).toBe(1);
  });

  it('deleting a non-active layer leaves the active layer alone', async () => {
    const active = service.convert(v45Layer()).layer;
    const other = service.convert(JSON.stringify({ name: 'Other', domain: 'enterprise-attack', techniques: [] })).layer;
    await service.saveLayer(active);
    await service.saveLayer(other);
    await service.setActive(active.id);

    await service.deleteLayer(other.id);
    expect(service.activeLayer?.id).toBe(active.id);
    expect(service.layers.map(m => m.id)).toEqual([active.id]);
  });
});
