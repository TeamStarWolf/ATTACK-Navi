// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { XlsxExportService } from './xlsx-export.service';
import type { Domain } from '../models/domain';
import type { Technique } from '../models/technique';
import type { ImplStatus } from './implementation.service';
import { type ImplView, implView } from './posture-adapters';
import { DEFAULT_POSTURE_RULES } from '../models/posture/derive-posture';

type XlsxModule = typeof import('xlsx-js-style');

/**
 * M1038 mapped to 79 techniques (as in Enterprise ATT&CK, far above the default
 * breadth threshold 15): T1059 is reached only by M1038; T1078 also by M1032,
 * which is narrow (one technique).
 */
function broadDomain(): Domain {
  const tech = (attackId: string): Technique => ({
    id: `attack-pattern--${attackId}`, attackId, name: attackId, description: '', url: `https://attack.mitre.org/techniques/${attackId}/`,
    tacticShortnames: ['execution'], isSubtechnique: false, parentId: null, subtechniques: [], mitigationCount: 1,
    platforms: ['Windows'], dataSources: [], detectionText: '', defenseBypassed: [], permissionsRequired: [],
    effectivePermissions: [], systemRequirements: [], impactType: [], remoteSupport: false, capecIds: [],
  } as unknown as Technique);
  const m1038 = { id: 'course-of-action--m1038', attackId: 'M1038', name: 'Execution Prevention' };
  const m1032 = { id: 'course-of-action--m1032', attackId: 'M1032', name: 'Multi-factor Authentication' };
  const t1059 = tech('T1059');
  const t1078 = tech('T1078');
  const fillers = Array.from({ length: 77 }, (_, i) => tech(`T9${String(i + 1).padStart(3, '0')}`));
  const all = [t1059, t1078, ...fillers];
  const rel = (m: typeof m1038) => ({ mitigation: m, description: '' });
  const mitigationsByTechnique = new Map(all.map(t => [t.id, t === t1078 ? [rel(m1038), rel(m1032)] : [rel(m1038)]]));
  t1078.mitigationCount = 2;
  const techniquesByMitigation = new Map([[m1038.id, all], [m1032.id, [t1078]]]);
  return {
    name: 'Enterprise ATT&CK', techniques: all, mitigations: [m1038, m1032], mitigationsByTechnique, techniquesByMitigation,
  } as unknown as Domain;
}

/** The guarded view the way PostureService.implViewFor computes it: threshold and technique marks. */
function viewFor(domain: Domain, impl: Map<string, ImplStatus>, threshold: number, marks: Record<string, ImplStatus[]> = {}) {
  return (t: Technique): ImplView => implView(t, impl, domain, threshold, marks[t.attackId] ?? []);
}

describe('XlsxExportService', () => {
  let service: XlsxExportService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(XlsxExportService);
  });

  it('is created', () => {
    expect(service).toBeTruthy();
  });

  it('exposes the public exportWorkbook method', () => {
    expect(typeof service.exportWorkbook).toBe('function');
  });

  describe("Techniques sheet 'Impl Status (best)' follows the guarded view (P2-14, Addendum note 4)", () => {
    let XLSX: XlsxModule;
    let domain: Domain;
    const impl = new Map<string, ImplStatus>([['course-of-action--m1038', 'implemented'], ['course-of-action--m1032', 'implemented']]);

    beforeAll(async () => {
      const mod = await import('xlsx-js-style');
      XLSX = ((mod as unknown as { utils?: unknown }).utils ? mod : (mod as unknown as { default: XlsxModule }).default) as XlsxModule;
    });
    beforeEach(() => (domain = broadDomain()));

    /** The 'Impl Status (best)' cell per ATT&CK id, read back from the built sheet. */
    function implColumn(implViewFor: (t: Technique) => ImplView): Map<string, string> {
      const build = (service as unknown as {
        buildTechniquesSheet(x: XlsxModule, d: Domain, v: (t: Technique) => ImplView, subs: boolean): unknown;
      }).buildTechniquesSheet;
      const ws = build.call(service, XLSX, domain, implViewFor, false);
      const rows = XLSX.utils.sheet_to_json<unknown[]>(ws as never, { header: 1 });
      const col = (rows[0] as string[]).indexOf('Impl Status (best)');
      expect(col).toBeGreaterThan(-1);
      return new Map(rows.slice(1).map(r => [String(r[0]), String(r[col] ?? '')]));
    }

    it('precondition: M1038 is mapped to 79 techniques, above the default threshold 15', () => {
      expect(domain.techniquesByMitigation.get('course-of-action--m1038')!.length).toBe(79);
      expect(DEFAULT_POSTURE_RULES.mitigationBreadthThreshold).toBe(15);
    });

    it("M1038 implemented, threshold 15: broad-only T1059 reads 'implemented, partial via M1038'; T1078 (also M1032) 'implemented'", () => {
      const col = implColumn(viewFor(domain, impl, 15));
      expect(col.get('T1059')).toBe('implemented, partial via M1038');
      expect(col.get('T1078')).toBe('implemented');
      expect([...col.values()].filter(v => v === 'implemented, partial via M1038').length).toBe(78);
    });

    it("threshold 100 (Settings > Posture rules): T1059 reads 'implemented'", () => {
      const col = implColumn(viewFor(domain, impl, 100));
      expect(col.get('T1059')).toBe('implemented');
      expect([...col.values()].every(v => v === 'implemented')).toBeTrue();
    });

    it("a technique mark (confirmation) on T1059: 'implemented' at threshold 15; the other broad-only techniques stay partial", () => {
      const col = implColumn(viewFor(domain, impl, 15, { T1059: ['implemented'] }));
      expect(col.get('T1059')).toBe('implemented');
      expect(col.get('T9001')).toBe('implemented, partial via M1038');
    });

    it('a status below implemented is written as is; no status is blank', () => {
      expect(implColumn(viewFor(domain, new Map([['course-of-action--m1038', 'planned']]), 15)).get('T1059')).toBe('planned');
      expect(implColumn(viewFor(domain, new Map(), 15)).get('T1059')).toBe('');
    });
  });
});
