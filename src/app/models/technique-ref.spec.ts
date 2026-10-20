// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  MitigationRefKey, TechniqueRef, parseTechniqueRef, refForTechnique, sameTechnique, techniqueRefKey,
} from './technique-ref';

const identity = (id: string) => id;

describe('TechniqueRef (Phase 2 design §2.1)', () => {
  describe('techniqueRefKey / parseTechniqueRef', () => {
    const refs: TechniqueRef[] = [
      { framework: 'attack', domain: 'enterprise', id: 'T1059.001', version: '19.2' },
      { framework: 'attack', domain: 'enterprise', id: 'T1110', version: '19.2' },
      { framework: 'attack', domain: 'ics', id: 'T0807', version: '19.2' },
      { framework: 'attack', domain: 'mobile', id: 'T1404', version: '19.2' },
      { framework: 'f3', domain: 'f3', id: 'F1001', version: '1.2' },
      { framework: 'f3', domain: 'f3', id: 'T1110', version: '1.2' },
      { framework: 'atlas', domain: 'atlas', id: 'AML.T0051', version: '5' },
      { framework: 'atlas', domain: 'atlas', id: 'AML.T0051.000', version: '5.1.0' },
    ];

    it('round-trips every framework and domain', () => {
      for (const ref of refs) {
        const key = techniqueRefKey(ref);
        expect(parseTechniqueRef(key)).withContext(key).toEqual(ref);
      }
    });

    it('serialises as framework/domain/id@version (plan:508)', () => {
      expect(techniqueRefKey(refs[0])).toBe('attack/enterprise/T1059.001@19.2');
      expect(techniqueRefKey(refs[4])).toBe('f3/f3/F1001@1.2');
      expect(techniqueRefKey(refs[6])).toBe('atlas/atlas/AML.T0051@5');
    });

    it('mitigation refs share the serialisation', () => {
      const key: MitigationRefKey = 'attack/enterprise/M1036@19.2';
      expect(parseTechniqueRef(key)).toEqual({ framework: 'attack', domain: 'enterprise', id: 'M1036', version: '19.2' });
      expect(parseTechniqueRef('atlas/atlas/AML.M0004@5')?.id).toBe('AML.M0004');
      expect(parseTechniqueRef('f3/f3/M1036@1.2')?.id).toBe('M1036');
    });

    it('returns null for any malformed part', () => {
      const bad = [
        '',
        'attack/enterprise/T1059.001',            // no version
        'attack/enterprise/T1059.001@',           // empty version
        'attack/enterprise@19.2',                 // no id part
        'attack/enterprise/T1059.001@19.2/x',     // trailing part
        'attack//T1059@19.2',                     // empty domain
        '/enterprise/T1059@19.2',                 // empty framework
        'Attack/enterprise/T1059@19.2',           // framework is case-sensitive
        'mitre/enterprise/T1059@19.2',            // unknown framework
        'constructor/enterprise/T1059@19.2',      // prototype key is not a framework
        'attack/f3/T1110@19.2',                   // attack has no f3 domain
        'attack/atlas/T1110@19.2',                // attack has no atlas domain
        'f3/enterprise/T1110@1.2',                // f3 names only its own domain
        'atlas/enterprise/AML.T0051@5',           // atlas names only its own domain
        'attack/enterprise/F1001@19.2',           // F-ids are f3-only
        'attack/enterprise/AML.T0051@19.2',       // ATLAS ids are atlas-only
        'atlas/atlas/T0051@5',                    // atlas ids carry AML.
        'attack/enterprise/T105@19.2',            // short id
        'attack/enterprise/T1059.1@19.2',         // short sub id
        'attack/enterprise/t1059@19.2',           // lower-case id
        'attack/enterprise/T1059@v19',            // version must be dotted digits
        'attack/enterprise/T1059@19.',            // trailing dot
        'attack/enterprise/T1059@19.2 ',          // whitespace
        'attack/enterprise/T1059@@19.2',          // two separators
      ];
      for (const key of bad) expect(parseTechniqueRef(key)).withContext(JSON.stringify(key)).toBeNull();
    });
  });

  describe('refForTechnique', () => {
    it('gives framework attack for the ATT&CK domains', () => {
      expect(refForTechnique({ attackId: 'T1059.001' }, 'enterprise', '19.2'))
        .toEqual({ framework: 'attack', domain: 'enterprise', id: 'T1059.001', version: '19.2' });
      expect(refForTechnique({ attackId: 'T0807' }, 'ics', '19.2').framework).toBe('attack');
      expect(refForTechnique({ attackId: 'T1404' }, 'mobile', '19.2').framework).toBe('attack');
    });

    it('gives framework f3 for the F3 domain', () => {
      expect(refForTechnique({ attackId: 'F1001' }, 'f3', '1.2'))
        .toEqual({ framework: 'f3', domain: 'f3', id: 'F1001', version: '1.2' });
      expect(techniqueRefKey(refForTechnique({ attackId: 'T1110' }, 'f3', '1.2'))).toBe('f3/f3/T1110@1.2');
    });
  });

  describe('sameTechnique', () => {
    const ent = (id: string, version = '19.2'): TechniqueRef => ({ framework: 'attack', domain: 'enterprise', id, version });
    const f3 = (id: string): TechniqueRef => ({ framework: 'f3', domain: 'f3', id, version: '1.2' });
    const ics = (id: string): TechniqueRef => ({ framework: 'attack', domain: 'ics', id, version: '19.2' });

    it('ignores the version', () => {
      expect(sameTechnique(ent('T1110', '18.1'), ent('T1110', '19.2'), identity)).toBeTrue();
    });

    it('F3 T-ids equal Enterprise T-ids, both ways (§1.12)', () => {
      expect(sameTechnique(f3('T1110'), ent('T1110'), identity)).toBeTrue();
      expect(sameTechnique(ent('T1110'), f3('T1110'), identity)).toBeTrue();
      expect(sameTechnique(f3('T1110'), f3('T1110'), identity)).toBeTrue();
    });

    it('F-ids are f3-only', () => {
      expect(sameTechnique(f3('F1001'), ent('F1001'), identity)).toBeFalse();
      expect(sameTechnique(f3('F1001'), ent('T1110'), identity)).toBeFalse();
      expect(sameTechnique(f3('F1001'), f3('F1001'), identity)).toBeTrue();
    });

    it('ICS and Mobile ids never equal Enterprise ids', () => {
      expect(sameTechnique(ics('T0807'), ent('T0807'), identity)).toBeFalse();
      const mobile: TechniqueRef = { framework: 'attack', domain: 'mobile', id: 'T1404', version: '19.2' };
      expect(sameTechnique(mobile, ent('T1404'), identity)).toBeFalse();
      expect(sameTechnique(ics('T0807'), f3('T0807'), identity)).toBeFalse();
    });

    it('compares resolved ids, so a remapped id still matches', () => {
      const resolve = (id: string) => (id === 'T1086' ? 'T1059.001' : id);
      expect(sameTechnique(ent('T1086', '7'), ent('T1059.001'), resolve)).toBeTrue();
      expect(sameTechnique(f3('T1086'), ent('T1059.001'), resolve)).toBeTrue();
      expect(sameTechnique(ent('T1086'), ent('T1059.001'), identity)).toBeFalse();
    });
  });
});
