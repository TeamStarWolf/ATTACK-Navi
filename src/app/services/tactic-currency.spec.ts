// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Currency gate: every tactic shortname in every bundled STIX domain must be
// understood by the hand-written content tables and by the kill-chain helpers.
// Reads the real bundles under src/assets/data so a data refresh that renames
// or adds a tactic fails here instead of silently falling back to Execution.
import { TestBed } from '@angular/core/testing';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { DataService } from './data.service';
import { ENTERPRISE_TACTIC_ORDER, resolveTacticEntry, tacticAliases, tacticOrderFor } from './attack-tactics';
import { TACTIC_RESPONSES } from './ir-playbook.service';
import { OBJECTIVE_TEMPLATES, SUCCESS_CRITERIA } from './emulation-plan.service';
import { TACTIC_HEADER_COLORS } from '../components/matrix/matrix.component';
import { BundledDomainTactics, BUNDLED_DOMAINS, loadBundledTactics } from '../testing/bundled-tactics';

/**
 * Tactics that have no SIEM tactic template yet (domain-specific ICS, Mobile
 * network and F3 fraud tactics). Listed explicitly so the gap is visible and a
 * new unhandled tactic still fails the suite.
 */
const KNOWN_SIEM_TEMPLATE_GAPS = new Set([
  'inhibit-response-function',
  'impair-process-control',
  'network-effects',
  'remote-service-effects',
  'positioning',
  'monetization',
]);

describe('ATT&CK tactic currency across the bundled domains', () => {
  let domains: BundledDomainTactics[] = [];

  beforeAll(async () => {
    domains = await loadBundledTactics();
  }, 120000);

  it('loads every bundled domain with at least one tactic', () => {
    expect(domains.map(d => d.key)).toEqual(BUNDLED_DOMAINS.map(d => d.key));
    for (const d of domains) {
      expect(d.tactics.length).withContext(d.file).toBeGreaterThan(0);
      expect(d.matrixOrder.length).withContext(d.file).toBeGreaterThan(0);
    }
  });

  it('bundled Enterprise is v19: stealth + defense-impairment, no defense-evasion', () => {
    const ent = domains.find(d => d.key === 'enterprise')!;
    expect(ent.version.startsWith('19')).withContext(`enterprise x_mitre_version ${ent.version}`).toBeTrue();
    const slugs = ent.tactics.map(t => t.shortname);
    expect(slugs).toContain('stealth');
    expect(slugs).toContain('defense-impairment');
    expect(slugs).not.toContain('defense-evasion');
    expect(ent.livePhaseNames).toContain('stealth');
    expect(ent.livePhaseNames).not.toContain('defense-evasion');
    expect(ent.matrixOrder).toEqual([...ENTERPRISE_TACTIC_ORDER]);
  });

  it('every kill_chain_phase used by a live technique is a tactic of its own bundle', () => {
    for (const d of domains) {
      const known = new Set(d.tactics.map(t => t.shortname));
      for (const phase of d.livePhaseNames) {
        expect(known.has(phase)).withContext(`${d.key}: phase ${phase}`).toBeTrue();
      }
    }
  });

  it('every tactic shortname has an IR playbook response entry', () => {
    for (const d of domains) {
      for (const t of d.tactics) {
        expect(resolveTacticEntry(TACTIC_RESPONSES, t.shortname))
          .withContext(`${d.key}: ${t.shortname} (${t.attackId} ${t.name})`)
          .toBeDefined();
      }
    }
  });

  it('every tactic shortname has an emulation objective and success criterion', () => {
    for (const d of domains) {
      for (const t of d.tactics) {
        expect(resolveTacticEntry(OBJECTIVE_TEMPLATES, t.shortname))
          .withContext(`${d.key}: objective for ${t.shortname}`).toBeDefined();
        expect(resolveTacticEntry(SUCCESS_CRITERIA, t.shortname))
          .withContext(`${d.key}: success criteria for ${t.shortname}`).toBeDefined();
      }
    }
  });

  it('every tactic shortname has a matrix header colour', () => {
    for (const d of domains) {
      for (const t of d.tactics) {
        expect(resolveTacticEntry(TACTIC_HEADER_COLORS, t.shortname))
          .withContext(`${d.key}: colour for ${t.shortname}`).toBeDefined();
      }
    }
  });

  it('every tactic shortname resolves to a SIEM tactic template, except the documented gaps', async () => {
    // Imported lazily so this spec's TestBed is only configured when needed.
    const { SiemQueryService } = await import('./siem-query.service');
    TestBed.configureTestingModule({
      providers: [{ provide: HttpClient, useValue: { get: () => of({ queries: {} }) } }],
    });
    const siem = TestBed.inject(SiemQueryService);
    for (const d of domains) {
      for (const t of d.tactics) {
        const queries = siem.getQueriesForTechnique('T0000', t.shortname);
        if (KNOWN_SIEM_TEMPLATE_GAPS.has(t.shortname)) {
          expect(queries.length).withContext(`${d.key}: ${t.shortname} is listed as a gap but now has a template`).toBe(0);
        } else {
          expect(queries.length).withContext(`${d.key}: SIEM template for ${t.shortname}`).toBeGreaterThan(0);
          for (const q of queries) {
            expect(q.query).withContext(`${d.key}: ${t.shortname} ${q.platform}`).not.toContain('{{TACTIC}}');
          }
        }
      }
    }
  });

  it('tacticOrderFor(DataService.parseBundle(bundle)) follows each matrix tactic_refs order', () => {
    TestBed.configureTestingModule({
      providers: [{ provide: HttpClient, useValue: { get: () => of({}) } }],
    });
    const data = TestBed.inject(DataService);
    for (const d of domains) {
      const domain = (data as any).parseBundle(d.raw, d.key);
      const order = tacticOrderFor(domain);
      // Mobile ships two matrices; data.service keeps the last one it sees,
      // so compare against the suffix of the concatenated order.
      expect(d.matrixOrder.join(',')).withContext(d.key).toContain(order.join(','));
      expect(order.length).withContext(d.key).toBeGreaterThan(0);
      // Every live technique's tactics sort somewhere in that order (directly or via alias).
      const known = new Set(order.flatMap(s => tacticAliases(s)));
      for (const phase of d.livePhaseNames) {
        if (order.includes(phase)) continue;
        expect(known.has(phase)).withContext(`${d.key}: ${phase} is not in the matrix order`).toBeTrue();
      }
    }
  });
});
