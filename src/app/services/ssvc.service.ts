// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { SourceRegistryService } from './source-registry.service';
import { KevContext, KEV_UNAVAILABLE, NvdCveItem } from '../models/cve';

/**
 * SSVC (Stakeholder-Specific Vulnerability Categorization) decision support.
 *
 * Answers two questions CVSS cannot: how urgently to act, and by when. Both come from
 * CERT/CC's *published* decision tables, loaded from
 * `assets/data/ssvc-decision-tables.json` (regenerate with
 * `node scripts/build-ssvc-tables.mjs`) rather than encoded in TypeScript, so the
 * tables stay auditable against their upstream source.
 *
 *   CISA Coordinator v2.0.3   -> track / track* / attend / act
 *   CISA BOD 26-04 v1.0.0     -> 3 days / 14 days / 60 days / fix on system upgrade
 *
 * Decision points fall into two groups, and the distinction is deliberately visible in
 * the UI rather than smoothed over:
 *
 *   derived         Exploitation and In KEV come from KEV membership and exploit
 *                   evidence. Automatable and Technical Impact are PROXIED from the
 *                   CVSS vector — they are not CVSS fields, and each records its basis.
 *   environmental   Publicly Exposed and Mission & Well-Being depend on the asset, not
 *                   the CVE. They are assumptions the analyst must set.
 *
 * KEV is read through a KevContext (plan E1.3). "Not in KEV" means "not known to be
 * exploited" only when a catalogue is on hand. With no catalogue (the live feed and
 * the bundled snapshot both failed, or the caller did not say), Exploitation and In KEV
 * are 'unknown' and both outcomes are blocked: the result reads
 * 'decision blocked: exploitation unknown', never 'track'. An analyst override of the
 * unknown points unblocks it. With the bundled snapshot, every basis names its date.
 */

export type PointKind = 'derived' | 'environmental' | 'override';

export interface SsvcPoint {
  /** Column name exactly as the CERT/CC table spells it. */
  column: string;
  /** Short label for display. */
  label: string;
  value: string;
  kind: PointKind;
  /** Why the value is what it is — shown to the analyst, never hidden. */
  basis: string;
  /** Values this point may take, for the override controls. */
  options: string[];
}

export interface SsvcResult {
  cveId: string;
  points: SsvcPoint[];
  /** Coordinator outcome; '' when blocked or when no table row matched. */
  action: string;
  actionTable: string;
  /** Why the coordinator outcome is blocked ('exploitation unknown'), or null. */
  actionBlocked: string | null;
  /** BOD 26-04 timeline; '' when blocked or when no table row matched. */
  timeline: string;
  timelineTable: string;
  /** Why the timeline is blocked ('KEV membership unknown'), or null. */
  timelineBlocked: string | null;
  warnings: string[];
}

/** The value of a KEV-derived decision point when no KEV catalogue is on hand. */
export const UNKNOWN = 'unknown';

/** What the SSVC views show in place of an outcome when exploitation is unknown. */
export const DECISION_BLOCKED = 'decision blocked: exploitation unknown';

/** Why each KEV-derived point can block a table, keyed by the point's short name. */
const BLOCKED_REASON: Readonly<Record<string, string>> = {
  exploitation: 'exploitation unknown',
  inKev: 'KEV membership unknown',
};

export interface SsvcEnvironment {
  exposed: 'yes' | 'no';
  mission: 'low' | 'medium' | 'high';
}

interface TableRow {
  key: string[];
  outcome: string;
}

interface DecisionTable {
  id: string;
  label: string;
  describes: string;
  url: string;
  columns: string[];
  outcomeColumn: string;
  outcomes: string[];
  rows: TableRow[];
}

interface TablesAsset {
  __meta?: Record<string, unknown>;
  tables?: Record<string, DecisionTable>;
}

/** Column-name prefixes are stable across table versions; full names are not. */
const COL = {
  exploitation: 'Exploitation',
  automatable: 'Automatable',
  impact: 'Technical Impact',
  inKev: 'In KEV',
  exposed: 'Publicly Exposed',
  mission: 'Mission and Well-Being',
} as const;

export const ACTION_MEANING: Readonly<Record<string, string>> = {
  act: 'Remediate now; prepare a crisis-level response.',
  attend: 'Supervisor attention; remediate sooner than the regular cycle.',
  'track*': 'Monitor closely; remediate within the regular cycle.',
  track: 'No immediate action; remediate within the regular cycle.',
};

export const DEFAULT_ENVIRONMENT: SsvcEnvironment = { exposed: 'yes', mission: 'medium' };

@Injectable({ providedIn: 'root' })
export class SsvcService {
  private tables: Record<string, DecisionTable> = {};
  private meta: Record<string, unknown> = {};

  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$ = this.loadedSubject.asObservable();

  constructor(
    private http: HttpClient,
    private sources: SourceRegistryService = new SourceRegistryService(),
  ) {
    this.loadTables();
  }

  /** Load again after a failed or empty load: the data-health Retry (E1.3). */
  retry(): void {
    this.loadTables();
  }

  private loadTables(): void {
    this.sources.begin('ssvc-tables');
    this.http
      .get<TablesAsset>('assets/data/ssvc-decision-tables.json')
      .subscribe({
        next: data => {
          if (data?.tables) {
            this.tables = data.tables;
            this.meta = data.__meta ?? {};
          }
          const rows = Object.keys(this.tables).length;
          this.sources.succeed('ssvc-tables', rows);
          if (rows > 0) this.loadedSubject.next(true);
        },
        // Recorded as failed; loaded$ stays false and the SSVC panel says the tables did not load.
        error: err => this.sources.fail('ssvc-tables', err),
      });
  }

  get available(): boolean {
    return Object.keys(this.tables).length > 0;
  }

  getMeta(): Record<string, unknown> {
    return { ...this.meta };
  }

  getTable(id: string): DecisionTable | null {
    return this.tables[id] ?? null;
  }

  /** Distinct values a column accepts, read from the table itself. */
  private optionsFor(column: string): string[] {
    for (const table of Object.values(this.tables)) {
      const i = table.columns.indexOf(column);
      if (i >= 0) {
        return [...new Set(table.rows.map(r => r.key[i]))];
      }
    }
    return [];
  }

  private column(prefix: string): string {
    for (const table of Object.values(this.tables)) {
      const hit = table.columns.find(c => c.startsWith(prefix));
      if (hit) return hit;
    }
    return prefix;
  }

  // ── decision point derivation ────────────────────────────────────────────

  /**
   * Automatable: can an adversary reliably automate reconnaissance through
   * exploitation? Proxied from the CVSS vector — network reachable, no privileges, no
   * user interaction, low complexity. Not a CVSS field; override when exploitation
   * needs a specific non-default configuration.
   */
  private automatable(cve: NvdCveItem): { value: string; basis: string } {
    const v = this.parseVector(cve.cvssVector);
    if (!v) {
      return { value: 'no', basis: 'no CVSS vector published; assumed no' };
    }
    const at = v['AT'] ?? 'N'; // CVSS 4.0 Attack Requirements; absent in 3.x
    const yes = v['AV'] === 'N' && v['AC'] === 'L' && v['PR'] === 'N' &&
      v['UI'] === 'N' && at === 'N';
    const shown = ['AV', 'AC', 'PR', 'UI'].map(k => `${k}:${v[k] ?? '?'}`).join(' ');
    return { value: yes ? 'yes' : 'no', basis: `CVSS ${shown}` };
  }

  /**
   * Technical Impact: total when the adversary gains full control of the vulnerable
   * component. Proxied from all three CVSS impact metrics being High.
   */
  private technicalImpact(cve: NvdCveItem): { value: string; basis: string } {
    const v = this.parseVector(cve.cvssVector);
    if (!v) {
      return { value: 'partial', basis: 'no CVSS vector published; assumed partial' };
    }
    // CVSS 4.0 names the vulnerable-system impacts VC/VI/VA.
    const c = v['VC'] ?? v['C'] ?? '?';
    const i = v['VI'] ?? v['I'] ?? '?';
    const a = v['VA'] ?? v['A'] ?? '?';
    const total = c === 'H' && i === 'H' && a === 'H';
    return {
      value: total ? 'total' : 'partial',
      basis: `CVSS impact C:${c} I:${i} A:${a}`,
    };
  }

  /** 'CISA KEV' or 'the bundled CISA KEV snapshot of <date>'. */
  private kevName(kev: KevContext): string {
    return kev.snapshotDate ? `the bundled CISA KEV snapshot of ${kev.snapshotDate}` : 'CISA KEV';
  }

  private exploitation(cve: NvdCveItem, kev: KevContext): { value: string; basis: string } {
    if (cve.isKev) {
      // Membership is positive evidence whatever else failed to load.
      const where = kev.snapshotDate ? `in ${this.kevName(kev)}` : 'in CISA KEV';
      return {
        value: 'active',
        basis: cve.kevKnownRansomware ? `${where} with known ransomware campaign use` : where,
      };
    }
    const exploitRef = (cve.references ?? []).some(r =>
      (r.tags ?? []).some(t => t.toLowerCase() === 'exploit'),
    );
    if (!kev.available) {
      // Absent from an empty map says nothing: the CVE may be in KEV.
      return {
        value: UNKNOWN,
        basis:
          'the CISA KEV catalog did not load, so whether this CVE is exploited in the wild is unknown' +
          (exploitRef ? ' (NVD has an Exploit-tagged reference, so at least public poc)' : ''),
      };
    }
    const dated = kev.snapshotDate
      ? `; KEV read from ${this.kevName(kev)}, so a later KEV addition would not show`
      : '';
    if (exploitRef) {
      return { value: 'public poc', basis: `NVD reference tagged Exploit${dated}` };
    }
    return {
      value: 'none',
      basis: `not in KEV and no Exploit-tagged reference in NVD${dated}`,
    };
  }

  private inKev(cve: NvdCveItem, kev: KevContext): { value: string; basis: string } {
    if (cve.isKev) return { value: 'yes', basis: `${kev.snapshotDate ? this.kevName(kev) : 'CISA KEV catalog'} membership` };
    if (!kev.available) return { value: UNKNOWN, basis: 'the CISA KEV catalog did not load' };
    return { value: 'no', basis: `${kev.snapshotDate ? this.kevName(kev) : 'CISA KEV catalog'} membership` };
  }

  private parseVector(vector: string | null): Record<string, string> | null {
    if (!vector) return null;
    const out: Record<string, string> = {};
    for (const part of vector.split('/')) {
      const [k, val] = part.split(':');
      if (k && val) out[k.trim().toUpperCase()] = val.trim().toUpperCase();
    }
    // A bare "CVSS:3.1" prefix alone is not a vector.
    return Object.keys(out).some(k => k !== 'CVSS') ? out : null;
  }

  // ── evaluation ───────────────────────────────────────────────────────────

  /**
   * Evaluate both tables for a CVE.
   *
   * @param overrides keyed by the short names in COL (exploitation, automatable,
   *   impact, inKev, exposed, mission); any supplied value replaces the derived one.
   * @param kev whether a KEV catalogue is on hand (CveService.kevContext). Defaults to
   *   none: a caller that does not say KEV loaded gets 'exploitation unknown' for any
   *   CVE not flagged in KEV, never a 'track' built on an absent catalogue.
   */
  evaluate(
    cve: NvdCveItem,
    env: SsvcEnvironment = DEFAULT_ENVIRONMENT,
    overrides: Partial<Record<keyof typeof COL, string>> = {},
    kev: KevContext = KEV_UNAVAILABLE,
  ): SsvcResult {
    const warnings: string[] = [];
    if (!this.available) {
      warnings.push('SSVC decision tables are not loaded; no outcome can be computed.');
    }
    if (!cve.cvssVector) {
      warnings.push(
        'No CVSS vector published for this CVE, so Automatable and Technical Impact ' +
          'fall back to conservative defaults. The outcome is provisional.',
      );
    }

    const exploitation = this.exploitation(cve, kev);
    const automatable = this.automatable(cve);
    const impact = this.technicalImpact(cve);

    const build = (
      short: keyof typeof COL,
      label: string,
      derived: { value: string; basis: string },
      kind: PointKind,
    ): SsvcPoint => {
      const column = this.column(COL[short]);
      const override = overrides[short];
      const options = this.optionsFor(column);
      const value = override ?? derived.value;
      return {
        column,
        label,
        value,
        kind: override ? 'override' : kind,
        basis: override ? `analyst override (was "${derived.value}")` : derived.basis,
        // 'unknown' is not a table value; it is offered only while it is the value shown.
        options: value === UNKNOWN && !options.includes(UNKNOWN) ? [UNKNOWN, ...options] : options,
      };
    };

    const points: SsvcPoint[] = [
      build('exploitation', 'Exploitation', exploitation, 'derived'),
      build('inKev', 'In KEV', this.inKev(cve, kev), 'derived'),
      build('automatable', 'Automatable', automatable, 'derived'),
      build('impact', 'Technical Impact', impact, 'derived'),
      build('exposed', 'Publicly Exposed', {
        value: env.exposed,
        basis: 'environmental assumption — not derivable from the CVE',
      }, 'environmental'),
      build('mission', 'Mission & Well-Being', {
        value: env.mission,
        basis: 'environmental assumption — not derivable from the CVE',
      }, 'environmental'),
    ];

    const values = new Map(points.map(p => [p.column, p.value]));
    const blockedBy = new Map<string, string>();
    for (const short of ['exploitation', 'inKev'] as const) {
      const column = this.column(COL[short]);
      if (values.get(column) === UNKNOWN) blockedBy.set(column, BLOCKED_REASON[short]);
    }
    const coordinator = this.decide('cisa-coordinator', values, warnings, blockedBy);
    const bod = this.decide('bod-26-04', values, warnings, blockedBy);

    if (coordinator.blocked || bod.blocked) {
      const exploitationOverridden = !!overrides.exploitation;
      warnings.unshift(
        (coordinator.blocked ? 'Decision blocked: exploitation unknown. ' : '') +
          'Provisional: exploitation unknown. The CISA KEV catalog did not load (neither the live feed ' +
          'nor the bundled snapshot), so "not in KEV" cannot be read as "not exploited". ' +
          (exploitationOverridden
            ? 'Set In KEV by hand as well to get a remediation timeline.'
            : 'Retry KEV, or set Exploitation and In KEV by hand to decide anyway.'),
      );
    } else if (kev.snapshotDate && !cve.isKev) {
      warnings.push(
        `KEV membership is read from the bundled CISA KEV snapshot of ${kev.snapshotDate} because the live ` +
          'feed did not load. A CVE added to KEV after that date shows here as not in KEV, so this outcome ' +
          'is provisional.',
      );
    }

    return {
      cveId: cve.id,
      points,
      action: coordinator.outcome,
      actionTable: coordinator.url,
      actionBlocked: coordinator.blocked,
      timeline: bod.outcome,
      timelineTable: bod.url,
      timelineBlocked: bod.blocked,
      warnings,
    };
  }

  private decide(
    id: string,
    values: Map<string, string>,
    warnings: string[],
    blockedBy: ReadonlyMap<string, string> = new Map(),
  ): { outcome: string; url: string; blocked: string | null } {
    const table = this.tables[id];
    if (!table) return { outcome: '', url: '', blocked: null };

    // A KEV-derived input that is unknown blocks this table: no row is looked up, so
    // no outcome (and in particular no 'track') can come from an absent catalogue.
    const reason = table.columns.map(c => blockedBy.get(c)).find(r => !!r);
    if (reason) return { outcome: '', url: table.url, blocked: reason };

    const key: string[] = [];
    const missing: string[] = [];
    for (const column of table.columns) {
      const v = values.get(column);
      if (v === undefined) {
        missing.push(column);
        key.push('');
      } else {
        key.push(v.toLowerCase());
      }
    }
    if (missing.length > 0) {
      warnings.push(`${table.label}: no value for ${missing.join(', ')}.`);
      return { outcome: '', url: table.url, blocked: null };
    }
    const hit = table.rows.find(r => r.key.every((k, i) => k === key[i]));
    if (!hit) {
      warnings.push(
        `${table.label}: no row matches ${key.join(' / ')}. The table may have been ` +
          'regenerated with different value names.',
      );
      return { outcome: '', url: table.url, blocked: null };
    }
    return { outcome: hit.outcome, url: table.url, blocked: null };
  }

  /** Rank an outcome for sorting: most urgent first. */
  actionRank(action: string): number {
    return ['act', 'attend', 'track*', 'track'].indexOf(action.toLowerCase());
  }

  /** Days implied by a BOD 26-04 timeline, for sorting. Non-numeric means no deadline. */
  timelineDays(timeline: string): number {
    const m = timeline.trim().match(/^(\d+)\s*days?/);
    return m ? Number(m[1]) : Number.MAX_SAFE_INTEGER;
  }
}
