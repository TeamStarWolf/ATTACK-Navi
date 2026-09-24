// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, catchError, of } from 'rxjs';
import { NvdCveItem } from '../models/cve';

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
  action: string;
  actionTable: string;
  timeline: string;
  timelineTable: string;
  warnings: string[];
}

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

  constructor(private http: HttpClient) {
    this.http
      .get<TablesAsset>('assets/data/ssvc-decision-tables.json')
      .pipe(catchError(() => of(null)))
      .subscribe(data => {
        if (data?.tables) {
          this.tables = data.tables;
          this.meta = data.__meta ?? {};
        }
        this.loadedSubject.next(true);
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

  private exploitation(cve: NvdCveItem): { value: string; basis: string } {
    if (cve.isKev) {
      return {
        value: 'active',
        basis: cve.kevKnownRansomware
          ? 'in CISA KEV with known ransomware campaign use'
          : 'in CISA KEV',
      };
    }
    const exploitRef = (cve.references ?? []).some(r =>
      (r.tags ?? []).some(t => t.toLowerCase() === 'exploit'),
    );
    if (exploitRef) {
      return { value: 'public poc', basis: 'NVD reference tagged Exploit' };
    }
    return {
      value: 'none',
      basis: 'not in KEV and no Exploit-tagged reference in NVD',
    };
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
   */
  evaluate(
    cve: NvdCveItem,
    env: SsvcEnvironment = DEFAULT_ENVIRONMENT,
    overrides: Partial<Record<keyof typeof COL, string>> = {},
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

    const exploitation = this.exploitation(cve);
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
      return {
        column,
        label,
        value: override ?? derived.value,
        kind: override ? 'override' : kind,
        basis: override ? `analyst override (was "${derived.value}")` : derived.basis,
        options: this.optionsFor(column),
      };
    };

    const points: SsvcPoint[] = [
      build('exploitation', 'Exploitation', exploitation, 'derived'),
      build('inKev', 'In KEV', {
        value: cve.isKev ? 'yes' : 'no',
        basis: 'CISA KEV catalog membership',
      }, 'derived'),
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
    const coordinator = this.decide('cisa-coordinator', values, warnings);
    const bod = this.decide('bod-26-04', values, warnings);

    return {
      cveId: cve.id,
      points,
      action: coordinator.outcome,
      actionTable: coordinator.url,
      timeline: bod.outcome,
      timelineTable: bod.url,
      warnings,
    };
  }

  private decide(
    id: string,
    values: Map<string, string>,
    warnings: string[],
  ): { outcome: string; url: string } {
    const table = this.tables[id];
    if (!table) return { outcome: '', url: '' };

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
      return { outcome: '', url: table.url };
    }
    const hit = table.rows.find(r => r.key.every((k, i) => k === key[i]));
    if (!hit) {
      warnings.push(
        `${table.label}: no row matches ${key.join(' / ')}. The table may have been ` +
          'regenerated with different value names.',
      );
      return { outcome: '', url: table.url };
    }
    return { outcome: hit.outcome, url: table.url };
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
