// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of, timeout, catchError, map } from 'rxjs';

/**
 * CISA's *authoritative, published* SSVC decision for a CVE.
 *
 * This is deliberately SEPARATE from `ssvc.service.ts` (`SsvcService`), which is an
 * analyst-facing SSVC *calculator* — it PROXIES Automatable / Technical Impact from the
 * CVSS vector and takes Exploitation from KEV, then runs the CERT/CC decision tables.
 * This service instead RETRIEVES the decision points CISA itself published: it reads the
 * CISA ADP (Authorized Data Publisher) container inside the CVE 5.0 record
 * (containers.adp[].metrics[].other where type === "ssvc"), also mirrored in the
 * cisagov/vulnrichment repo. Data is CC0 — "data from CISA via the CVE Program".
 *
 * Source: the official CVE Services (CVE Program) API, which returns the full CVE 5.0
 * record including the CISA ADP/SSVC container and sends
 * `Access-Control-Allow-Origin: *` (so it is browser-CORS-safe).
 */

export type SsvcExploitation = 'none' | 'poc' | 'active';
export type SsvcAutomatable = 'no' | 'yes';
export type SsvcTechnicalImpact = 'partial' | 'total';
export type SsvcMissionWellbeing = 'low' | 'medium' | 'high';
export type SsvcDecision = 'Track' | 'Track*' | 'Attend' | 'Act';

export interface CisaSsvcAssessment {
  cveId: string;
  exploitation: SsvcExploitation;
  automatable: SsvcAutomatable;
  technicalImpact: SsvcTechnicalImpact;
  /** Computed decision (see TREE). Because CISA does not publish Mission & Well-being in
   *  the ADP container, this is evaluated at the representative default (medium). */
  decision: SsvcDecision;
  /** Distinct decisions the published points yield across Mission & Well-being
   *  low/medium/high, ordered least→most severe. Length > 1 ⇒ the decision depends on
   *  the (unpublished) M&W, so the single `decision` is a representative choice. */
  decisionRange: SsvcDecision[];
  /** The Mission & Well-being value assumed to resolve `decision` (not published by CISA). */
  assumedMissionWellbeing: SsvcMissionWellbeing;
  role: string;       // "CISA Coordinator"
  version: string;    // SSVC methodology version, e.g. "2.0.3"
  timestamp: string;  // when CISA scored it (ISO 8601), may be empty
}

// The CISA Coordinator SSVC decision tree, v2.0.3 (36 rows), reproduced verbatim from
// CERTCC/SSVC data/csv/cisa/cisa_coordinator_2_0_3.csv (the "public poc" value is keyed
// here as 'poc' to match the ADP container's Exploitation vocabulary).
// Key: `${exploitation}|${automatable}|${technicalImpact}|${missionWellbeing}`.
const TREE: Record<string, SsvcDecision> = {
  'none|no|partial|low': 'Track',
  'none|no|partial|medium': 'Track',
  'none|no|partial|high': 'Track',
  'none|no|total|low': 'Track',
  'none|no|total|medium': 'Track',
  'none|no|total|high': 'Track*',
  'none|yes|partial|low': 'Track',
  'none|yes|partial|medium': 'Track',
  'none|yes|partial|high': 'Attend',
  'none|yes|total|low': 'Track',
  'none|yes|total|medium': 'Track',
  'none|yes|total|high': 'Attend',
  'poc|no|partial|low': 'Track',
  'poc|no|partial|medium': 'Track',
  'poc|no|partial|high': 'Track*',
  'poc|no|total|low': 'Track',
  'poc|no|total|medium': 'Track*',
  'poc|no|total|high': 'Attend',
  'poc|yes|partial|low': 'Track',
  'poc|yes|partial|medium': 'Track',
  'poc|yes|partial|high': 'Attend',
  'poc|yes|total|low': 'Track',
  'poc|yes|total|medium': 'Track*',
  'poc|yes|total|high': 'Attend',
  'active|no|partial|low': 'Track',
  'active|no|partial|medium': 'Track',
  'active|no|partial|high': 'Attend',
  'active|no|total|low': 'Track',
  'active|no|total|medium': 'Attend',
  'active|no|total|high': 'Act',
  'active|yes|partial|low': 'Attend',
  'active|yes|partial|medium': 'Attend',
  'active|yes|partial|high': 'Act',
  'active|yes|total|low': 'Attend',
  'active|yes|total|medium': 'Act',
  'active|yes|total|high': 'Act',
};

const SEVERITY_ORDER: SsvcDecision[] = ['Track', 'Track*', 'Attend', 'Act'];

// NOTE (decision-tree limitation): CISA's full Coordinator tree has FOUR decision points,
// but the ADP container publishes only three (Exploitation, Automatable, Technical Impact).
// Mission & Well-being is deployer-/environment-specific and is NOT published, so a single
// CISA decision is not uniquely determined by the record. We therefore evaluate the real
// tree at the representative default Mission & Well-being = "medium" (the SSVC calculator
// midpoint; this yields CISA's publicly-stated "Act" for Log4Shell), and expose the full
// range across low/medium/high in `decisionRange` + the tooltip so nothing is hidden.
const DEFAULT_MISSION_WELLBEING: SsvcMissionWellbeing = 'medium';

/** Pure decision-tree lookup. Exposed for testing. */
export function decideSsvc(
  exploitation: SsvcExploitation,
  automatable: SsvcAutomatable,
  technicalImpact: SsvcTechnicalImpact,
  missionWellbeing: SsvcMissionWellbeing = DEFAULT_MISSION_WELLBEING,
): SsvcDecision {
  return TREE[`${exploitation}|${automatable}|${technicalImpact}|${missionWellbeing}`] ?? 'Track';
}

/** Distinct decisions across all Mission & Well-being values, least→most severe. */
export function ssvcDecisionRange(
  exploitation: SsvcExploitation,
  automatable: SsvcAutomatable,
  technicalImpact: SsvcTechnicalImpact,
): SsvcDecision[] {
  const decisions = (['low', 'medium', 'high'] as SsvcMissionWellbeing[])
    .map(mw => decideSsvc(exploitation, automatable, technicalImpact, mw));
  return SEVERITY_ORDER.filter(d => decisions.includes(d));
}

/** Parse the CISA SSVC assessment out of a CVE 5.0 record. Returns null when the record
 *  carries no usable CISA SSVC container (never throws). Exposed for testing. */
export function parseCisaSsvcRecord(cveId: string, record: any): CisaSsvcAssessment | null {
  const adp: any[] = record?.containers?.adp ?? [];
  for (const entry of adp) {
    for (const metric of (entry?.metrics ?? [])) {
      const other = metric?.other;
      if (!other || other.type !== 'ssvc' || !other.content) continue;
      const content = other.content;
      const opts = new Map<string, string>();
      for (const opt of (content.options ?? [])) {
        for (const [k, v] of Object.entries(opt ?? {})) {
          opts.set(k.toLowerCase(), String(v).toLowerCase());
        }
      }

      const exploitation = normalizeExploitation(opts.get('exploitation'));
      const automatable = normalizeAutomatable(opts.get('automatable'));
      const technicalImpact = normalizeTechnicalImpact(opts.get('technical impact'));
      if (!exploitation || !automatable || !technicalImpact) continue;

      return {
        cveId,
        exploitation,
        automatable,
        technicalImpact,
        decision: decideSsvc(exploitation, automatable, technicalImpact),
        decisionRange: ssvcDecisionRange(exploitation, automatable, technicalImpact),
        assumedMissionWellbeing: DEFAULT_MISSION_WELLBEING,
        role: content.role ?? 'CISA Coordinator',
        version: content.version ?? '',
        timestamp: content.timestamp ?? '',
      };
    }
  }
  return null;
}

function normalizeExploitation(v: string | undefined): SsvcExploitation | null {
  if (!v) return null;
  if (v === 'none') return 'none';
  if (v.includes('poc')) return 'poc';          // "poc" | "public poc" | "public_poc"
  if (v === 'active') return 'active';
  return null;
}
function normalizeAutomatable(v: string | undefined): SsvcAutomatable | null {
  if (v === 'yes') return 'yes';
  if (v === 'no') return 'no';
  return null;
}
function normalizeTechnicalImpact(v: string | undefined): SsvcTechnicalImpact | null {
  if (v === 'partial') return 'partial';
  if (v === 'total') return 'total';
  return null;
}

@Injectable({ providedIn: 'root' })
export class CisaSsvcService {
  // Official CVE Services (CVE Program) API — returns the full CVE 5.0 record including
  // CISA's ADP/SSVC container. Sends Access-Control-Allow-Origin: * (browser-CORS-safe).
  private readonly CVE_API = 'https://cveawg.mitre.org/api/cve';

  // cache: cveId -> assessment, or null = record fetched OK but carries no CISA SSVC.
  private cache = new Map<string, CisaSsvcAssessment | null>();
  // errored: cveId -> fetch failed (network/CORS/timeout/404); decision is unknown, not absent.
  private errored = new Set<string>();

  constructor(private http: HttpClient) {}

  /** Fetch + parse CISA's published SSVC for a CVE. Cached; never throws (null on miss). */
  fetchSsvc(cveId: string): Observable<CisaSsvcAssessment | null> {
    const id = cveId.toUpperCase();
    if (this.cache.has(id)) return of(this.cache.get(id)!);

    return this.http.get<any>(`${this.CVE_API}/${encodeURIComponent(id)}`).pipe(
      timeout(10000),
      map(record => {
        const assessment = parseCisaSsvcRecord(id, record);
        this.cache.set(id, assessment);
        this.errored.delete(id);
        return assessment;
      }),
      catchError(() => {
        // CORS-blocked, offline, rate-limited, or not-found — record "unknown", do NOT fabricate.
        this.errored.add(id);
        return of(null);
      }),
    );
  }

  /** Synchronous cache read: the assessment, or null if not fetched / absent. */
  getSsvc(cveId: string): CisaSsvcAssessment | null {
    return this.cache.get(cveId.toUpperCase()) ?? null;
  }

  /** True when the last fetch for this CVE failed (so the decision is unknown, not absent). */
  hasError(cveId: string): boolean {
    const id = cveId.toUpperCase();
    return this.errored.has(id) && !this.cache.has(id);
  }

  /** The SCSS modifier class for a decision (colors are token-driven in the component SCSS). */
  badgeClass(decision: SsvcDecision): string {
    switch (decision) {
      case 'Act': return 'ssvc-badge--act';
      case 'Attend': return 'ssvc-badge--attend';
      case 'Track*': return 'ssvc-badge--track-star';
      default: return 'ssvc-badge--track';
    }
  }

  /** Human-readable hover text: the three published points, the M&W caveat, and attribution. */
  tooltip(a: CisaSsvcAssessment): string {
    const pts =
      `Exploitation: ${a.exploitation} · Automatable: ${a.automatable} · Technical Impact: ${a.technicalImpact}`;
    const mw =
      a.decisionRange.length > 1
        ? `Decision ${a.decision} (assumes Mission & Well-being = ${a.assumedMissionWellbeing}; not published by CISA — range ${a.decisionRange.join('→')})`
        : `Decision ${a.decision}`;
    const src = `${a.role}${a.version ? ' · SSVC v' + a.version : ''} — data from CISA via the CVE Program (CC0)`;
    return `CISA SSVC — ${pts}. ${mw}. ${src}`;
  }
}
