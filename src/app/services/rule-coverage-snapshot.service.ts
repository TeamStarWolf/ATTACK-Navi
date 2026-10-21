// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The bundled rule-coverage snapshot (src/assets/data/rule-coverage-snapshot.json),
// built by scripts/build-rule-coverage-snapshot.mjs from the rule bodies of three
// public rule repositories at pinned commits. ElasticService, SplunkContentService and
// SigmaService (community rules) each read their own section through this service; the
// file is fetched once, on first use, and never imported into the bundle.
import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, catchError, map, shareReplay, throwError } from 'rxjs';
import { describeLoadError } from './source-registry.service';

export const RULE_COVERAGE_SNAPSHOT_URL = 'assets/data/rule-coverage-snapshot.json';

/** The start of every load error from this file: the registry shows it as 'failed', never 'empty'. */
export const SNAPSHOT_MISSING = 'bundled snapshot missing';

export type RuleCoverageKey = 'elastic' | 'splunk' | 'mdecrevoisier';

export interface RuleCoverageRule {
  name: string;
  /** Path inside the upstream repository. */
  path: string;
}

export interface RuleCoverageTechnique {
  /** Rules in the repository naming this technique (or, for a parent, any of its sub-techniques). */
  count: number;
  /** Up to ten of them, sorted by name. */
  rules: RuleCoverageRule[];
}

export interface RuleCoverageSource {
  owner: string;
  repo: string;
  branch: string;
  sha: string;
  commitDate: string;
  licence: string;
  ruleCount: number;
  techniqueCount: number;
  techniques: Record<string, RuleCoverageTechnique>;
}

/** One section of the snapshot, with the date the snapshot was generated. */
export interface RuleCoverageSection extends RuleCoverageSource {
  generated: string;
}

/** A rule name with its permalink at the pinned commit. */
export interface RuleCoverageLink {
  name: string;
  url: string;
}

const SHA = /^[0-9a-f]{40}$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T/;
const TECHNIQUE_ID = /^T\d{4}(?:\.\d{3})?$/;

const isText = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
const isCount = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0;

/** What is wrong with one technique entry, or null when it can be used. */
function techniqueProblem(id: string, t: any): string | null {
  if (!TECHNIQUE_ID.test(id)) return `technique key '${id}' is not an ATT&CK technique id`;
  if (!t || typeof t !== 'object' || Array.isArray(t)) return `technique ${id} is not an object`;
  if (!isCount(t.count)) return `technique ${id} has no rule count`;
  if (!Array.isArray(t.rules)) return `technique ${id} has no rule list`;
  if (t.rules.some((r: any) => !r || typeof r !== 'object' || !isText(r.name) || !isText(r.path))) {
    return `technique ${id} lists a rule without a name or path`;
  }
  return null;
}

/**
 * What is wrong with one section, or null when it can be used. Every field a reader
 * touches is checked here, so a malformed file fails with this reason and never with a
 * TypeError from inside a loader.
 */
function sectionProblem(doc: any, key: RuleCoverageKey): string | null {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return 'not a JSON object';
  if (!isText(doc.generated) || !DATE.test(doc.generated)) return 'no generated date';
  const s = doc.sources?.[key];
  if (!s || typeof s !== 'object' || Array.isArray(s)) return `no '${key}' section`;
  if (!isText(s.owner) || !isText(s.repo) || !isText(s.sha) || !SHA.test(s.sha)) return `'${key}' names no repository or commit`;
  if (!isText(s.branch)) return `'${key}' names no branch`;
  if (!isText(s.commitDate) || !DATE_TIME.test(s.commitDate)) return `'${key}' has no commit date`;
  if (!isText(s.licence)) return `'${key}' names no licence`;
  if (!isCount(s.ruleCount)) return `'${key}' has no rule count`;
  if (!isCount(s.techniqueCount)) return `'${key}' has no technique count`;
  const t = s.techniques;
  if (!t || typeof t !== 'object' || Array.isArray(t)) return `'${key}' lists no techniques`;
  for (const [id, entry] of Object.entries(t)) {
    const problem = techniqueProblem(id, entry);
    if (problem) return `'${key}' ${problem}`;
  }
  if (!Object.values(t).some((x: any) => x.count > 0)) return `'${key}' lists no techniques`;
  return null;
}

/**
 * Why the app's own copy of the file did not arrive. A 404 here means the file is not
 * in this build (it is served from the app's origin, not from GitHub), so the GitHub
 * wording of describeLoadError ('branch or path moved') does not apply.
 */
function describeAssetError(err: unknown): string {
  if (err instanceof HttpErrorResponse) {
    const url = err.url ?? RULE_COVERAGE_SNAPSHOT_URL;
    if (err.status === 404) return `not in this build (HTTP 404): ${url}`;
    if (err.status >= 200 && err.status < 300) return `not valid JSON: ${url}`;
  }
  return describeLoadError(err);
}

/**
 * The error a loader records when reading a section it was handed still throws: always
 * worded as a missing or malformed snapshot, so the registry never shows a bare TypeError.
 */
export function snapshotError(err: unknown): Error {
  const message = err instanceof Error ? err.message : String(err);
  return message.startsWith(SNAPSHOT_MISSING) ? (err as Error) : new Error(`${SNAPSHOT_MISSING} or malformed: ${message}`);
}

/** https://github.com/<owner>/<repo>/blob/<sha>/<path>, each path segment encoded. */
export function rulePermalink(source: Pick<RuleCoverageSource, 'owner' | 'repo' | 'sha'>, path: string): string {
  const encoded = path.split('/').map(encodeURIComponent).join('/');
  return `https://github.com/${source.owner}/${source.repo}/blob/${source.sha}/${encoded}`;
}

/** The registry version line, in the KEV snapshot's wording. */
export function snapshotVersion(section: RuleCoverageSection): string {
  return `snapshot of ${section.generated}, ${section.owner}/${section.repo}@${section.sha.slice(0, 7)}`
    + ` (commit ${section.commitDate.slice(0, 10)}, ${section.branch})`;
}

/** The rules a section lists for one technique, as names with permalinks. */
export function ruleLinks(section: RuleCoverageSource, attackId: string): RuleCoverageLink[] {
  return (section.techniques[attackId]?.rules ?? []).map(r => ({ name: r.name, url: rulePermalink(section, r.path) }));
}

@Injectable({ providedIn: 'root' })
export class RuleCoverageSnapshotService {
  private readonly http = inject(HttpClient);
  private file$?: Observable<unknown>;

  /**
   * One section of the snapshot. Errors with an Error whose message starts with
   * SNAPSHOT_MISSING when the file does not load or the section is malformed.
   */
  section(key: RuleCoverageKey): Observable<RuleCoverageSection> {
    if (!this.file$) {
      this.file$ = this.http.get<unknown>(RULE_COVERAGE_SNAPSHOT_URL).pipe(
        catchError(err => {
          // Not cached: the next reader asks again (shareReplay resets after an error).
          return throwError(() => new Error(`${SNAPSHOT_MISSING} (${describeAssetError(err)})`));
        }),
        shareReplay(1),
      );
    }
    return this.file$.pipe(
      map((doc: any) => {
        const problem = sectionProblem(doc, key);
        if (problem) throw new Error(`${SNAPSHOT_MISSING} or malformed: ${problem}`);
        return { ...doc.sources[key], generated: doc.generated } as RuleCoverageSection;
      }),
    );
  }
}
