// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The bundled rule-coverage snapshot (src/assets/data/rule-coverage-snapshot.json),
// built by scripts/build-rule-coverage-snapshot.mjs from the rule bodies of three
// public rule repositories at pinned commits. ElasticService, SplunkContentService and
// SigmaService (community rules) each read their own section through this service; the
// file is fetched once, on first use, and never imported into the bundle.
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
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

/** What is wrong with one section, or null when it can be used. */
function sectionProblem(doc: any, key: RuleCoverageKey): string | null {
  if (!doc || typeof doc !== 'object') return 'not a JSON object';
  if (!/^\d{4}-\d{2}-\d{2}$/.test(doc.generated ?? '')) return 'no generated date';
  const s = doc.sources?.[key];
  if (!s || typeof s !== 'object') return `no '${key}' section`;
  if (!s.owner || !s.repo || !SHA.test(s.sha ?? '')) return `'${key}' names no repository or commit`;
  const t = s.techniques;
  if (!t || typeof t !== 'object' || Array.isArray(t) || !Object.values(t).some((x: any) => x?.count > 0)) {
    return `'${key}' lists no techniques`;
  }
  return null;
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
          return throwError(() => new Error(`${SNAPSHOT_MISSING} (${describeLoadError(err)})`));
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
