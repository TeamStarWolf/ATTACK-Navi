// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { catchError, of } from 'rxjs';
import { retryWithBackoff } from '../utils/retry';

export interface M365Query {
  title: string;      // filename without extension
  tactic: string;     // parent folder name
  url: string;        // GitHub raw URL
  path: string;       // repo path
}

interface GitHubTree {
  sha: string;
  url: string;
  tree: Array<{
    path: string;
    mode: string;
    type: string;
    sha: string;
    size?: number;
    url: string;
  }>;
  truncated: boolean;
}

/**
 * Map of ATT&CK tactic display names (as used in the Microsoft 365 Defender
 * Hunting Queries repo folder structure) to ATT&CK tactic shortnames used
 * in the MITRE ATT&CK framework.
 */
const TACTIC_FOLDER_MAP: Record<string, string> = {
  'Reconnaissance': 'reconnaissance',
  'Resource Development': 'resource-development',
  'Initial Access': 'initial-access',
  'initial-access': 'initial-access',
  'Execution': 'execution',
  'Persistence': 'persistence',
  'Privilege Escalation': 'privilege-escalation',
  'Defense Evasion': 'defense-evasion',
  'Credential Access': 'credential-access',
  'Discovery': 'discovery',
  'Lateral Movement': 'lateral-movement',
  'Collection': 'collection',
  'Command and Control': 'command-and-control',
  'Exfiltration': 'exfiltration',
  'Impact': 'impact',
  // Common alternate casing/naming
  'Command And Control': 'command-and-control',
  'CredentialAccess': 'credential-access',
  'DefenseEvasion': 'defense-evasion',
  'InitialAccess': 'initial-access',
  'LateralMovement': 'lateral-movement',
  'PrivilegeEscalation': 'privilege-escalation',
  'ResourceDevelopment': 'resource-development',
};

// NOTE: Microsoft archived this repo in 2022 — the queries are genuine and
// still served, but no longer updated.
const GITHUB_TREE_URL =
  'https://api.github.com/repos/microsoft/Microsoft-365-Defender-Hunting-Queries/git/trees/master?recursive=1';

const GITHUB_BLOB_BASE =
  'https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master';

@Injectable({ providedIn: 'root' })
export class M365DefenderService {
  /** Direct mapping: attackId (e.g. 'T1059' or 'T1059.001') -> M365Query[] */
  private queryMap = new Map<string, M365Query[]>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  readonly total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  readonly covered$ = this.coveredSubject.asObservable();

  private initialized = false;

  constructor(private http: HttpClient) {}

  /** Trigger data fetch on first use. Safe to call multiple times. */
  loadOnDemand(): void {
    if (this.initialized) return;
    this.initialized = true;
    this.loadTree();
  }

  // ─── Public API ──────────────────────────────────────────────────────────────

  /** Returns all M365 Defender hunting queries mapped to a technique. */
  getQueriesForTechnique(attackId: string): M365Query[] {
    const direct = this.queryMap.get(attackId) ?? [];
    // Also check parent technique for sub-technique queries
    if (attackId.includes('.')) {
      const parent = attackId.split('.')[0];
      const parentQueries = this.queryMap.get(parent) ?? [];
      return [...direct, ...parentQueries.filter(q => !direct.some(d => d.path === q.path))];
    }
    // For parent technique, also roll up sub-technique queries
    const results = [...direct];
    const prefix = attackId + '.';
    for (const [id, queries] of this.queryMap) {
      if (id.startsWith(prefix)) {
        for (const q of queries) {
          if (!results.some(r => r.path === q.path)) results.push(q);
        }
      }
    }
    return results;
  }

  /** Query count for a technique (with parent rollup), used as heatmap score. */
  getHeatScore(attackId: string): number {
    return this.getQueriesForTechnique(attackId).length;
  }

  // ─── Private ─────────────────────────────────────────────────────────────────

  private loadTree(): void {
    this.http.get<GitHubTree>(GITHUB_TREE_URL)
      .pipe(retryWithBackoff(), catchError(() => of(null)))
      .subscribe(tree => {
        if (tree?.tree?.length) {
          this.parseTree(tree);
        }
        this.loadedSubject.next(true);
      });
  }

  private parseTree(tree: GitHubTree): void {
    const validExtensions = ['.kql', '.md', '.kusto', '.csl'];
    let totalQueries = 0;
    const coveredIds = new Set<string>();

    for (const node of tree.tree) {
      if (node.type !== 'blob') continue;

      const ext = this.getExtension(node.path);
      if (!validExtensions.includes(ext)) continue;

      // Skip root-level README and non-query files
      const parts = node.path.split('/');
      if (parts.length < 2) continue;
      if (node.path.toLowerCase().includes('readme')) continue;

      const folderName = parts[0];
      const fileName = parts[parts.length - 1];
      const title = fileName.replace(/\.(kql|md|kusto|csl)$/i, '').replace(/[-_]/g, ' ');

      // Determine tactic from folder name
      const tacticShortname = TACTIC_FOLDER_MAP[folderName];
      if (!tacticShortname) continue; // Not a recognized tactic folder

      const query: M365Query = {
        title,
        tactic: folderName,
        url: `${GITHUB_BLOB_BASE}/${encodeURI(node.path)}`,
        path: node.path,
      };

      // Extract technique IDs from the filename (e.g. T1059, T1059.001).
      // Only files Microsoft explicitly tagged with a technique id are
      // attributed to techniques — untagged files previously fanned out to
      // EVERY technique in the tactic (up to 35), crediting techniques with
      // queries that have nothing to do with them.
      const techIds = this.extractTechniqueIds(node.path);
      totalQueries++;

      for (const id of techIds) {
        const existing = this.queryMap.get(id) ?? [];
        existing.push(query);
        this.queryMap.set(id, existing);
        coveredIds.add(id.split('.')[0]); // count parent technique as covered
      }
    }

    this.totalSubject.next(totalQueries);
    this.coveredSubject.next(coveredIds.size);
  }

  /** Extract T-codes from a file path like "Execution/T1059-PowerShell.kql" */
  private extractTechniqueIds(path: string): string[] {
    const ids: string[] = [];
    // Match T followed by 4 digits, optionally .3 digits for sub-technique
    const regex = /T(\d{4})(?:\.(\d{3}))?/g;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(path)) !== null) {
      const id = match[2] ? `T${match[1]}.${match[2]}` : `T${match[1]}`;
      if (!ids.includes(id)) ids.push(id);
    }
    return ids;
  }

  private getExtension(path: string): string {
    const lastDot = path.lastIndexOf('.');
    return lastDot >= 0 ? path.substring(lastDot).toLowerCase() : '';
  }
}
