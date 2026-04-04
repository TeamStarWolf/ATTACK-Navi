import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { catchError, of } from 'rxjs';
import { AttackCveService } from './attack-cve.service';

/**
 * Nuclei Templates Service
 *
 * Fetches the nuclei-templates GitHub tree to identify CVE-based templates,
 * then cross-references them against AttackCveService to map templates
 * to ATT&CK technique IDs.
 */
@Injectable({ providedIn: 'root' })
export class NucleiService {
  // GitHub API to list the full repo tree recursively
  private static readonly TREE_URL =
    'https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1';

  /** attackId -> nuclei template count */
  private byTechnique = new Map<string, number>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  /** Total number of nuclei CVE templates that mapped to at least one ATT&CK technique. */
  readonly total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  /** Number of unique ATT&CK techniques covered by nuclei templates. */
  readonly covered$ = this.coveredSubject.asObservable();

  constructor(
    private http: HttpClient,
    private attackCveService: AttackCveService,
  ) {
    this.load();
  }

  private load(): void {
    // Wait for AttackCveService to finish loading before cross-referencing
    const sub = this.attackCveService.loaded$.subscribe(cveLoaded => {
      if (!cveLoaded) return;
      sub.unsubscribe();
      this.fetchTree();
    });
  }

  private fetchTree(): void {
    this.http.get<GitHubTree>(NucleiService.TREE_URL)
      .pipe(catchError(() => of(null)))
      .subscribe(tree => {
        if (tree?.tree) {
          this.processTree(tree.tree);
        }
        this.loadedSubject.next(true);
      });
  }

  private processTree(entries: GitHubTreeEntry[]): void {
    // CVE templates live under paths like: http/cves/2021/CVE-2021-44228.yaml
    // or cves/2021/CVE-2021-44228.yaml
    const cvePattern = /CVE-(\d{4})-(\d+)/i;
    const techCounts = new Map<string, number>();
    let totalMapped = 0;

    // Collect unique CVE IDs from file paths under cves/ directories
    const seenCves = new Set<string>();
    for (const entry of entries) {
      if (entry.type !== 'blob') continue;
      if (!entry.path.includes('cves/') && !entry.path.includes('CVE-')) continue;
      if (!entry.path.endsWith('.yaml') && !entry.path.endsWith('.yml')) continue;

      const match = entry.path.match(cvePattern);
      if (!match) continue;

      const cveId = `CVE-${match[1]}-${match[2]}`;
      if (seenCves.has(cveId)) continue;
      seenCves.add(cveId);

      // Cross-reference to ATT&CK
      const mapping = this.attackCveService.getMappingForCve(cveId);
      if (!mapping) continue;
      totalMapped++;

      const allTechs = new Set([
        ...mapping.primaryImpact,
        ...mapping.secondaryImpact,
        ...mapping.exploitationTechnique,
      ]);
      for (const techId of allTechs) {
        techCounts.set(techId, (techCounts.get(techId) ?? 0) + 1);
      }
    }

    this.byTechnique = techCounts;
    this.totalSubject.next(totalMapped);
    this.coveredSubject.next(techCounts.size);
  }

  /** Number of nuclei templates mapped to the given ATT&CK technique. */
  getTemplateCount(attackId: string): number {
    const direct = this.byTechnique.get(attackId) ?? 0;
    if (attackId.includes('.')) return direct;
    // For parent techniques, also sum subtechnique counts
    let sub = 0;
    const prefix = attackId + '.';
    for (const [id, count] of this.byTechnique) {
      if (id.startsWith(prefix)) sub += count;
    }
    return direct + sub;
  }

  /** Whether any nuclei templates are mapped to this technique. */
  hasTemplates(attackId: string): boolean {
    return this.getTemplateCount(attackId) > 0;
  }
}

/** GitHub Trees API response shape */
interface GitHubTree {
  sha: string;
  url: string;
  tree: GitHubTreeEntry[];
  truncated: boolean;
}

interface GitHubTreeEntry {
  path: string;
  mode: string;
  type: 'blob' | 'tree';
  sha: string;
  size?: number;
  url: string;
}
