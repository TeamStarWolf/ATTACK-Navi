// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable } from 'rxjs';
import { forkJoin, of, throwError } from 'rxjs';
import { catchError, map, switchMap } from 'rxjs/operators';
import { retryWithBackoff } from '../utils/retry';
import { SourceRegistryService } from './source-registry.service';

export interface CveAttackMapping {
  cveId: string;
  description: string;              // capability_description
  primaryImpact: string[];           // T#### IDs
  secondaryImpact: string[];         // T#### IDs
  exploitationTechnique: string[];   // T#### IDs
  capabilityGroup: string;           // "xxe", "sql_injection", "buffer_overflow", etc.
  comments: string[];                // analyst reasoning per mapping
  references: string[];              // source URLs
  phase: string;
  source: 'ctid-csv' | 'ctid-kev';  // which dataset this came from
}

@Injectable({ providedIn: 'root' })
export class AttackCveService {
  // CTID curated ATT&CK→CVE mapping (839 entries, older CVEs)
  private static readonly CSV_URL =
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv';

  // CTID KEV→ATT&CK mapping. CTID publishes these under a dated directory per ATT&CK
  // release (mappings/kev/attack-<ver>/kev-<MM.DD.YYYY>/), so a pinned path keeps
  // serving an old snapshot indefinitely once a newer one lands — silently, because the
  // old file stays where it is. The newest is discovered at load time and this pinned
  // path is the fallback for when that lookup is unavailable.
  private static readonly KEV_CTID_URL =
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json';

  private static readonly KEV_CTID_API =
    'https://api.github.com/repos/center-for-threat-informed-defense/mappings-explorer/contents/mappings/kev';

  private static readonly RAW_BASE =
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main';

  /** Which KEV snapshot actually loaded, for display and debugging. */
  private kevSourceUrl = AttackCveService.KEV_CTID_URL;

  private byTechniqueId = new Map<string, CveAttackMapping[]>();
  private byCveId = new Map<string, CveAttackMapping>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  /** True once at least one of the two CTID datasets loaded with rows; never after a failure. */
  loaded$ = this.loadedSubject.asObservable();

  private outcomeSubject = new BehaviorSubject<'pending' | 'loaded' | 'failed'>('pending');
  /**
   * How the load settled: 'loaded' when either dataset arrived, 'failed' when neither did.
   * Services that cross-reference CVEs (ExploitDB, Nuclei, trickest) wait on this so a
   * failure here marks them blocked instead of leaving them pending forever.
   */
  readonly outcome$ = this.outcomeSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  /** Number of unique ATT&CK techniques that have ≥1 CVE mapping. */
  covered$ = this.coveredSubject.asObservable();

  private initialized = false;

  constructor(
    private http: HttpClient,
    private sources: SourceRegistryService = new SourceRegistryService(),
  ) {}

  /**
   * Start loading both CTID datasets the first time something needs them. Safe to call
   * any number of times; only the first call makes the requests. Nothing asks at boot
   * on the matrix's default lens: the CVE and EPSS lenses, the KEV scores, the technique
   * drawer, the CVE, dossier, SSVC, roadmap and dashboard views, search and the services
   * that cross-reference CVEs (ExploitDB, Nuclei, trickest) ask for it. Every reader
   * below also asks on its first read, so a view that reads the mapping always gets it,
   * as it did when the mapping loaded at construction; views that show it re-render on
   * loaded$. While it loads, the 'ctid-attack-to-cve' and 'ctid-kev' sources read
   * 'loading'; a failure is recorded on each by name.
   */
  loadOnDemand(): void {
    if (this.initialized) return;
    this.initialized = true;
    this.load();
  }

  /** URL of the KEV snapshot that was actually used. */
  getKevSourceUrl(): string {
    return this.kevSourceUrl;
  }

  /**
   * Resolve the newest KEV→ATT&CK snapshot, falling back to the pinned path.
   *
   * Directory names encode the ATT&CK version (attack-16.1) and the snapshot date
   * (kev-07.28.2025), so "newest" means highest ATT&CK version, then latest date.
   */
  private resolveKevUrl(): Observable<string> {
    const pinned = AttackCveService.KEV_CTID_URL;
    const byName = (names: string[], prefix: string, key: (n: string) => (number | string)[]) =>
      names.filter(n => n.startsWith(prefix)).sort((a, b) => {
        const ka = key(a), kb = key(b);
        for (let i = 0; i < Math.max(ka.length, kb.length); i++) {
          if (ka[i] === kb[i]) continue;
          return ka[i] > kb[i] ? 1 : -1;
        }
        return 0;
      });

    return this.http.get<{ name: string; type: string }[]>(AttackCveService.KEV_CTID_API).pipe(
      switchMap(entries => {
        const versions = byName(
          (entries ?? []).filter(e => e.type === 'dir').map(e => e.name),
          'attack-',
          n => n.replace('attack-', '').split('.').map(Number),
        );
        const version = versions[versions.length - 1];
        if (!version) return of(pinned);
        return this.http
          .get<{ name: string; type: string }[]>(`${AttackCveService.KEV_CTID_API}/${version}`)
          .pipe(
            map(snaps => {
              const dates = byName(
                (snaps ?? []).filter(e => e.type === 'dir').map(e => e.name),
                'kev-',
                n => {
                  const [mm, dd, yyyy] = n.replace('kev-', '').split('.');
                  return [Number(yyyy), Number(mm), Number(dd)];
                },
              );
              const snap = dates[dates.length - 1];
              if (!snap) return pinned;
              return `${AttackCveService.RAW_BASE}/mappings/kev/${version}/${snap}` +
                `/enterprise/${snap}_${version}-enterprise.json`;
            }),
          );
      }),
      // Rate limiting or an offline start must not cost us the mapping entirely.
      catchError(() => of(pinned)),
    );
  }

  private load(): void {
    this.sources.begin('ctid-attack-to-cve');
    this.sources.begin('ctid-kev');
    forkJoin({ csv: this.csv$(), kev: this.kev$() }).subscribe(({ csv, kev }) => this.indexDatasets(csv, kev));
  }

  /**
   * Fetch one dataset again after it failed or came back empty: the data-health Retry
   * (E1.3). The other dataset is left as it is. While the retry runs, the services that
   * wait on outcome$ see 'pending' again rather than the earlier failure.
   */
  retry(id: 'ctid-attack-to-cve' | 'ctid-kev'): void {
    // Not requested yet ("Load now"): load both datasets, as the first use would.
    if (!this.initialized) {
      this.loadOnDemand();
      return;
    }
    this.sources.begin(id);
    if (this.outcomeSubject.value === 'failed') this.outcomeSubject.next('pending');
    forkJoin({
      csv: id === 'ctid-attack-to-cve' ? this.csv$() : of(null),
      kev: id === 'ctid-kev' ? this.kev$() : of(null),
    }).subscribe(({ csv, kev }) => this.indexDatasets(csv, kev));
  }

  // Each dataset records its own failure and yields null, so one failing does not
  // hide the other, and neither failure is reported as an empty, loaded mapping.
  private csv$(): Observable<string | null> {
    return this.http.get(AttackCveService.CSV_URL, { responseType: 'text' }).pipe(
      retryWithBackoff(),
      catchError(err => {
        this.sources.fail('ctid-attack-to-cve', err);
        return of(null);
      }),
    );
  }

  private kev$(): Observable<any> {
    return this.resolveKevUrl().pipe(
      switchMap(url => {
        this.kevSourceUrl = url;
        return this.http.get<any>(url).pipe(
          retryWithBackoff(),
          // A discovered path that does not serve is worse than the pinned one.
          catchError(err => {
            if (url === AttackCveService.KEV_CTID_URL) return throwError(() => err);
            this.kevSourceUrl = AttackCveService.KEV_CTID_URL;
            return this.http.get<any>(AttackCveService.KEV_CTID_URL);
          }),
        );
      }),
      catchError(err => {
        this.sources.fail('ctid-kev', err);
        return of(null);
      }),
    );
  }

  private indexDatasets(csv: string | null, kev: any): void {
    if (csv !== null) {
      this.parseAndIndexCsv(csv);
      this.sources.succeed('ctid-attack-to-cve', this.byCveId.size);
    }
    if (kev !== null) {
      this.parseAndIndexKevJson(kev);
      this.sources.succeed('ctid-kev', Array.isArray(kev?.mapping_objects) ? kev.mapping_objects.length : 0);
    }
    this.totalSubject.next(this.byCveId.size);
    this.coveredSubject.next(this.byTechniqueId.size);
    if (this.byCveId.size > 0) {
      this.loadedSubject.next(true);
      this.outcomeSubject.next('loaded');
    } else {
      this.outcomeSubject.next('failed');
    }
  }

  private parseAndIndexCsv(csv: string): void {
    const lines = csv.replace(/\r/g, '').split('\n').slice(1);

    for (const line of lines) {
      if (!line.trim()) continue;
      const parts = line.split(',');
      if (parts.length < 4) continue;

      const cveId = parts[0].trim();
      if (!cveId.startsWith('CVE-')) continue;

      const parseIds = (s: string) =>
        s.split(';').map(x => x.trim()).filter(x => /^T\d{4}/.test(x));

      const mapping: CveAttackMapping = {
        cveId,
        description: '',
        primaryImpact: parseIds(parts[1] ?? ''),
        secondaryImpact: parseIds(parts[2] ?? ''),
        exploitationTechnique: parseIds(parts[3] ?? ''),
        capabilityGroup: '',
        comments: [],
        references: [],
        phase: parts[5]?.trim() ?? '',
        source: 'ctid-csv',
      };

      this.indexMapping(mapping);
    }
  }

  /** Parse CTID mappings-explorer KEV JSON.
   *  Each mapping_object has a single CVE→technique link with a mapping_type.
   *  We group by CVE so the existing CveAttackMapping shape is preserved,
   *  and we now preserve comments, capability_description, capability_group,
   *  and references from each mapping_object.
   */
  private parseAndIndexKevJson(data: any): void {
    const objects: any[] = data?.mapping_objects ?? [];
    // Group by CVE first so we can build a CveAttackMapping per CVE
    const byCve = new Map<string, {
      primary: string[]; secondary: string[]; exploitation: string[];
      description: string; capabilityGroup: string;
      comments: string[]; references: string[];
    }>();

    for (const obj of objects) {
      const cveId: string = obj.capability_id ?? '';
      const techId: string = obj.attack_object_id ?? '';
      const mtype: string = obj.mapping_type ?? '';
      if (!cveId.startsWith('CVE-') || !/^T\d{4}/.test(techId)) continue;

      if (!byCve.has(cveId)) {
        byCve.set(cveId, {
          primary: [], secondary: [], exploitation: [],
          description: '', capabilityGroup: '', comments: [], references: [],
        });
      }
      const entry = byCve.get(cveId)!;

      // Collect capability_description (use first non-empty one per CVE)
      const capDesc: string = obj.capability_description ?? '';
      if (capDesc && !entry.description) {
        entry.description = capDesc;
      }

      // Collect capability_group
      const capGroup: string = obj.capability_group ?? '';
      if (capGroup && !entry.capabilityGroup) {
        entry.capabilityGroup = capGroup;
      }

      // Collect comments (analyst rationale per mapping_object)
      const comment: string = obj.comments ?? '';
      if (comment && !entry.comments.includes(comment)) {
        entry.comments.push(comment);
      }

      // Collect references (source URLs from each mapping_object)
      const refs: any[] = obj.references ?? [];
      for (const ref of refs) {
        const url = typeof ref === 'string' ? ref : (ref?.url ?? ref?.source ?? '');
        if (url && !entry.references.includes(url)) {
          entry.references.push(url);
        }
      }

      if (mtype === 'primary_impact' && !entry.primary.includes(techId)) {
        entry.primary.push(techId);
      } else if (mtype === 'secondary_impact' && !entry.secondary.includes(techId)) {
        entry.secondary.push(techId);
      } else if (mtype === 'exploitation_technique' && !entry.exploitation.includes(techId)) {
        entry.exploitation.push(techId);
      } else if (
        mtype !== 'primary_impact' && mtype !== 'secondary_impact' && mtype !== 'exploitation_technique'
        && !entry.primary.includes(techId)
      ) {
        entry.primary.push(techId);
      }
    }

    for (const [cveId, entry] of byCve) {
      // If CVE already indexed from CSV, merge technique IDs and metadata in
      const existing = this.byCveId.get(cveId);
      if (existing) {
        const addIfNew = (arr: string[], id: string) => { if (!arr.includes(id)) arr.push(id); };
        entry.primary.forEach(id => addIfNew(existing.primaryImpact, id));
        entry.secondary.forEach(id => addIfNew(existing.secondaryImpact, id));
        entry.exploitation.forEach(id => addIfNew(existing.exploitationTechnique, id));
        // Merge metadata
        if (!existing.description && entry.description) existing.description = entry.description;
        if (!existing.capabilityGroup && entry.capabilityGroup) existing.capabilityGroup = entry.capabilityGroup;
        entry.comments.forEach(c => addIfNew(existing.comments, c));
        entry.references.forEach(r => addIfNew(existing.references, r));
        // Re-index the updated mapping
        const allTechs = [
          ...new Set([
            ...existing.primaryImpact,
            ...existing.secondaryImpact,
            ...existing.exploitationTechnique,
          ]),
        ];
        for (const techId of allTechs) {
          if (!this.byTechniqueId.has(techId)) this.byTechniqueId.set(techId, []);
          if (!this.byTechniqueId.get(techId)!.some(m => m.cveId === cveId)) {
            this.byTechniqueId.get(techId)!.push(existing);
          }
        }
      } else {
        const mapping: CveAttackMapping = {
          cveId,
          description: entry.description,
          primaryImpact: entry.primary,
          secondaryImpact: entry.secondary,
          exploitationTechnique: entry.exploitation,
          capabilityGroup: entry.capabilityGroup,
          comments: entry.comments,
          references: entry.references,
          phase: '',
          source: 'ctid-kev',
        };
        this.indexMapping(mapping);
      }
    }
  }

  private indexMapping(mapping: CveAttackMapping): void {
    this.byCveId.set(mapping.cveId, mapping);
    const allTechs = [
      ...new Set([
        ...mapping.primaryImpact,
        ...mapping.secondaryImpact,
        ...mapping.exploitationTechnique,
      ]),
    ];
    for (const techId of allTechs) {
      if (!this.byTechniqueId.has(techId)) this.byTechniqueId.set(techId, []);
      if (!this.byTechniqueId.get(techId)!.some(m => m.cveId === mapping.cveId)) {
        this.byTechniqueId.get(techId)!.push(mapping);
      }
    }
  }

  getCvesForTechnique(attackId: string): CveAttackMapping[] {
    this.loadOnDemand();
    const direct = this.byTechniqueId.get(attackId) ?? [];
    const prefix = attackId + '.';
    const fromSubs = !attackId.includes('.')
      ? [...this.byTechniqueId.entries()]
          .filter(([k]) => k.startsWith(prefix))
          .flatMap(([, v]) => v)
      : [];
    const seen = new Set<string>();
    return [...direct, ...fromSubs].filter(m => {
      if (seen.has(m.cveId)) return false;
      seen.add(m.cveId);
      return true;
    });
  }

  getMappingForCve(cveId: string): CveAttackMapping | undefined {
    this.loadOnDemand();
    return this.byCveId.get(cveId);
  }

  isCveMapped(cveId: string): boolean {
    this.loadOnDemand();
    return this.byCveId.has(cveId);
  }

  getExploitCvesForTechnique(attackId: string): string[] {
    return this.getCvesForTechnique(attackId)
      .filter(m => m.exploitationTechnique.includes(attackId))
      .map(m => m.cveId);
  }

  /** KEV-sourced CVEs only (from CTID KEV JSON). */
  getKevCvesForTechnique(attackId: string): CveAttackMapping[] {
    return this.getCvesForTechnique(attackId).filter(m => m.source === 'ctid-kev');
  }

  /** Search CVEs by ID, description, or capability group. Returns up to 50 results. */
  searchCves(query: string): CveAttackMapping[] {
    this.loadOnDemand();
    if (!query || query.length < 2) return [];
    const ql = query.toLowerCase();
    const results: CveAttackMapping[] = [];
    for (const mapping of this.byCveId.values()) {
      if (results.length >= 50) break;
      if (
        mapping.cveId.toLowerCase().includes(ql) ||
        mapping.description.toLowerCase().includes(ql) ||
        mapping.capabilityGroup.toLowerCase().includes(ql) ||
        mapping.comments.some(c => c.toLowerCase().includes(ql))
      ) {
        results.push(mapping);
      }
    }
    return results;
  }

  /** Return all CTID-curated mappings (both CSV and KEV sources). */
  getAllCtidMappings(): CveAttackMapping[] {
    this.loadOnDemand();
    return Array.from(this.byCveId.values());
  }
}
