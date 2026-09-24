// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, map, of } from 'rxjs';

import {
  CveDossier,
  DossierArticle,
  DossierControl,
  DossierCountermeasure,
  DossierDetection,
  DossierExploits,
  DossierNamed,
  DossierTechnique,
  DossierTier,
} from '../models/dossier';
import { NvdCveItem } from '../models/cve';
import { AtomicService } from './atomic.service';
import { AttackCveService } from './attack-cve.service';
import { CapecService } from './capec.service';
import { Cve2CapecService } from './cve2capec.service';
import { CveService } from './cve.service';
import { D3fendService } from './d3fend.service';
import { DataService } from './data.service';
import { EngageService } from './engage.service';
import { EpssService } from './epss.service';
import { NistMappingService } from './nist-mapping.service';
import { PocExploitService } from './poc-exploit.service';
import { SigmaService } from './sigma.service';
import { DEFAULT_ENVIRONMENT, SsvcEnvironment, SsvcService } from './ssvc.service';

const ASSET_DIR = 'assets/data/dossiers';

/**
 * Assembles one CVE across every framework the app knows about.
 *
 * Assets first, live fallback. A pre-generated asset is preferred because it can carry
 * material the browser cannot reach — published reporting, Exploit-DB rows, hunt
 * queries. When there is no asset, the dossier is composed from services that are
 * already loaded, so any CVE still works; the sections an asset would have supplied are
 * reported as missing rather than quietly rendered empty.
 *
 * The two paths produce the same shape, and `source` says which one ran.
 */
@Injectable({ providedIn: 'root' })
export class DossierService {
  /** CVEs for which an asset exists, from the generated index. Null until loaded. */
  private assetIndex: Set<string> | null = null;

  constructor(
    private http: HttpClient,
    private cveService: CveService,
    private ssvc: SsvcService,
    private attackCve: AttackCveService,
    private cve2capec: Cve2CapecService,
    private capecService: CapecService,
    private d3fend: D3fendService,
    private engage: EngageService,
    private nist: NistMappingService,
    private dataService: DataService,
    private epss: EpssService,
    private poc: PocExploitService,
    private sigma: SigmaService,
    private atomic: AtomicService,
  ) {
    this.http
      .get<{ cves?: string[] }>(`${ASSET_DIR}/index.json`)
      .pipe(catchError(() => of(null)))
      .subscribe(idx => {
        this.assetIndex = new Set((idx?.cves ?? []).map(c => c.toUpperCase()));
      });
  }

  /** True when a pre-generated dossier is known to exist for this CVE. */
  hasAsset(cveId: string): boolean {
    return this.assetIndex?.has(cveId.toUpperCase()) ?? false;
  }

  get indexLoaded(): boolean {
    return this.assetIndex !== null;
  }

  get assetCount(): number {
    return this.assetIndex?.size ?? 0;
  }

  /**
   * Load a dossier. Tries the asset even when the index says there is none — the index
   * can lag the files, and a 404 costs one request.
   */
  load(cveId: string, env: SsvcEnvironment = DEFAULT_ENVIRONMENT): Observable<CveDossier> {
    const id = cveId.trim().toUpperCase();
    return this.http.get<Partial<CveDossier>>(`${ASSET_DIR}/${id}.json`).pipe(
      map(raw => this.fromAsset(id, raw, env)),
      catchError(() => of(this.compose(id, env))),
    );
  }

  /**
   * Re-run the parts that depend on environmental SSVC inputs, and on data that may
   * have arrived since the dossier was built.
   *
   * An asset opened by direct link is assembled before the KEV catalogue finishes
   * loading, so the first verdict can be computed with `isKev: false` — which is not a
   * missing badge but a materially weaker outcome (`track*` instead of `act`). This
   * must therefore work with no NVD record cached, by synthesizing the CVE from the
   * dossier itself, and must refresh the dossier's own KEV fields too.
   */
  reevaluate(dossier: CveDossier, env: SsvcEnvironment): CveDossier {
    if (!this.ssvc.available) return dossier;
    const cached = this.cveService.getCachedCve(dossier.cveId);
    const cve = this.withLiveKev(cached ?? this.synthesizeCve(dossier));
    const entry = this.cveService.getKevEntry(dossier.cveId);
    return {
      ...dossier,
      isKev: cve.isKev,
      kevDateAdded: entry?.dateAdded ?? dossier.kevDateAdded,
      kevDueDate: entry?.dueDate ?? dossier.kevDueDate,
      kevRansomware: entry
        ? entry.knownRansomwareCampaignUse?.toLowerCase() === 'known'
        : dossier.kevRansomware,
      kevVendorProject: entry?.vendorProject ?? dossier.kevVendorProject,
      kevProduct: entry?.product ?? dossier.kevProduct,
      ssvc: this.ssvc.evaluate(cve, env),
    };
  }

  // ── asset path ───────────────────────────────────────────────────────────

  /**
   * Merge a generated asset with whatever the app can add now.
   *
   * The asset is authoritative for its own fields, but it was generated at a point in
   * time: KEV membership and EPSS move, and the app holds fresher copies. SSVC is
   * always recomputed so the environmental inputs on screen are the ones that produced
   * the verdict.
   */
  private fromAsset(id: string, raw: Partial<CveDossier>, env: SsvcEnvironment): CveDossier {
    const live = this.cveService.getCachedCve(id);
    const kevEntry = this.cveService.getKevEntry(id);
    const epssScore = this.epss.getScore(id)?.epss ?? raw.epss ?? null;

    const base: CveDossier = {
      ...this.empty(id),
      ...raw,
      cveId: id,
      source: 'asset',
      epss: epssScore,
      isKev: kevEntry ? true : (raw.isKev ?? false),
      kevDateAdded: kevEntry?.dateAdded ?? raw.kevDateAdded,
      kevDueDate: kevEntry?.dueDate ?? raw.kevDueDate,
      kevRansomware: kevEntry
        ? kevEntry.knownRansomwareCampaignUse?.toLowerCase() === 'known'
        : raw.kevRansomware,
      warnings: [...(raw.warnings ?? [])],
    };

    // Resolve technique ids against the release actually loaded: an asset generated
    // against an older ATT&CK can carry ids that have since been retired.
    base.techniques = (raw.techniques ?? []).map(t => this.resolveTechnique(t));
    base.attackVersion = this.dataService.getCurrentDomain()?.attackVersion ?? raw.attackVersion;

    // Sigma and Atomic counts come from services the generator cannot see, so the
    // asset leaves them at zero. Fill them in rather than under-reporting coverage.
    base.detection = (raw.detection ?? []).map(det => ({
      ...det,
      sigmaRuleCount: det.sigmaRuleCount || this.sigma.getRuleCount(det.techniqueId),
      atomicTestCount: det.atomicTestCount || this.atomic.getTestCount(det.techniqueId),
    }));

    const cveForSsvc = live ?? this.synthesizeCve(base);
    base.ssvc = this.ssvc.available ? this.ssvc.evaluate(this.withLiveKev(cveForSsvc), env) : null;
    if (!this.ssvc.available) {
      base.warnings.push('SSVC decision tables are not loaded, so no prioritization outcome is shown.');
    }
    if (!live) {
      base.warnings.push(
        'This CVE is not in the NVD cache, so severity is taken from the generated ' +
          'dossier rather than a live record. Search it on the CVE tab to refresh.',
      );
    }
    return base;
  }

  // ── live path ────────────────────────────────────────────────────────────

  private compose(id: string, env: SsvcEnvironment): CveDossier {
    const d = this.empty(id);
    d.source = 'live';

    const cve = this.cveService.getCachedCve(id);
    if (!cve) {
      d.warnings.push(
        `No generated dossier exists for ${id} and it is not in the NVD cache. ` +
          'Search for it on the CVE tab first, then reopen this view.',
      );
      return d;
    }

    const enriched = this.withLiveKev(cve);
    d.description = enriched.description;
    d.published = enriched.published;
    d.cvssScore = enriched.cvssScore;
    d.cvssVector = enriched.cvssVector;
    d.severity = enriched.severity;
    d.epss = this.epss.getScore(id)?.epss ?? enriched.epssScore ?? null;
    d.epssPercentile = this.epss.getScore(id)?.percentile ?? enriched.epssPercentile ?? null;
    d.isKev = enriched.isKev;
    d.kevDateAdded = enriched.kevDateAdded;
    d.kevDueDate = enriched.kevDueDate;
    d.kevRansomware = enriched.kevKnownRansomware;
    d.kevVendorProject = enriched.kevVendorProject;
    d.kevProduct = enriched.kevProduct;

    d.ssvc = this.ssvc.available ? this.ssvc.evaluate(enriched, env) : null;

    // Techniques, tiered by strength of claim.
    const ctid = this.attackCve.getMappingForCve(id);
    const chain = this.cve2capec.getChainForCve(id);
    const tiers = new Map<string, DossierTier>();
    const rank = (t: DossierTier) =>
      ['exploitation', 'primary-impact', 'secondary-impact', 'weakness-class'].indexOf(t);
    const assign = (ids: string[] | undefined, tier: DossierTier) => {
      for (const tid of ids ?? []) {
        const cur = tiers.get(tid);
        if (!cur || rank(tier) < rank(cur)) tiers.set(tid, tier);
      }
    };
    assign(enriched.mappedAttackIds, 'weakness-class');
    assign(chain?.techniques, 'weakness-class');
    assign(ctid?.secondaryImpact, 'secondary-impact');
    assign(ctid?.primaryImpact, 'primary-impact');
    assign(ctid?.exploitationTechnique, 'exploitation');

    const comment = (ctid?.comments ?? [])[0] ?? '';
    d.techniques = [...tiers.entries()]
      .map(([tid, tier]) =>
        this.resolveTechnique({
          id: tid,
          name: '',
          tier,
          tactics: [],
          comment: tier === 'exploitation' ? comment : undefined,
        }),
      )
      .sort((a, b) => rank(a.tier) - rank(b.tier) || a.id.localeCompare(b.id));

    if (!ctid) {
      d.warnings.push(
        'CTID publishes no per-CVE ATT&CK mapping for this CVE, so every technique ' +
          'below is derived from its weakness classes and describes that class rather ' +
          'than this vulnerability.',
      );
    }

    const cwes = [...new Set([...enriched.cwes, ...(chain?.cwes ?? [])])];
    d.cwes = cwes.map(c => ({ id: c, name: '', url: this.cweUrl(c) }));

    const techniqueIds = d.techniques.map(t => t.id);
    d.capecs = this.collectCapecs(cwes, techniqueIds);
    d.countermeasures = this.collectCountermeasures(techniqueIds);
    d.engage = this.collectEngage(techniqueIds);
    d.controls = this.collectControls(techniqueIds);
    d.mitigations = this.collectMitigations(techniqueIds);
    d.detection = this.collectDetection(d.techniques);
    d.exploits = this.collectExploits(enriched);
    d.attackVersion = this.dataService.getCurrentDomain()?.attackVersion;

    d.warnings.push(
      'Composed live from the data loaded in the app. Published reporting, Exploit-DB ' +
        'rows and hunt queries come from a generated dossier; generate one for this CVE ' +
        'to include them.',
    );
    return d;
  }

  // ── collectors ───────────────────────────────────────────────────────────

  private collectCapecs(cweIds: string[], techniqueIds: string[]): DossierNamed[] {
    const seen = new Map<string, DossierNamed>();
    const add = (entries: { id: string; name: string; url: string; description?: string }[]) => {
      for (const c of entries) {
        if (!seen.has(c.id)) {
          seen.set(c.id, { id: c.id, name: c.name, url: c.url, detail: c.description });
        }
      }
    };
    for (const cwe of cweIds) add(this.capecService.getCapecForCwe(cwe));
    for (const tid of techniqueIds) add(this.capecService.getCapecForTechnique(tid));
    return [...seen.values()];
  }

  private collectCountermeasures(techniqueIds: string[]): DossierCountermeasure[] {
    const byId = new Map<string, DossierCountermeasure>();
    for (const tid of techniqueIds) {
      for (const cm of this.d3fend.getCountermeasures(tid)) {
        const existing = byId.get(cm.id);
        if (existing) {
          if (!existing.techniques.includes(tid)) existing.techniques.push(tid);
        } else {
          byId.set(cm.id, {
            id: cm.id,
            name: cm.name,
            tactic: cm.category,
            // Deliberately no `artifact`: D3fendTechnique.definition is prose, not the
            // digital artifact the countermeasure consumes. Only the D3FEND
            // offensive-to-defensive mapping carries that, and it reaches us through a
            // generated asset.
            definition: cm.definition,
            techniques: [tid],
          });
        }
      }
    }
    return [...byId.values()];
  }

  private collectEngage(techniqueIds: string[]): DossierNamed[] {
    const byId = new Map<string, DossierNamed>();
    for (const tid of techniqueIds) {
      for (const a of this.engage.getActivities(tid)) {
        if (!byId.has(a.id)) {
          byId.set(a.id, { id: a.id, name: a.name, url: a.url, detail: a.definition });
        }
      }
    }
    return [...byId.values()];
  }

  private collectControls(techniqueIds: string[]): DossierControl[] {
    const byId = new Map<string, DossierControl>();
    for (const tid of techniqueIds) {
      for (const c of this.nist.getControlsForTechnique(tid)) {
        const existing = byId.get(c.id);
        if (existing) {
          if (!existing.techniques.includes(tid)) existing.techniques.push(tid);
        } else {
          byId.set(c.id, {
            control: c.id,
            name: c.description,
            family: c.family,
            techniques: [tid],
          });
        }
      }
    }
    return [...byId.values()].sort((a, b) => a.control.localeCompare(b.control));
  }

  private collectMitigations(techniqueIds: string[]): DossierNamed[] {
    const domain = this.dataService.getCurrentDomain();
    if (!domain) return [];
    const byId = new Map<string, DossierNamed>();
    for (const tid of techniqueIds) {
      const technique = domain.techniques.find(t => t.attackId === tid);
      if (!technique) continue;
      for (const rel of domain.mitigationsByTechnique.get(technique.id) ?? []) {
        if (!byId.has(rel.mitigation.attackId)) {
          byId.set(rel.mitigation.attackId, {
            id: rel.mitigation.attackId,
            name: rel.mitigation.name,
            url: rel.mitigation.url,
            detail: rel.description || rel.mitigation.description,
          });
        }
      }
    }
    return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
  }

  private collectDetection(techniques: DossierTechnique[]): DossierDetection[] {
    const domain = this.dataService.getCurrentDomain();
    const out: DossierDetection[] = [];
    for (const t of techniques) {
      const technique = domain?.techniques.find(x => x.attackId === t.id);
      const notes = technique ? (domain?.detectionNotesByTechnique.get(technique.id) ?? []) : [];
      const sigmaCount = this.sigma.getRuleCount(t.id);
      const atomicCount = this.atomic.getTestCount(t.id);
      if (notes.length === 0 && sigmaCount === 0 && atomicCount === 0) continue;
      out.push({
        techniqueId: t.id,
        techniqueName: t.name || t.id,
        notes: notes.map(n => n.description).filter(Boolean),
        dataComponents: [...new Set(notes.map(n => n.dataComponentName).filter(Boolean))],
        sigmaRuleCount: sigmaCount,
        atomicTestCount: atomicCount,
        queries: [],
      });
    }
    return out;
  }

  private collectExploits(cve: NvdCveItem): DossierExploits {
    return {
      hasPoc: this.poc.hasPoc(cve.id),
      pocUrl: this.poc.getPocUrl(cve.id) || undefined,
      exploitDb: [],
      publicPocs: [],
      advisories: [],
      exploitTaggedRefs: (cve.references ?? [])
        .filter(r => (r.tags ?? []).some(t => t.toLowerCase() === 'exploit'))
        .map(r => r.url)
        .slice(0, 15),
    };
  }

  // ── helpers ──────────────────────────────────────────────────────────────

  /**
   * Resolve a mapped technique id against the loaded ATT&CK release, translating ids
   * that have since been retired. See Domain.supersededBy.
   */
  private resolveTechnique(t: DossierTechnique): DossierTechnique {
    const domain = this.dataService.getCurrentDomain();
    if (!domain) return { ...t, unresolved: !t.name };

    let technique = domain.techniques.find(x => x.attackId === t.id);
    let id = t.id;
    let supersedes = t.supersedes;

    if (!technique) {
      const replacement = domain.supersededBy.get(t.id);
      const replacementTech = replacement
        ? domain.techniques.find(x => x.attackId === replacement)
        : undefined;
      if (replacementTech) {
        technique = replacementTech;
        supersedes = t.id;
        id = replacement!;
      }
    }

    return {
      ...t,
      id,
      name: technique?.name ?? t.name ?? domain.retiredNames.get(t.id) ?? '',
      tactics: technique?.tacticShortnames?.map(x => x.replace(/-/g, ' ')) ?? t.tactics ?? [],
      supersedes,
      unresolved: !technique,
    };
  }

  /**
   * Read KEV membership from the catalogue rather than the cached record. A record
   * parsed before KEV finished loading keeps isKev false forever, which silently
   * downgrades the SSVC outcome.
   */
  private withLiveKev(cve: NvdCveItem): NvdCveItem {
    const entry = this.cveService.getKevEntry(cve.id);
    if (!entry) return cve.isKev ? { ...cve, isKev: false } : cve;
    return {
      ...cve,
      isKev: true,
      kevDateAdded: entry.dateAdded,
      kevDueDate: entry.dueDate,
      kevVendorProject: entry.vendorProject,
      kevProduct: entry.product,
      kevKnownRansomware: entry.knownRansomwareCampaignUse?.toLowerCase() === 'known',
    };
  }

  /** Enough of an NvdCveItem for SSVC, when only an asset is available. */
  private synthesizeCve(d: CveDossier): NvdCveItem {
    return {
      id: d.cveId,
      description: d.description,
      cvssScore: d.cvssScore,
      cvssVector: d.cvssVector,
      severity: (d.severity || 'UNKNOWN') as NvdCveItem['severity'],
      cwes: d.cwes.map(c => c.id),
      cpes: [],
      published: d.published ?? '',
      lastModified: '',
      references: d.exploits.exploitTaggedRefs.map(url => ({ url, tags: ['Exploit'] })),
      mappedAttackIds: d.techniques.map(t => t.id),
      isKev: d.isKev,
      kevDateAdded: d.kevDateAdded,
      kevDueDate: d.kevDueDate,
      kevKnownRansomware: d.kevRansomware,
      epssScore: d.epss,
      epssPercentile: d.epssPercentile,
    };
  }

  private cweUrl(cweId: string): string {
    const n = cweId.replace(/^CWE-/i, '');
    return `https://cwe.mitre.org/data/definitions/${n}.html`;
  }

  private empty(id: string): CveDossier {
    return {
      cveId: id,
      generated: new Date().toISOString(),
      source: 'live',
      description: '',
      cvssScore: null,
      cvssVector: null,
      severity: 'UNKNOWN',
      epss: null,
      epssPercentile: null,
      isKev: false,
      ssvc: null,
      cwes: [],
      capecs: [],
      techniques: [],
      mitigations: [],
      countermeasures: [],
      engage: [],
      controls: [],
      detection: [],
      exploits: {
        hasPoc: false,
        exploitDb: [],
        publicPocs: [],
        advisories: [],
        exploitTaggedRefs: [],
      },
      articles: [] as DossierArticle[],
      warnings: [],
    };
  }
}
