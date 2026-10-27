// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { SourceRegistryService } from './source-registry.service';

export interface D3fendTechnique {
  id: string;          // e.g., "D3-PSA"
  name: string;        // e.g., "Process Spawn Analysis"
  definition: string;  // brief description
  url: string;
  category: 'Harden' | 'Detect' | 'Isolate' | 'Deceive' | 'Evict';
  attackIds: string[]; // ATT&CK technique IDs this counters
}

// ─────────────────────────────────────────────────────────────────────────────
// PROVENANCE: curated editorial seed (15 countermeasures), NOT an official
// export. It serves only as an offline fallback: the live D3FEND ontology API
// (loadOntologyIndex / per-technique fetch below) replaces these entries the
// moment it responds, and live data always takes precedence. Each id, label
// and URL fragment matches a technique in the D3FEND ontology (the seed
// currency spec in d3fend.service.spec.ts checks every entry against the
// checked-in all.json snapshot); the ATT&CK mappings remain editorial.
// ATT&CK ids are v19.2 (attack-id-currency.spec.ts fails when a refresh retires one).
// ─────────────────────────────────────────────────────────────────────────────
export const D3FEND_MAPPING: D3fendTechnique[] = [
  { id: 'D3-PSA', name: 'Process Spawn Analysis', category: 'Detect', definition: 'Analyzing process spawn events to detect anomalous parent-child relationships.', url: 'https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis', attackIds: ['T1059', 'T1055', 'T1078', 'T1053'] },
  { id: 'D3-NTF', name: 'Network Traffic Filtering', category: 'Isolate', definition: 'Restricting network traffic based on policies and rules.', url: 'https://d3fend.mitre.org/technique/d3f:NetworkTrafficFiltering', attackIds: ['T1021', 'T1071', 'T1041', 'T1095', 'T1572'] },
  { id: 'D3-DNSAL', name: 'DNS Allowlisting', category: 'Harden', definition: 'Permitting only known-good DNS resolutions.', url: 'https://d3fend.mitre.org/technique/d3f:DNSAllowlisting', attackIds: ['T1568', 'T1071.004', 'T1583'] },
  { id: 'D3-NI', name: 'Network Isolation', category: 'Isolate', definition: 'Preventing or limiting lateral movement via network segmentation.', url: 'https://d3fend.mitre.org/technique/d3f:NetworkIsolation', attackIds: ['T1021', 'T1570', 'T1534'] },
  { id: 'D3-UDTA', name: 'User Data Transfer Analysis', category: 'Detect', definition: 'Monitoring and analyzing data transfers performed by users.', url: 'https://d3fend.mitre.org/technique/d3f:UserDataTransferAnalysis', attackIds: ['T1041', 'T1030', 'T1048', 'T1567'] },
  { id: 'D3-PA', name: 'Process Analysis', category: 'Detect', definition: 'Monitoring and analyzing process behavior during execution.', url: 'https://d3fend.mitre.org/technique/d3f:ProcessAnalysis', attackIds: ['T1055', 'T1059', 'T1203', 'T1106'] },
  { id: 'D3-UAP', name: 'User Account Permissions', category: 'Harden', definition: 'Managing and restricting user account privileges.', url: 'https://d3fend.mitre.org/technique/d3f:UserAccountPermissions', attackIds: ['T1078', 'T1548', 'T1134'] },
  { id: 'D3-EAL', name: 'Executable Allowlisting', category: 'Harden', definition: 'Restricting execution to known-good executables and scripts.', url: 'https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting', attackIds: ['T1059', 'T1203', 'T1218', 'T1574'] },
  { id: 'D3-FA', name: 'File Analysis', category: 'Detect', definition: 'Monitoring and analyzing file system operations.', url: 'https://d3fend.mitre.org/technique/d3f:FileAnalysis', attackIds: ['T1005', 'T1083', 'T1560', 'T1070.004'] },
  { id: 'D3-MFA', name: 'Multi-factor Authentication', category: 'Harden', definition: 'Requiring multiple authentication factors to verify identity.', url: 'https://d3fend.mitre.org/technique/d3f:Multi-factorAuthentication', attackIds: ['T1078', 'T1556', 'T1110', 'T1621'] },
  { id: 'D3-ISVA', name: 'Inbound Session Volume Analysis', category: 'Detect', definition: 'Monitoring and limiting inbound session volumes.', url: 'https://d3fend.mitre.org/technique/d3f:InboundSessionVolumeAnalysis', attackIds: ['T1190', 'T1499'] },
  { id: 'D3-FE', name: 'File Encryption', category: 'Harden', definition: 'Encrypting sensitive files and data stores to protect against unauthorized access.', url: 'https://d3fend.mitre.org/technique/d3f:FileEncryption', attackIds: ['T1005', 'T1039', 'T1025', 'T1530'] },
  { id: 'D3-FH', name: 'File Hashing', category: 'Detect', definition: 'Computing and verifying cryptographic hashes of files.', url: 'https://d3fend.mitre.org/technique/d3f:FileHashing', attackIds: ['T1036', 'T1027', 'T1195'] },
  { id: 'D3-NTA', name: 'Network Traffic Analysis', category: 'Detect', definition: 'Inspecting and analyzing network traffic for anomalies and malicious patterns.', url: 'https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis', attackIds: ['T1040', 'T1095', 'T1071', 'T1557'] },
  { id: 'D3-PT', name: 'Process Termination', category: 'Evict', definition: 'Terminating malicious or unauthorized processes.', url: 'https://d3fend.mitre.org/technique/d3f:ProcessTermination', attackIds: ['T1055', 'T1059', 'T1203'] },
];

// D3FEND 1.4.0+ per-technique mapping endpoint. Returns SPARQL-style bindings
// with authoritative def_tactic_label (Harden/Detect/Isolate/Deceive/Evict).
const D3FEND_TECHNIQUE_API = 'https://d3fend.mitre.org/api/offensive-technique/attack/';

/**
 * The d3fend.mitre.org API URL for one ATT&CK technique. D3FEND keys
 * sub-techniques by their dotted ATT&CK id (T1059.001.json); the slash form
 * (T1059/001.json) is a 404, checked against d3fend.mitre.org on 2026-10-17
 * (plan E1.5).
 */
export function d3fendTechniqueApiUrl(attackId: string): string {
  return `${D3FEND_TECHNIQUE_API}${encodeURIComponent(attackId)}.json`;
}

// JSON-LD list of every defensive technique currently in the ontology.
// Used at startup to prune any seed entry whose ID or label is no longer
// current in the ontology.
const D3FEND_ALL_TECHNIQUES_API = 'https://d3fend.mitre.org/api/technique/all.json';

interface D3fendOntologyNode {
  '@id'?: string;
  'd3f:d3fend-id'?: string;
  'rdfs:label'?: string;
}
interface D3fendOntologyResponse {
  '@graph'?: D3fendOntologyNode[];
}

interface D3fendSparqlLiteral { value: string }
interface D3fendSparqlBinding {
  def_tactic_label?: D3fendSparqlLiteral;
  def_tech_label?: D3fendSparqlLiteral;
  def_tech_id?: D3fendSparqlLiteral;
  def_tech?: D3fendSparqlLiteral;
}
interface D3fendAttackResponse {
  off_to_def?: { results?: { bindings?: D3fendSparqlBinding[] } };
}

const VALID_CATEGORIES: ReadonlySet<D3fendTechnique['category']> =
  new Set(['Harden', 'Detect', 'Isolate', 'Deceive', 'Evict']);

@Injectable({ providedIn: 'root' })
export class D3fendService {
  private byAttackId = new Map<string, D3fendTechnique[]>();
  private liveIndex = new Map<string, D3fendTechnique>();

  /** Live data keyed by ATT&CK ID (populated lazily per technique) */
  private liveMap = new Map<string, D3fendTechnique[]>();

  /** Track in-flight and completed fetches to dedupe requests. */
  private fetchStatus = new Map<string, 'pending' | 'done'>();

  /** Techniques whose per-technique API request failed this session (the Retry fetches them again). */
  private failedTechniques = new Set<string>();

  /** Current D3FEND ontology ID -> label. Empty until startup fetch resolves. */
  private currentOntology = new Map<string, string>();

  /** Emits on bundled-ready and after each successful live fetch merges. */
  loaded$ = new BehaviorSubject<boolean>(true);

  constructor(
    private http: HttpClient,
    private sources: SourceRegistryService = new SourceRegistryService(),
  ) {
    // Build the offline index from the seed. Every seed entry is current in the
    // D3FEND ontology (seed currency spec in d3fend.service.spec.ts), so it
    // renders before the live ontology fetch resolves or when offline.
    for (const d of D3FEND_MAPPING) {
      this.liveIndex.set(d.id, d);
      for (const attackId of d.attackIds) {
        if (!this.byAttackId.has(attackId)) this.byAttackId.set(attackId, []);
        this.byAttackId.get(attackId)!.push(d);
      }
    }
    this.loadOntologyIndex();
  }

  /** Fetch the ontology index again after it failed or came back empty: the data-health Retry (E1.3). */
  retryOntologyIndex(): void {
    this.loadOntologyIndex();
  }

  /**
   * Fetch the current D3FEND defensive technique index and reconcile the seed
   * against it. Drops any seed entry whose ID was removed from the ontology or
   * now carries a different label.
   * No-op on network failure — bundled data stays as offline fallback.
   */
  private loadOntologyIndex(): void {
    this.sources.begin('d3fend-ontology');
    this.http.get<D3fendOntologyResponse>(D3FEND_ALL_TECHNIQUES_API)
      .subscribe({
        next: response => {
          const graph = response?.['@graph'] ?? [];
          for (const node of graph) {
            const id = node['d3f:d3fend-id'];
            const label = node['rdfs:label'];
            if (id && label && id.startsWith('D3-')) this.currentOntology.set(id, label);
          }
          this.sources.succeed('d3fend-ontology', this.currentOntology.size);
          if (!this.currentOntology.size) return;

          this.reconcileBundledData();
          this.loaded$.next(true);
        },
        // The seed stays as the offline fallback; the index is recorded as failed.
        error: err => this.sources.fail('d3fend-ontology', err),
      });
  }

  /** Drop bundled entries whose ID or name no longer matches current D3FEND. */
  private reconcileBundledData(): void {
    const norm = (s: string) => s.toLowerCase().replace(/[\s\-/]/g, '');
    // We drop both fully-removed IDs *and* IDs reassigned to a different
    // technique — the bundled ATT&CK mappings were written for the old name
    // and no longer apply. Live per-technique fetches fill in the current
    // mappings from d3fend.mitre.org.
    const keep = (d: D3fendTechnique): boolean => {
      const current = this.currentOntology.get(d.id);
      return !!current && norm(current) === norm(d.name);
    };

    const survivors = D3FEND_MAPPING.filter(keep);
    this.liveIndex.clear();
    this.byAttackId.clear();
    for (const d of survivors) {
      this.liveIndex.set(d.id, d);
      for (const attackId of d.attackIds) {
        if (!this.byAttackId.has(attackId)) this.byAttackId.set(attackId, []);
        this.byAttackId.get(attackId)!.push(d);
      }
    }
  }

  /**
   * Fetch live D3FEND countermeasures for a single ATT&CK technique from
   * d3fend.mitre.org (v1.4.0 ontology). Deduplicates in-flight and completed
   * requests. On success, merges results into `liveMap` and emits `loaded$`
   * so subscribers (matrix, panels) re-render.
   */
  private fetchLiveForAttackId(attackId: string): void {
    if (this.fetchStatus.has(attackId)) return;
    this.fetchStatus.set(attackId, 'pending');

    this.sources.begin('d3fend-technique-api');
    this.http.get<D3fendAttackResponse>(d3fendTechniqueApiUrl(attackId))
      .subscribe({ next: response => {
        this.fetchStatus.set(attackId, 'done');
        const bindings = response?.off_to_def?.results?.bindings ?? [];

        const collected: D3fendTechnique[] = [];
        const seen = new Set<string>();
        for (const b of bindings) {
          const defId = b.def_tech_id?.value ?? '';
          const defLabel = b.def_tech_label?.value ?? '';
          const tactic = b.def_tactic_label?.value ?? '';
          if (!defId || !defLabel) continue;
          if (seen.has(defId)) continue;
          seen.add(defId);

          const category = VALID_CATEGORIES.has(tactic as D3fendTechnique['category'])
            ? (tactic as D3fendTechnique['category'])
            : 'Detect';

          // Prefer ontology URI fragment for URL when available.
          const uri = b.def_tech?.value ?? '';
          const fragment = uri.split('#')[1] ?? defLabel.replace(/\s+/g, '');

          collected.push({
            id: defId,
            name: defLabel,
            definition: `D3FEND ${category.toLowerCase()} countermeasure that counters ${attackId}.`,
            url: `https://d3fend.mitre.org/technique/d3f:${fragment}`,
            category,
            attackIds: [attackId],
          });
          if (!this.liveIndex.has(defId)) this.liveIndex.set(defId, collected[collected.length - 1]);
        }

        if (collected.length) this.liveMap.set(attackId, collected);
        // Recorded once the answer is merged: a view that re-reads on the source's
        // record (the evidence card's D3FEND row) then reads the live count, never
        // the seed's count beside a 'loaded' state.
        this.sources.succeed('d3fend-technique-api', null);
        if (collected.length) this.loaded$.next(true);
      }, error: err => {
        // Recorded as failed (not as "no countermeasures"); not retried automatically this
        // session, only by the data-health Retry.
        this.fetchStatus.set(attackId, 'done');
        this.failedTechniques.add(attackId);
        this.sources.fail('d3fend-technique-api', err);
      } });
  }

  /**
   * Where a technique's live D3FEND answer stands (technique page design 4.4):
   * 'loading' while its request, or its parent's for a sub-technique, is in flight;
   * 'failed' when one of them failed this session (retryTechniqueApi asks again);
   * 'loaded' once answered; null when nothing has asked for it. Until the answer,
   * getCountermeasures reads the bundled seed, so a view shows this state instead
   * of the seed's count (T1037: 0 in the seed, 20 live).
   */
  liveState(attackId: string): 'loading' | 'loaded' | 'failed' | null {
    const ids = attackId.includes('.') ? [attackId, attackId.split('.')[0]] : [attackId];
    const asked = ids.filter(id => this.fetchStatus.has(id));
    if (!asked.length) return null;
    if (asked.some(id => this.fetchStatus.get(id) === 'pending')) return 'loading';
    if (asked.some(id => this.failedTechniques.has(id))) return 'failed';
    return 'loaded';
  }

  /**
   * The data-health Retry (E1.3): fetch again every technique whose per-technique
   * request failed this session, or `probe` when none has been requested yet.
   */
  retryTechniqueApi(probe: string): void {
    const ids = this.failedTechniques.size ? [...this.failedTechniques] : [probe];
    for (const id of ids) {
      this.failedTechniques.delete(id);
      this.fetchStatus.delete(id);
      this.fetchLiveForAttackId(id);
    }
  }

  /**
   * @param attackId e.g. "T1059" or "T1059.001"
   * @param fetchLive when true, kick off a live D3FEND API fetch (deduped).
   *   Pass false from hot paths like matrix rendering where hundreds of
   *   techniques are queried just for counts — otherwise we'd fire 200+
   *   requests at startup. Panel/detail views that actually display
   *   countermeasures should pass true.
   */
  getCountermeasures(attackId: string, fetchLive = false): D3fendTechnique[] {
    if (fetchLive) {
      this.fetchLiveForAttackId(attackId);
      if (attackId.includes('.')) this.fetchLiveForAttackId(attackId.split('.')[0]);
    }

    // Authoritative-first: when the official d3fend.mitre.org API has
    // responded for this technique, its mappings ARE the answer. The bundled
    // static seed is an offline fallback only — it must never override or
    // pad live data (it previously took precedence, so a stale/incorrect
    // seed entry could not be corrected by the real ontology).
    const parentId = attackId.includes('.') ? attackId.split('.')[0] : null;
    const prefix = attackId + '.';

    const collect = (map: Map<string, D3fendTechnique[]>): D3fendTechnique[] => [
      ...(map.get(attackId) ?? []),
      ...(parentId ? (map.get(parentId) ?? []) : []),
      ...(!attackId.includes('.')
        ? [...map.entries()]
            .filter(([id]) => id.startsWith(prefix))
            .flatMap(([, values]) => values)
        : []),
    ];

    const live = collect(this.liveMap);
    if (live.length) {
      const seen = new Set<string>();
      return live.filter(d => (seen.has(d.id) ? false : (seen.add(d.id), true)));
    }
    const fallback = collect(this.byAttackId);
    const seen = new Set<string>();
    return fallback.filter(d => (seen.has(d.id) ? false : (seen.add(d.id), true)));
  }

  getAllTechniques(): D3fendTechnique[] {
    return [...this.liveIndex.values()];
  }

  getAllByCategory(): Map<string, D3fendTechnique[]> {
    const map = new Map<string, D3fendTechnique[]>();
    for (const d of this.liveIndex.values()) {
      if (!map.has(d.category)) map.set(d.category, []);
      map.get(d.category)!.push(d);
    }
    return map;
  }
}
