// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { AttackDomain, ATTACK_NAVIGATOR_DOMAIN_CONFIG } from './data.service';
import { Domain } from '../models/domain';
import { ImplStatus, ImplementationService } from './implementation.service';
import { AnnotationService, TechniqueAnnotation } from './annotation.service';
import { BrowserFileService } from './browser-file.service';

/** Navigator metadata entry ({name, value} pairs shown in its tooltip). */
interface NavigatorMetadata {
  name: string;
  value: string;
}

interface NavigatorTechniqueEntry {
  techniqueID: string;
  tactic: string;
  color: string;
  comment: string;
  enabled: boolean;
  score: number;
  metadata: NavigatorMetadata[];
}

/** One mitigation status that comment-keyword detection derived for a foreign layer. */
export interface DerivedStatus {
  /** ATT&CK id of the technique whose comment drove the detection. */
  techniqueId: string;
  /** Mitigation STIX id (ImplementationService key). */
  mitigationId: string;
  mitigationAttackId: string;
  status: ImplStatus;
  /** The comment the status was read from (for the preview). */
  comment: string;
}

export interface LayerImportOptions {
  /**
   * Foreign layers (no `attack-navi:*` metadata) can only GUESS statuses from
   * free-text comments, and a guess sets EVERY mitigation of that technique.
   * Off by default — comments become notes only. Callers should preview with
   * `dryRun` and ask before turning this on.
   */
  deriveStatusesFromComments?: boolean;
  /** Compute the result without writing any status or note. */
  dryRun?: boolean;
}

export interface LayerImportResult {
  layerName: string;
  /** Distinct technique ids in the layer (Navigator repeats a technique once per tactic). */
  techniqueIdCount: number;
  /**
   * Distinct ids that resolved to a live technique in the loaded domain,
   * directly or through a retired-id replacement.
   */
  resolvedCount: number;
  /** Retired ids resolved through `Domain.supersededBy`, e.g. T1070.001 -> T1685.005. */
  remapped: Array<{ from: string; to: string }>;
  /** Ids that match nothing in the loaded domain (other domain, typo, or retired with no replacement). */
  unresolvedIds: string[];
  statusesApplied: number;
  notesApplied: number;
  /**
   * Statuses keyword detection derived from foreign-layer comments. Populated
   * whenever a match exists, even when not applied (opted out or dryRun), so
   * the caller can show a preview.
   */
  derivedStatuses: DerivedStatus[];
}

/**
 * A status keyword preceded by a negation ("not implemented", "never planned",
 * "isn't in progress", "not yet implemented") is NOT that status. Word
 * boundaries already exclude "unimplemented" / "unplanned".
 */
const NOT_NEGATED = String.raw`(?<!\b(?:not|never|no|isn'?t|wasn'?t|cannot|can'?t|won'?t|partially|partly)\s+)(?<!\bnot\s+yet\s+)`;
const STATUS_PATTERNS: Array<{ status: ImplStatus; re: RegExp }> = [
  { status: 'implemented', re: new RegExp(NOT_NEGATED + String.raw`\bimplemented\b`, 'i') },
  { status: 'in-progress', re: new RegExp(NOT_NEGATED + String.raw`\bin[\s-]+progress\b`, 'i') },
  { status: 'planned', re: new RegExp(NOT_NEGATED + String.raw`\bplanned\b`, 'i') },
];

/**
 * Reads an implementation status out of a free-text Navigator comment, or null
 * when no anchored, non-negated status keyword is present.
 */
export function detectStatusKeyword(comment: string): ImplStatus | null {
  for (const { status, re } of STATUS_PATTERNS) {
    if (re.test(comment)) return status;
  }
  return null;
}

interface NavigatorLayer {
  name: string;
  versions: { attack: string; navigator: string; layer: string };
  domain: string;
  description: string;
  filters: { platforms: string[] };
  sorting: number;
  layout: {
    layout: string;
    aggregateFunction: string;
    showID: boolean;
    showName: boolean;
    showAggregateScores: boolean;
    countUnscored: boolean;
  };
  hideDisabled: boolean;
  techniques: NavigatorTechniqueEntry[];
  gradient: { colors: string[]; minValue: number; maxValue: number };
  legendItems: Array<{ label: string; color: string }>;
}

@Injectable({ providedIn: 'root' })
export class NavigatorLayerService {
  buildLayer(
    domain: Domain,
    currentDomain: AttackDomain,
    statusMap: Map<string, ImplStatus>,
    annotations?: Map<string, TechniqueAnnotation>,
  ): NavigatorLayer {
    const metadata = ATTACK_NAVIGATOR_DOMAIN_CONFIG[currentDomain];
    const statusScore: Record<ImplStatus, number> = {
      implemented: 4,
      'in-progress': 3,
      planned: 2,
      'not-started': 1,
    };
    const statusColor: Record<ImplStatus, string> = {
      implemented: '#00c853',
      'in-progress': '#1565c0',
      planned: '#ffa726',
      'not-started': '#d32f2f',
    };
    const coverageColors = ['#d32f2f', '#ff9800', '#ffd54f', '#aed581', '#4caf50'];

    const techniques = domain.techniques.map((tech) => {
      const rels = domain.mitigationsByTechnique.get(tech.id) ?? [];
      const mitigationCount = rels.length;
      let bestStatus: ImplStatus | null = null;
      let bestScore = 0;

      // Exact per-mitigation statuses ride along in metadata so ATTACK-Navi
      // layers round-trip losslessly (the technique-level rollup is lossy).
      const mitStatusPairs: string[] = [];
      for (const rel of rels) {
        const status = statusMap.get(rel.mitigation.id);
        if (status) {
          mitStatusPairs.push(`${rel.mitigation.attackId}=${status}`);
          if (statusScore[status] > bestScore) {
            bestStatus = status;
            bestScore = statusScore[status];
          }
        }
      }

      const note = annotations?.get(tech.attackId)?.note ?? '';
      const baseComment = bestStatus ? `Status: ${bestStatus}` : `${mitigationCount} mitigation(s)`;
      const entryMetadata: NavigatorMetadata[] = [];
      if (mitStatusPairs.length) entryMetadata.push({ name: 'attack-navi:mitStatuses', value: mitStatusPairs.join(';') });
      if (note) entryMetadata.push({ name: 'attack-navi:note', value: note });

      return {
        techniqueID: tech.attackId,
        tactic: tech.tacticShortnames[0] ?? '',
        color: bestStatus ? statusColor[bestStatus] : coverageColors[Math.min(mitigationCount, 4)],
        // Analyst notes travel in the comment (visible in Navigator's UI).
        comment: note ? `${baseComment}\n\n${note}` : baseComment,
        enabled: true,
        score: mitigationCount,
        metadata: entryMetadata,
      };
    });

    return {
      name: `${domain.name} Coverage`,
      versions: { attack: domain.attackVersion || '', navigator: '4.9', layer: '4.5' },
      domain: metadata.navigatorDomain,
      description: `Exported from ATT&CK Navi (${domain.name})`,
      filters: { platforms: metadata.defaultPlatforms },
      sorting: 0,
      layout: { layout: 'side', aggregateFunction: 'average', showID: false, showName: true, showAggregateScores: false, countUnscored: false },
      hideDisabled: false,
      techniques,
      gradient: {
        colors: ['#d32f2f', '#4caf50'],
        minValue: 0,
        maxValue: 4,
      },
      legendItems: [
        { label: 'Implemented', color: '#00c853' },
        { label: 'In Progress', color: '#1565c0' },
        { label: 'Planned', color: '#ffa726' },
        { label: 'Not Started', color: '#d32f2f' },
        { label: '0 mitigations', color: '#d32f2f' },
        { label: '4+ mitigations', color: '#4caf50' },
      ],
    };
  }

  downloadLayer(
    domain: Domain,
    currentDomain: AttackDomain,
    statusMap: Map<string, ImplStatus>,
    browserFileService: BrowserFileService,
    annotations?: Map<string, TechniqueAnnotation>,
  ): void {
    browserFileService.downloadJson(this.buildLayer(domain, currentDomain, statusMap, annotations), 'attack-navigator-layer.json');
  }

  /**
   * Imports a Navigator layer with round-trip fidelity:
   * - ATTACK-Navi layers restore EXACT per-mitigation statuses and analyst
   *   notes from `attack-navi:*` metadata entries.
   * - Foreign layers' comments become analyst notes — but only on techniques
   *   that don't already have a note (imports never clobber existing analyst
   *   work). Deriving mitigation statuses from those comments is a guess, so
   *   it is reported in `derivedStatuses` and only written when the caller
   *   opts in with `deriveStatusesFromComments` (disabled entries never count).
   * - Technique ids are matched against the loaded domain, following retired
   *   ids through `Domain.supersededBy`; what did and did not resolve is
   *   reported so the caller never claims more than was applied.
   */
  async importLayer(
    json: string,
    domain: Domain,
    implService: ImplementationService,
    annotationService?: AnnotationService,
    options: LayerImportOptions = {},
  ): Promise<LayerImportResult> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      throw new Error('Failed to parse Navigator layer JSON.');
    }

    const techniques = this.getTechniqueEntries(parsed);
    if (!techniques) {
      throw new Error('Invalid Navigator layer: missing techniques array.');
    }

    const layerMap = new Map<string, NavigatorTechniqueEntry>();
    for (const entry of techniques) {
      if (entry.techniqueID) {
        layerMap.set(entry.techniqueID, entry);
      }
    }

    // One of our own exports carries exact data in `attack-navi:*` metadata;
    // its comments ("Status: planned", "3 mitigation(s)") are display text,
    // not analyst notes, and must not be guessed at or imported as notes.
    const layerHeader = parsed as { description?: unknown };
    const ownLayer = (typeof layerHeader.description === 'string' && layerHeader.description.startsWith('Exported from ATT&CK Navi'))
      || techniques.some(e => e.metadata.some(m => m.name.startsWith('attack-navi:')));

    // Mitigation ATT&CK id → STIX id, for exact status restore.
    const mitByAttackId = new Map((domain.mitigations ?? []).map(m => [m.attackId, m.id]));

    // Live id → the retired ids it replaced (reverse of Domain.supersededBy),
    // so a layer written against an older ATT&CK release still lands.
    const retiredByLive = new Map<string, string[]>();
    for (const [retired, live] of domain.supersededBy ?? new Map<string, string>()) {
      const list = retiredByLive.get(live) ?? [];
      list.push(retired);
      retiredByLive.set(live, list);
    }

    const write = !options.dryRun;
    const deriveStatuses = options.deriveStatusesFromComments === true;
    let statusesApplied = 0;
    let notesApplied = 0;
    const derivedStatuses: DerivedStatus[] = [];
    const resolvedIds = new Set<string>();
    const remapped: Array<{ from: string; to: string }> = [];
    const validStatuses = new Set<ImplStatus>(['implemented', 'in-progress', 'planned', 'not-started']);

    for (const tech of domain.techniques) {
      let entry = layerMap.get(tech.attackId);
      if (entry) {
        resolvedIds.add(tech.attackId);
      } else {
        for (const retired of retiredByLive.get(tech.attackId) ?? []) {
          const candidate = layerMap.get(retired);
          if (candidate) {
            entry = candidate;
            resolvedIds.add(retired);
            remapped.push({ from: retired, to: tech.attackId });
            break;
          }
        }
      }
      if (!entry) continue;

      const meta = new Map(entry.metadata.map(m => [m.name, m.value]));

      // 1) Exact restore (our own layers): per-mitigation statuses.
      const mitStatuses = meta.get('attack-navi:mitStatuses');
      if (mitStatuses) {
        for (const pair of mitStatuses.split(';')) {
          const eq = pair.indexOf('=');
          if (eq < 0) continue;
          const mitId = mitByAttackId.get(pair.slice(0, eq));
          const status = pair.slice(eq + 1) as ImplStatus;
          if (mitId && validStatuses.has(status)) {
            if (write) implService.setStatus(mitId, status);
            statusesApplied++;
          }
        }
      } else if (!ownLayer && entry.enabled) {
        // 2) Foreign layers: an anchored, non-negated status keyword in the
        //    comment. A disabled row is hidden in Navigator, so it says
        //    nothing about the analyst's controls.
        const status = detectStatusKeyword(entry.comment);
        if (status) {
          for (const rel of domain.mitigationsByTechnique.get(tech.id) ?? []) {
            derivedStatuses.push({
              techniqueId: tech.attackId,
              mitigationId: rel.mitigation.id,
              mitigationAttackId: rel.mitigation.attackId,
              status,
              comment: entry.comment.trim(),
            });
            if (deriveStatuses) {
              if (write) implService.setStatus(rel.mitigation.id, status);
              statusesApplied++;
            }
          }
        }
      }

      // 3) Notes: exact from our metadata; otherwise a foreign comment becomes
      //    a note only where no analyst note exists yet.
      if (annotationService) {
        const exactNote = meta.get('attack-navi:note');
        const existing = annotationService.getAnnotation(tech.attackId)?.note ?? '';
        if (exactNote && exactNote !== existing) {
          if (write) annotationService.setAnnotation(tech.attackId, exactNote);
          notesApplied++;
        } else if (!ownLayer && !exactNote && entry.comment.trim() && !existing) {
          if (write) annotationService.setAnnotation(tech.attackId, entry.comment.trim());
          notesApplied++;
        }
      }
    }

    // A retired id whose replacement also appears directly in the layer was
    // superseded by that direct entry; it still resolves, nothing is lost.
    const liveIds = new Set(domain.techniques.map(t => t.attackId));
    const unresolvedIds = [...layerMap.keys()].filter((id) => {
      if (resolvedIds.has(id)) return false;
      const replacement = domain.supersededBy?.get(id);
      return !(replacement && liveIds.has(replacement));
    });

    const layer = parsed as { name?: unknown };
    return {
      layerName: typeof layer.name === 'string' ? layer.name : 'unnamed',
      techniqueIdCount: layerMap.size,
      resolvedCount: layerMap.size - unresolvedIds.length,
      remapped,
      unresolvedIds,
      statusesApplied,
      notesApplied,
      derivedStatuses,
    };
  }

  private getTechniqueEntries(value: unknown): NavigatorTechniqueEntry[] | null {
    if (!value || typeof value !== 'object') return null;
    const layer = value as { techniques?: unknown };
    if (!Array.isArray(layer.techniques)) return null;
    return layer.techniques
      .filter((entry): entry is Partial<NavigatorTechniqueEntry> => !!entry && typeof entry === 'object')
      .map((entry) => ({
        techniqueID: typeof entry.techniqueID === 'string' ? entry.techniqueID : '',
        tactic: typeof entry.tactic === 'string' ? entry.tactic : '',
        color: typeof entry.color === 'string' ? entry.color : '',
        comment: typeof entry.comment === 'string' ? entry.comment : '',
        enabled: typeof entry.enabled === 'boolean' ? entry.enabled : true,
        score: typeof entry.score === 'number' ? entry.score : 0,
        metadata: Array.isArray(entry.metadata)
          ? entry.metadata
              .filter((m): m is NavigatorMetadata =>
                !!m && typeof (m as any).name === 'string' && typeof (m as any).value === 'string')
          : [],
      }));
  }
}
