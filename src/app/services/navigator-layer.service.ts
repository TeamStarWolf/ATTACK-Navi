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

export interface LayerImportResult {
  layerName: string;
  appliedCount: number;
  statusesApplied: number;
  notesApplied: number;
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
      name: `${domain.name} Mitigation Coverage`,
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
   * - Foreign layers fall back to comment-keyword status detection, and their
   *   comments become analyst notes — but only on techniques that don't
   *   already have a note (imports never clobber existing analyst work).
   */
  async importLayer(
    json: string,
    domain: Domain,
    implService: ImplementationService,
    annotationService?: AnnotationService,
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

    // Mitigation ATT&CK id → STIX id, for exact status restore.
    const mitByAttackId = new Map((domain.mitigations ?? []).map(m => [m.attackId, m.id]));

    let statusesApplied = 0;
    let notesApplied = 0;
    const validStatuses = new Set<ImplStatus>(['implemented', 'in-progress', 'planned', 'not-started']);

    for (const tech of domain.techniques) {
      const entry = layerMap.get(tech.attackId);
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
            implService.setStatus(mitId, status);
            statusesApplied++;
          }
        }
      } else {
        // 2) Foreign layers: keyword fallback on the comment.
        const comment = entry.comment.toLowerCase();
        const rels = domain.mitigationsByTechnique.get(tech.id) ?? [];
        for (const rel of rels) {
          if (comment.includes('implemented')) {
            implService.setStatus(rel.mitigation.id, 'implemented');
            statusesApplied++;
          } else if (comment.includes('progress')) {
            implService.setStatus(rel.mitigation.id, 'in-progress');
            statusesApplied++;
          } else if (comment.includes('planned')) {
            implService.setStatus(rel.mitigation.id, 'planned');
            statusesApplied++;
          }
        }
      }

      // 3) Notes: exact from our metadata; otherwise a foreign comment becomes
      //    a note only where no analyst note exists yet.
      if (annotationService) {
        const exactNote = meta.get('attack-navi:note');
        const existing = annotationService.getAnnotation(tech.attackId)?.note ?? '';
        if (exactNote && exactNote !== existing) {
          annotationService.setAnnotation(tech.attackId, exactNote);
          notesApplied++;
        } else if (!exactNote && entry.comment.trim() && !existing) {
          annotationService.setAnnotation(tech.attackId, entry.comment.trim());
          notesApplied++;
        }
      }
    }

    const layer = parsed as { name?: unknown };
    return {
      layerName: typeof layer.name === 'string' ? layer.name : 'unnamed',
      appliedCount: layerMap.size,
      statusesApplied,
      notesApplied,
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
