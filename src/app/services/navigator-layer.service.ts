import { Injectable } from '@angular/core';
import { AttackDomain, ATTACK_NAVIGATOR_DOMAIN_CONFIG } from './data.service';
import { Domain } from '../models/domain';
import { ImplStatus, ImplementationService } from './implementation.service';
import { BrowserFileService } from './browser-file.service';

interface NavigatorTechniqueEntry {
  techniqueID: string;
  tactic: string;
  color: string;
  comment: string;
  enabled: boolean;
  score: number;
  metadata: unknown[];
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
  buildLayer(domain: Domain, currentDomain: AttackDomain, statusMap: Map<string, ImplStatus>): NavigatorLayer {
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

      for (const rel of rels) {
        const status = statusMap.get(rel.mitigation.id);
        if (status && statusScore[status] > bestScore) {
          bestStatus = status;
          bestScore = statusScore[status];
        }
      }

      return {
        techniqueID: tech.attackId,
        tactic: tech.tacticShortnames[0] ?? '',
        color: bestStatus ? statusColor[bestStatus] : coverageColors[Math.min(mitigationCount, 4)],
        comment: bestStatus ? `Status: ${bestStatus}` : `${mitigationCount} mitigation(s)`,
        enabled: true,
        score: mitigationCount,
        metadata: [],
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

  downloadLayer(domain: Domain, currentDomain: AttackDomain, statusMap: Map<string, ImplStatus>, browserFileService: BrowserFileService): void {
    browserFileService.downloadJson(this.buildLayer(domain, currentDomain, statusMap), 'attack-navigator-layer.json');
  }

  async importLayer(json: string, domain: Domain, implService: ImplementationService): Promise<{ layerName: string; appliedCount: number }> {
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

    for (const tech of domain.techniques) {
      const entry = layerMap.get(tech.attackId);
      if (!entry) continue;
      const comment = entry.comment.toLowerCase();
      const rels = domain.mitigationsByTechnique.get(tech.id) ?? [];
      for (const rel of rels) {
        if (comment.includes('implemented')) {
          implService.setStatus(rel.mitigation.id, 'implemented');
        } else if (comment.includes('progress')) {
          implService.setStatus(rel.mitigation.id, 'in-progress');
        } else if (comment.includes('planned')) {
          implService.setStatus(rel.mitigation.id, 'planned');
        }
      }
    }

    const layer = parsed as { name?: unknown };
    return {
      layerName: typeof layer.name === 'string' ? layer.name : 'unnamed',
      appliedCount: layerMap.size,
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
        metadata: Array.isArray(entry.metadata) ? entry.metadata : [],
      }));
  }
}
