import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { CustomTechniqueService, CustomTechnique } from './custom-technique.service';
import { CustomGroupService, CustomGroup } from './custom-group.service';
import { CustomMitigationService, CustomMitigation } from './custom-mitigation.service';
import { AnnotationService, TechniqueAnnotation } from './annotation.service';

export interface ImportSummary {
  techniques: number;
  groups: number;
  mitigations: number;
  notes: number;
  skipped: number;
}

@Injectable({ providedIn: 'root' })
export class StixCollectionService {

  constructor(
    private http: HttpClient,
    private techniqueSvc: CustomTechniqueService,
    private groupSvc: CustomGroupService,
    private mitigationSvc: CustomMitigationService,
    private annotationSvc: AnnotationService,
  ) {}

  // ─── Export ───────────────────────────────────────────────────────────────

  exportCollection(name: string, description: string): Record<string, any> {
    const now = new Date().toISOString();
    const objects: Record<string, any>[] = [];

    // Identity for this collection
    const identityId = `identity--${this.uuid()}`;
    objects.push({
      type: 'identity',
      spec_version: '2.1',
      id: identityId,
      created: now,
      modified: now,
      name,
      description,
      identity_class: 'organization',
    });

    // Track mapping from internal IDs to STIX IDs for relationships
    const techniqueStixMap = new Map<string, string>(); // attackId -> stix id
    const groupStixMap = new Map<string, string>();     // internal id -> stix id
    const mitigationStixMap = new Map<string, string>(); // internal id -> stix id

    // Custom Techniques → attack-pattern
    for (const t of this.techniqueSvc.getAll()) {
      const stixId = `attack-pattern--${this.uuid()}`;
      techniqueStixMap.set(t.attackId, stixId);
      objects.push({
        type: 'attack-pattern',
        spec_version: '2.1',
        id: stixId,
        created: t.createdAt,
        modified: t.updatedAt,
        name: t.name,
        description: t.description,
        external_references: [{
          source_name: 'mitre-attack',
          external_id: t.attackId,
        }],
        kill_chain_phases: t.tacticShortnames.map(s => ({
          kill_chain_name: 'mitre-attack',
          phase_name: s,
        })),
        x_mitre_platforms: t.platforms,
        x_mitre_is_subtechnique: t.isSubtechnique,
        x_mitre_data_sources: t.dataSources,
      });
    }

    // Custom Groups → intrusion-set
    for (const g of this.groupSvc.getAll()) {
      const stixId = `intrusion-set--${this.uuid()}`;
      groupStixMap.set(g.id, stixId);
      objects.push({
        type: 'intrusion-set',
        spec_version: '2.1',
        id: stixId,
        created: g.createdAt,
        modified: g.updatedAt,
        name: g.name,
        description: g.description,
        aliases: g.aliases,
      });

      // Relationship: group uses technique
      for (const techId of g.techniqueIds) {
        const targetRef = techniqueStixMap.get(techId);
        if (targetRef) {
          objects.push(this.makeRelationship(stixId, targetRef, 'uses', now));
        }
      }
    }

    // Custom Mitigations → course-of-action
    for (const m of this.mitigationSvc.all) {
      const stixId = `course-of-action--${this.uuid()}`;
      mitigationStixMap.set(m.id, stixId);
      objects.push({
        type: 'course-of-action',
        spec_version: '2.1',
        id: stixId,
        created: m.createdAt,
        modified: m.updatedAt,
        name: m.name,
        description: m.description,
      });

      // Relationship: mitigation mitigates technique
      for (const techId of m.techniqueIds) {
        const targetRef = techniqueStixMap.get(techId);
        if (targetRef) {
          objects.push(this.makeRelationship(stixId, targetRef, 'mitigates', now));
        }
      }
    }

    // Annotations → note
    const annotationMap = this.annotationSvc.all;
    annotationMap.forEach((ann: TechniqueAnnotation) => {
      if (!ann.note) return;
      const techStixId = techniqueStixMap.get(ann.techniqueId);
      const objectRefs = techStixId ? [techStixId] : [`attack-pattern--${ann.techniqueId}`];
      objects.push({
        type: 'note',
        spec_version: '2.1',
        id: `note--${this.uuid()}`,
        created: ann.updatedAt,
        modified: ann.updatedAt,
        content: ann.note,
        object_refs: objectRefs,
      });
    });

    return {
      type: 'bundle',
      id: `bundle--${this.uuid()}`,
      objects,
    };
  }

  // ─── Import ───────────────────────────────────────────────────────────────

  importCollection(bundle: Record<string, any>): ImportSummary {
    const objects: any[] = bundle['objects'] ?? [];
    const summary: ImportSummary = { techniques: 0, groups: 0, mitigations: 0, notes: 0, skipped: 0 };

    // Index existing custom technique attackIds for dedup
    const existingAttackIds = new Set(this.techniqueSvc.getAll().map(t => t.attackId));

    // Index objects by STIX id for relationship resolution
    const objectById = new Map<string, any>();
    for (const obj of objects) {
      if (obj.id) objectById.set(obj.id, obj);
    }

    // Collect relationships for later linking
    const relationships: any[] = objects.filter(o => o.type === 'relationship');

    // Map from STIX id to newly-created attackId (for relationship resolution)
    const stixToAttackId = new Map<string, string>();
    const stixToGroupId = new Map<string, string>();
    const stixToMitigationId = new Map<string, string>();

    // Import attack-patterns → CustomTechnique
    for (const obj of objects) {
      if (obj.type !== 'attack-pattern') continue;
      const extRef = (obj.external_references ?? []).find(
        (r: any) => r.source_name === 'mitre-attack'
      );
      const attackId = extRef?.external_id ?? obj.name ?? '';
      if (!attackId || existingAttackIds.has(attackId)) {
        summary.skipped++;
        // Still record for relationship mapping even if skipped
        if (attackId) stixToAttackId.set(obj.id, attackId);
        continue;
      }
      const phases: string[] = (obj.kill_chain_phases ?? []).map((p: any) => p.phase_name);
      const created = this.techniqueSvc.create({
        attackId,
        name: obj.name ?? '',
        description: obj.description ?? '',
        tacticShortnames: phases,
        platforms: obj.x_mitre_platforms ?? [],
        dataSources: obj.x_mitre_data_sources ?? [],
        isSubtechnique: obj.x_mitre_is_subtechnique ?? false,
        parentId: null,
      });
      stixToAttackId.set(obj.id, created.attackId);
      existingAttackIds.add(attackId);
      summary.techniques++;
    }

    // Import intrusion-sets → CustomGroup
    const existingGroupNames = new Set(this.groupSvc.getAll().map(g => g.name.toLowerCase()));
    for (const obj of objects) {
      if (obj.type !== 'intrusion-set') continue;
      const gName = obj.name ?? '';
      if (!gName || existingGroupNames.has(gName.toLowerCase())) {
        summary.skipped++;
        continue;
      }
      const created = this.groupSvc.create({
        name: gName,
        aliases: obj.aliases ?? [],
        description: obj.description ?? '',
        techniqueIds: [], // will be populated from relationships
      });
      stixToGroupId.set(obj.id, created.id);
      existingGroupNames.add(gName.toLowerCase());
      summary.groups++;
    }

    // Import course-of-action → CustomMitigation
    const existingMitNames = new Set(this.mitigationSvc.all.map(m => m.name.toLowerCase()));
    for (const obj of objects) {
      if (obj.type !== 'course-of-action') continue;
      const mName = obj.name ?? '';
      if (!mName || existingMitNames.has(mName.toLowerCase())) {
        summary.skipped++;
        continue;
      }
      const created = this.mitigationSvc.create({
        name: mName,
        description: obj.description ?? '',
        category: 'Custom',
        techniqueIds: [], // will be populated from relationships
        implStatus: null,
      });
      stixToMitigationId.set(obj.id, created.id);
      existingMitNames.add(mName.toLowerCase());
      summary.mitigations++;
    }

    // Process relationships to link groups/mitigations to techniques
    for (const rel of relationships) {
      const sourceId = rel.source_ref;
      const targetId = rel.target_ref;
      const targetAttackId = stixToAttackId.get(targetId);
      if (!targetAttackId) continue;

      if (rel.relationship_type === 'uses') {
        const groupId = stixToGroupId.get(sourceId);
        if (groupId) {
          const group = this.groupSvc.getById(groupId);
          if (group && !group.techniqueIds.includes(targetAttackId)) {
            this.groupSvc.update(groupId, {
              techniqueIds: [...group.techniqueIds, targetAttackId],
            });
          }
        }
      }

      if (rel.relationship_type === 'mitigates') {
        const mitId = stixToMitigationId.get(sourceId);
        if (mitId) {
          const mit = this.mitigationSvc.all.find(m => m.id === mitId);
          if (mit && !mit.techniqueIds.includes(targetAttackId)) {
            this.mitigationSvc.update(mitId, {
              techniqueIds: [...mit.techniqueIds, targetAttackId],
            });
          }
        }
      }
    }

    // Import notes → Annotations
    for (const obj of objects) {
      if (obj.type !== 'note') continue;
      const content = obj.content ?? '';
      if (!content) continue;
      // Find the first object_ref that resolves to an attackId
      const refs: string[] = obj.object_refs ?? [];
      let targetAttackId: string | undefined;
      for (const ref of refs) {
        targetAttackId = stixToAttackId.get(ref);
        if (targetAttackId) break;
      }
      if (targetAttackId) {
        this.annotationSvc.setAnnotation(targetAttackId, content);
        summary.notes++;
      } else {
        summary.skipped++;
      }
    }

    return summary;
  }

  // ─── Import from URL ──────────────────────────────────────────────────────

  async importFromUrl(url: string): Promise<ImportSummary> {
    const bundle = await firstValueFrom(
      this.http.get<Record<string, any>>(url)
    );
    return this.importCollection(bundle);
  }

  // ─── Download ─────────────────────────────────────────────────────────────

  downloadBundle(name: string, description: string): void {
    const bundle = this.exportCollection(name, description);
    const json = JSON.stringify(bundle, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name.replace(/[^a-zA-Z0-9_-]/g, '_')}_stix_collection.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  private makeRelationship(sourceRef: string, targetRef: string, type: string, now: string): Record<string, any> {
    return {
      type: 'relationship',
      spec_version: '2.1',
      id: `relationship--${this.uuid()}`,
      created: now,
      modified: now,
      relationship_type: type,
      source_ref: sourceRef,
      target_ref: targetRef,
    };
  }

  private uuid(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }
}
