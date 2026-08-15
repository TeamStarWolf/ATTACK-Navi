// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, forkJoin, of } from 'rxjs';
import { catchError } from 'rxjs/operators';

export interface EngageActivity {
  id: string;           // e.g., "EAC0002"
  name: string;
  category: 'Prepare' | 'Expose' | 'Affect' | 'Elicit' | 'Understand';
  definition: string;
  url: string;
  attackIds: string[];  // ATT&CK technique IDs this activity applies to
}

// MITRE Engage's published dataset (github.com/mitre/engage). The previous
// implementation shipped a generated table that reused real EAC ids with
// invented names, definitions, and technique mappings (e.g. EAC0002 is
// officially "Network Monitoring", not "Behavioral Analytics") — everything
// now comes from the official JSON files.
const ENGAGE_DATA_BASE = 'https://raw.githubusercontent.com/mitre/engage/main/Data/json';

interface EngageActivityRow { id: string; name?: string; description?: string }
interface EngageAttackMappingRow { attack_id?: string; eac_id?: string }
interface EngageGoalApproachRow { goal_id?: string; approach_id?: string }
interface EngageApproachActivityRow { approach_id?: string; activity_id?: string }
interface EngageGoalRow { id: string; name?: string }

@Injectable({ providedIn: 'root' })
export class EngageService {
  private byAttackId = new Map<string, EngageActivity[]>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  constructor(private http: HttpClient) {
    this.load();
  }

  private load(): void {
    const get = <T>(file: string) =>
      this.http.get<T[]>(`${ENGAGE_DATA_BASE}/${file}`).pipe(catchError(() => of([] as T[])));

    forkJoin({
      activities: get<EngageActivityRow>('activities.json'),
      attackMap: get<EngageAttackMappingRow>('attack_mapping.json'),
      goalApproach: get<EngageGoalApproachRow>('goal_approach_mappings.json'),
      approachActivity: get<EngageApproachActivityRow>('approach_activity_mappings.json'),
      goals: get<EngageGoalRow>('goals.json'),
    }).subscribe(({ activities, attackMap, goalApproach, approachActivity, goals }) => {
      // Category = the activity's goal, resolved activity → approach → goal.
      const goalNames = new Map(goals.map(g => [g.id, g.name ?? '']));
      const approachGoal = new Map<string, string>();
      for (const row of goalApproach) {
        if (row.approach_id && row.goal_id && !approachGoal.has(row.approach_id)) {
          approachGoal.set(row.approach_id, goalNames.get(row.goal_id) ?? '');
        }
      }
      const activityCategory = new Map<string, string>();
      for (const row of approachActivity) {
        if (row.activity_id && row.approach_id && !activityCategory.has(row.activity_id)) {
          activityCategory.set(row.activity_id, approachGoal.get(row.approach_id) ?? '');
        }
      }

      const registry = new Map<string, EngageActivity>();
      for (const a of activities) {
        if (!a.id) continue;
        const category = activityCategory.get(a.id);
        registry.set(a.id, {
          id: a.id,
          name: a.name ?? '',
          category: (category as EngageActivity['category']) || 'Expose',
          definition: a.description ?? '',
          url: 'https://engage.mitre.org/matrix/',
          attackIds: [],
        });
      }

      for (const row of attackMap) {
        const activity = row.eac_id ? registry.get(row.eac_id) : undefined;
        const attackId = row.attack_id;
        if (!activity || !attackId) continue;
        if (!activity.attackIds.includes(attackId)) activity.attackIds.push(attackId);
        if (!this.byAttackId.has(attackId)) this.byAttackId.set(attackId, []);
        const list = this.byAttackId.get(attackId)!;
        if (!list.some(existing => existing.id === activity.id)) list.push(activity);
      }

      this.loadedSubject.next(true);
    });
  }

  getActivities(attackId: string): EngageActivity[] {
    const direct = this.byAttackId.get(attackId) ?? [];
    const parentId = attackId.includes('.') ? attackId.split('.')[0] : null;
    const parent = parentId ? (this.byAttackId.get(parentId) ?? []) : [];
    return [...direct, ...parent.filter(p => !direct.some(d => d.id === p.id))];
  }
}
