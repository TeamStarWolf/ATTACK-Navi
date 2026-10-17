// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { SourceRegistryService } from './source-registry.service';

interface SkillsNavigatorLayer {
  name?: string;
  domain?: string;
  techniques: Array<{
    techniqueID: string;
    score?: number;
    tactic?: string;
  }>;
}

const SKILLS_LAYER_URL =
  'https://raw.githubusercontent.com/mukul975/Anthropic-Cybersecurity-Skills/main/mappings/attack-navigator-layer.json';

@Injectable({ providedIn: 'root' })
export class AnthropicSkillsService {
  private skillCounts = new Map<string, number>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  readonly total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  readonly covered$ = this.coveredSubject.asObservable();

  constructor(
    private http: HttpClient,
    private sources: SourceRegistryService = new SourceRegistryService(),
  ) {
    this.loadLayer();
  }

  /** Load again after a failed or empty load: the data-health Retry (E1.3). */
  retry(): void {
    this.loadLayer();
  }

  /** Fetch the Anthropic Cybersecurity Skills Navigator layer. */
  private loadLayer(): void {
    this.sources.begin('anthropic-skills-layer');
    this.http.get<SkillsNavigatorLayer>(SKILLS_LAYER_URL).subscribe({
      next: layer => {
        if (layer?.techniques?.length) {
          this.ingestLayer(layer);
        } else {
          this.sources.succeed('anthropic-skills-layer', 0);
        }
      },
      // A failed fetch is recorded as failed; loaded$ stays false.
      error: err => this.sources.fail('anthropic-skills-layer', err),
    });
  }

  /** Ingest a parsed Navigator layer into local counts. */
  private ingestLayer(layer: SkillsNavigatorLayer): void {
    this.skillCounts.clear();
    let total = 0;
    let covered = 0;
    for (const entry of layer.techniques ?? []) {
      const id = entry.techniqueID;
      const score = entry.score ?? 0;
      if (!id || score <= 0) continue;
      this.skillCounts.set(id, score);
      total += score;
      covered++;
    }
    this.totalSubject.next(total);
    this.coveredSubject.next(covered);
    this.sources.succeed('anthropic-skills-layer', covered);
    if (covered > 0) this.loadedSubject.next(true);
  }

  /** Skill count for a technique (rolls up sub-technique counts). */
  getSkillCount(attackId: string): number {
    const direct = this.skillCounts.get(attackId) ?? 0;
    if (attackId.includes('.')) return direct;
    let sub = 0;
    const prefix = attackId + '.';
    for (const [id, count] of this.skillCounts) {
      if (id.startsWith(prefix)) sub += count;
    }
    return direct + sub;
  }

  /** Alias used by heatmap subsystem. */
  getHeatScore(attackId: string): number {
    return this.getSkillCount(attackId);
  }
}
