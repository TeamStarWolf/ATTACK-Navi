// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

/** Rich test record fetched live from the Atomic Red Team GitHub YAML index. */
export interface AtomicLiveTest {
  name: string;
  description: string;       // first 250 chars of description
  platforms: string[];
  executorName: string;      // 'powershell', 'command_prompt', 'bash', 'sh', 'manual'
  guid: string;
  attackId: string;
  githubUrl: string;
}

export interface AtomicTest {
  attackId: string;        // ATT&CK technique ID (e.g. "T1059.001")
  name: string;            // Test name
  platforms: string[];
  inputArgs?: string;      // Brief description of what inputs are needed
  url: string;             // Link to the atomic test on GitHub
}

interface AtomicNavigatorLayer {
  name?: string;
  domain?: string;
  techniques: Array<{
    techniqueID: string;
    score?: number;
    tactic?: string;
    enabled?: boolean;
  }>;
}

// (The 68-entry ATOMIC_DETAIL_TESTS table was removed 2026-08-15: 21 of 27
// spot-checked test names did not exist in the upstream Atomic Red Team index
// (fabricated). Test details now come exclusively from the live per-technique
// YAML; counts from the published Red Canary navigator layer.)

@Injectable({ providedIn: 'root' })
export class AtomicService {
  // Published by Red Canary — ATT&CK Navigator layer with test counts per technique.
  private static readonly NAVIGATOR_LAYER_URL =
    'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/Attack-Navigator-Layers/art-navigator-layer.json';

  // Per-technique YAML base URL — fetch on demand
  private static readonly YAML_BASE_URL =
    'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics';

  // Live counts from the Navigator layer (techniqueID → test count)
  private directCounts = new Map<string, number>();
  // Live tests fetched from GitHub YAML (per technique, cached)
  private liveTestCache = new Map<string, AtomicLiveTest[]>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  readonly total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  readonly covered$ = this.coveredSubject.asObservable();

  constructor(private http: HttpClient) {
    this.fetchNavigatorLayer();
  }

  // ─── Public API ──────────────────────────────────────────────────────────────

  /** Returns ATT&CK test count for a technique (from the live navigator layer). */
  getTestCount(attackId: string): number {
    if (this.directCounts.size > 0) {
      return this.getLiveCount(attackId);
    }
    return 0;
  }

  /** Alias used by matrix heatmap. */
  getHeatScore(attackId: string): number {
    return this.getTestCount(attackId);
  }

  /** Returns cached live test records for the sidebar (fetched via fetchLiveTests). */
  getTests(attackId: string): AtomicTest[] {
    const live = this.liveTestCache.get(attackId) ?? [];
    return live.map(t => ({
      attackId: t.attackId,
      name: t.name,
      platforms: t.platforms,
      url: t.githubUrl,
    }));
  }

  /** GitHub link for a technique's Atomic Red Team page. */
  getAtomicUrl(attackId: string): string {
    return `https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/${attackId}/${attackId}.md`;
  }

  /** Returns the full live counts map (techniqueID → count). */
  getLiveCounts(): ReadonlyMap<string, number> {
    return this.directCounts;
  }

  getAll(): AtomicTest[] {
    const all: AtomicTest[] = [];
    for (const tests of this.liveTestCache.values()) {
      for (const t of tests) {
        all.push({ attackId: t.attackId, name: t.name, platforms: t.platforms, url: t.githubUrl });
      }
    }
    return all;
  }

  /**
   * Fetch up to `limit` real test records from Atomic Red Team GitHub YAML.
   * Returns cached results on repeat calls. Falls back to [] on network error.
   */
  fetchLiveTests(attackId: string, limit = 5): Observable<AtomicLiveTest[]> {
    if (this.liveTestCache.has(attackId)) {
      return of(this.liveTestCache.get(attackId)!.slice(0, limit));
    }

    const url = `${AtomicService.YAML_BASE_URL}/${attackId}/${attackId}.yaml`;
    return this.http.get(url, { responseType: 'text' }).pipe(
      map(yaml => {
        const tests = this.parseAtomicYaml(yaml, attackId);
        this.liveTestCache.set(attackId, tests);
        return tests.slice(0, limit);
      }),
      catchError(() => of([])),
    );
  }

  // ─── Private helpers ─────────────────────────────────────────────────────────

  /**
   * Parse Atomic Red Team YAML to extract test records.
   * Uses a simple line-based parser specific to the ART YAML format.
   */
  private parseAtomicYaml(yaml: string, attackId: string): AtomicLiveTest[] {
    const tests: AtomicLiveTest[] = [];
    // Split on top-level list items (each test starts with "- name:")
    const lines = yaml.split('\n');
    let inTests = false;
    let currentTest: Partial<AtomicLiveTest> | null = null;
    let descLines: string[] = [];
    let inDescription = false;
    let inPlatforms = false;
    let inExecutor = false;
    let executorIndent = -1;

    const pushCurrent = () => {
      if (currentTest?.name) {
        const desc = descLines.join(' ').replace(/\s+/g, ' ').trim().slice(0, 280);
        tests.push({
          name: currentTest.name,
          description: desc,
          platforms: currentTest.platforms ?? [],
          executorName: currentTest.executorName ?? 'manual',
          guid: currentTest.guid ?? '',
          attackId,
          githubUrl: `https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/${attackId}/${attackId}.md`,
        });
      }
      currentTest = null;
      descLines = [];
      inDescription = false;
      inPlatforms = false;
      inExecutor = false;
      executorIndent = -1;
    };

    for (const rawLine of lines) {
      const line = rawLine;
      const trimmed = line.trim();
      const indent = line.length - line.trimStart().length;

      // Detect start of atomic_tests section
      if (trimmed === 'atomic_tests:') { inTests = true; continue; }
      if (!inTests) continue;

      // New test item
      if (trimmed.startsWith('- name:') && indent === 0) {
        pushCurrent();
        currentTest = { name: trimmed.slice(7).trim().replace(/^['"]|['"]$/g, ''), platforms: [] };
        continue;
      }
      if (!currentTest) continue;

      // GUID
      if (trimmed.startsWith('auto_generated_guid:')) {
        currentTest.guid = trimmed.slice(20).trim().replace(/^['"]|['"]$/g, '');
        inDescription = false; inPlatforms = false; inExecutor = false;
        continue;
      }

      // Description block
      if (trimmed.startsWith('description:')) {
        inDescription = true; inPlatforms = false; inExecutor = false;
        const inline = trimmed.slice(12).trim().replace(/^\|/, '').trim();
        if (inline && inline !== '|') descLines.push(inline);
        continue;
      }

      // Platforms
      if (trimmed === 'supported_platforms:') {
        inPlatforms = true; inDescription = false; inExecutor = false;
        continue;
      }
      if (inPlatforms && trimmed.startsWith('- ')) {
        currentTest.platforms = currentTest.platforms ?? [];
        currentTest.platforms.push(trimmed.slice(2).trim().replace(/^['"]|['"]$/g, ''));
        continue;
      }
      if (inPlatforms && !trimmed.startsWith('- ')) {
        inPlatforms = false;
      }

      // Executor block
      if (trimmed === 'executor:') {
        inExecutor = true; inDescription = false; inPlatforms = false;
        executorIndent = indent;
        continue;
      }
      if (inExecutor && trimmed.startsWith('name:')) {
        currentTest.executorName = trimmed.slice(5).trim().replace(/^['"]|['"]$/g, '');
        inExecutor = false;
        continue;
      }
      if (inExecutor && (indent <= executorIndent && trimmed.length > 0 && !trimmed.startsWith('#'))) {
        inExecutor = false;
      }

      // Collect description lines
      if (inDescription) {
        if (trimmed === '' || (indent < 2 && trimmed.length > 0 && !trimmed.startsWith('#') &&
            !trimmed.startsWith('- ') && trimmed.includes(':') && !trimmed.startsWith('http'))) {
          inDescription = false;
        } else {
          descLines.push(trimmed);
        }
      }
    }
    pushCurrent();

    return tests;
  }

  private fetchNavigatorLayer(): void {
    this.http.get<AtomicNavigatorLayer>(AtomicService.NAVIGATOR_LAYER_URL).subscribe({
      next: (layer) => this.ingestLayer(layer),
      error: () => {
        // Network unavailable — service falls back to hardcoded counts silently
        this.loadedSubject.next(false);
      },
    });
  }

  private ingestLayer(layer: AtomicNavigatorLayer): void {
    this.directCounts.clear();
    let totalTests = 0;
    let coveredTechs = 0;

    for (const entry of layer.techniques ?? []) {
      const id = entry.techniqueID;
      const score = entry.score ?? 0;
      if (!id || score <= 0) continue;

      this.directCounts.set(id, score);
      totalTests += score;
      coveredTechs++;
    }

    this.totalSubject.next(totalTests);
    this.coveredSubject.next(coveredTechs);
    this.loadedSubject.next(true);
  }

  /**
   * Compute test count for a technique ID from live directCounts.
   * For a parent ID (e.g. T1059): returns own count + all sub counts.
   * For a sub ID (e.g. T1059.001): returns own count only.
   */
  private getLiveCount(attackId: string): number {
    const direct = this.directCounts.get(attackId) ?? 0;
    if (attackId.includes('.')) return direct;

    // Aggregate subtechnique counts into parent total
    let sub = 0;
    const prefix = attackId + '.';
    for (const [id, count] of this.directCounts) {
      if (id.startsWith(prefix)) sub += count;
    }
    return direct + sub;
  }

  // ─── Invoke-AtomicRedTeam Command Generation ────────────────────────────────

  /**
   * Generate a PowerShell script to install Invoke-AtomicRedTeam and run a
   * specific technique test (or all tests for the technique).
   */
  generateInvokeCommand(attackId: string, testNumber?: number): string {
    const lines = [
      '# Install Invoke-AtomicRedTeam if needed',
      "IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)",
      'Install-AtomicRedTeam -getAtomics',
      '',
      `# Run test for ${attackId}`,
    ];
    if (testNumber !== undefined) {
      lines.push(`Invoke-AtomicTest ${attackId} -TestNumbers ${testNumber}`);
    } else {
      lines.push(`Invoke-AtomicTest ${attackId}`);
    }
    return lines.join('\n');
  }

  /** Generate a cleanup command for a technique. */
  generateCleanupCommand(attackId: string): string {
    return `Invoke-AtomicTest ${attackId} -Cleanup`;
  }

  /** Generate a batch execution script for multiple techniques. */
  generateAllTestsScript(attackIds: string[]): string {
    if (attackIds.length === 0) return '# No techniques selected';
    const lines = [
      '# Invoke-AtomicRedTeam Batch Execution Script',
      '# Install Invoke-AtomicRedTeam if needed',
      "IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)",
      'Install-AtomicRedTeam -getAtomics',
      '',
      `# Run tests for ${attackIds.length} techniques`,
    ];
    for (const id of attackIds) {
      lines.push(`Write-Host "Running tests for ${id}..." -ForegroundColor Cyan`);
      lines.push(`Invoke-AtomicTest ${id}`);
      lines.push('');
    }
    lines.push('Write-Host "All tests complete." -ForegroundColor Green');
    return lines.join('\n');
  }
}
