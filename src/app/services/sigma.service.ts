import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, of } from 'rxjs';
import { catchError, map, switchMap } from 'rxjs/operators';
import { Technique } from '../models/technique';

export interface SigmaRule {
  techniqueId: string;
  techniqueName: string;
  yaml: string;
}

export interface SigmaRuleDetail {
  title: string;
  id: string;
  status: string;
  level: string;
  description: string;
  url: string;
}

interface SigmaNavigatorLayer {
  name?: string;
  domain?: string;
  techniques: Array<{
    techniqueID: string;
    score?: number;
    tactic?: string;
  }>;
}

// ATT&CK data source → Sigma logsource mapping
const DATASOURCE_TO_LOGSOURCE: Record<string, { category?: string; product?: string; service?: string }> = {
  'Process': { category: 'process_creation' },
  'Process Creation': { category: 'process_creation' },
  'Process Termination': { category: 'process_termination' },
  'Network Traffic': { category: 'network_connection' },
  'Network Connection': { category: 'network_connection' },
  'File': { category: 'file_event' },
  'File Creation': { category: 'file_creation' },
  'File Modification': { category: 'file_change' },
  'File Deletion': { category: 'file_delete' },
  'File Access': { category: 'file_access' },
  'Windows Registry': { product: 'windows', category: 'registry_event' },
  'Registry': { product: 'windows', category: 'registry_event' },
  'Registry Key Creation': { product: 'windows', category: 'registry_add' },
  'Registry Key Modification': { product: 'windows', category: 'registry_set' },
  'Registry Key Deletion': { product: 'windows', category: 'registry_delete' },
  'Windows Security': { product: 'windows', service: 'security' },
  'Windows System': { product: 'windows', service: 'system' },
  'Windows Application': { product: 'windows', service: 'application' },
  'Authentication': { product: 'windows', service: 'security', category: 'authentication' },
  'Logon Session': { product: 'windows', service: 'security' },
  'Command': { category: 'process_creation' },
  'Script': { category: 'process_creation' },
  'Module': { category: 'image_load' },
  'Service': { product: 'windows', service: 'system' },
  'Scheduled Job': { product: 'windows', service: 'taskscheduler' },
  'WMI': { product: 'windows', service: 'wmi' },
  'DNS': { category: 'dns' },
  'Firewall': { category: 'firewall' },
  'Web': { category: 'webserver' },
  'Email': { category: 'email' },
  'Cloud': { product: 'aws|azure|gcp' },
  'Container': { product: 'docker|kubernetes' },
  'Driver': { category: 'driver_loaded' },
  'Kernel': { category: 'process_creation' },
};

// SigmaHQ publishes Navigator layer stats for the current rule set
const SIGMA_LAYER_URLS = [
  'https://raw.githubusercontent.com/SigmaHQ/sigma-statistics/main/navigator_layer.json',
  'https://raw.githubusercontent.com/SigmaHQ/sigma/master/other/statistics/sigma_statistics.json',
];

@Injectable({ providedIn: 'root' })
export class SigmaService {
  private directCounts = new Map<string, number>();
  private ruleDetailCache = new Map<string, SigmaRuleDetail[]>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  readonly total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  readonly covered$ = this.coveredSubject.asObservable();

  constructor(private http: HttpClient) {
    this.loadLive();
  }

  /**
   * Attempt to fetch a live Sigma Navigator layer from SigmaHQ.
   * Tries each URL in sequence; silently falls back to empty counts on failure.
   */
  loadLive(): void {
    this.tryUrl(0);
  }

  private tryUrl(index: number): void {
    if (index >= SIGMA_LAYER_URLS.length) return;
    this.http.get<SigmaNavigatorLayer>(SIGMA_LAYER_URLS[index])
      .pipe(catchError(() => of(null)))
      .subscribe(layer => {
        if (layer?.techniques?.length) {
          this.ingestLayer(layer);
        } else {
          this.tryUrl(index + 1);
        }
      });
  }

  /** Rule count for a technique (0 until a Sigma backend is connected). */
  getRuleCount(techniqueId: string): number {
    if (this.directCounts.size === 0) return 0;
    return this.getLiveCount(techniqueId);
  }

  /** Alias used by matrix heatmap. */
  getHeatScore(techniqueId: string): number {
    return this.getRuleCount(techniqueId);
  }

  /** Returns the full live counts map (techniqueID → count). */
  getLiveCounts(): ReadonlyMap<string, number> {
    return this.directCounts;
  }

  /** Returns cached rule details for a technique, if available. */
  getCachedRules(attackId: string): SigmaRuleDetail[] | undefined {
    return this.ruleDetailCache.get(attackId);
  }

  /**
   * Fetch actual Sigma rule details for a technique from the SigmaHQ GitHub repo.
   * Searches the GitHub code API for YAML files mentioning the technique tag,
   * then fetches each raw file to extract YAML front matter fields.
   * Results are cached per attackId.
   */
  fetchRulesForTechnique(attackId: string): Observable<SigmaRuleDetail[]> {
    const cached = this.ruleDetailCache.get(attackId);
    if (cached) return of(cached);

    const tag = `attack.${attackId.toLowerCase()}`;
    const url = `https://api.github.com/search/code?q=${encodeURIComponent(tag)}+repo:SigmaHQ/sigma+extension:yml&per_page=10`;

    return this.http.get<{ items: Array<{ path: string; html_url: string }> }>(url).pipe(
      map(resp => (resp.items ?? []).slice(0, 10)),
      switchMap(items => {
        if (items.length === 0) {
          this.ruleDetailCache.set(attackId, []);
          return of([] as SigmaRuleDetail[]);
        }
        // Fetch raw content for each file and extract front matter
        const fetches = items.map(item => {
          const rawUrl = `https://raw.githubusercontent.com/SigmaHQ/sigma/main/${item.path}`;
          return this.http.get(rawUrl, { responseType: 'text' }).pipe(
            map(yaml => this.parseYamlFrontMatter(yaml, item.html_url)),
            catchError(() => of(null as SigmaRuleDetail | null)),
          );
        });
        // Combine all fetches
        return new Observable<SigmaRuleDetail[]>(subscriber => {
          const results: (SigmaRuleDetail | null)[] = [];
          let completed = 0;
          for (const fetch$ of fetches) {
            fetch$.subscribe({
              next: val => {
                results.push(val);
                completed++;
                if (completed === fetches.length) {
                  const details = results.filter((r): r is SigmaRuleDetail => r !== null);
                  this.ruleDetailCache.set(attackId, details);
                  subscriber.next(details);
                  subscriber.complete();
                }
              },
              error: () => {
                results.push(null);
                completed++;
                if (completed === fetches.length) {
                  const details = results.filter((r): r is SigmaRuleDetail => r !== null);
                  this.ruleDetailCache.set(attackId, details);
                  subscriber.next(details);
                  subscriber.complete();
                }
              },
            });
          }
        });
      }),
      catchError(() => {
        this.ruleDetailCache.set(attackId, []);
        return of([] as SigmaRuleDetail[]);
      }),
    );
  }

  /** Extract title, id, status, level, description from Sigma YAML text. */
  private parseYamlFrontMatter(yaml: string, htmlUrl: string): SigmaRuleDetail | null {
    const getField = (field: string): string => {
      const regex = new RegExp(`^${field}:\\s*(.+)$`, 'm');
      const match = yaml.match(regex);
      return match ? match[1].trim().replace(/^['"]|['"]$/g, '') : '';
    };
    const title = getField('title');
    if (!title) return null;
    return {
      title,
      id: getField('id'),
      status: getField('status'),
      level: getField('level'),
      description: getField('description').slice(0, 200),
      url: htmlUrl,
    };
  }

  /**
   * Ingest a pre-parsed ATT&CK Navigator layer (e.g. from a connected Sigma backend).
   * The layer must have `techniques[].techniqueID` and `techniques[].score` fields.
   */
  ingestLayer(layer: SigmaNavigatorLayer): void {
    this.directCounts.clear();
    let total = 0;
    let covered = 0;
    for (const entry of layer.techniques ?? []) {
      const id = entry.techniqueID;
      const score = entry.score ?? 0;
      if (!id || score <= 0) continue;
      this.directCounts.set(id, score);
      total += score;
      covered++;
    }
    this.totalSubject.next(total);
    this.coveredSubject.next(covered);
    this.loadedSubject.next(true);
  }

  private getLiveCount(attackId: string): number {
    const direct = this.directCounts.get(attackId) ?? 0;
    if (attackId.includes('.')) return direct;
    let sub = 0;
    const prefix = attackId + '.';
    for (const [id, count] of this.directCounts) {
      if (id.startsWith(prefix)) sub += count;
    }
    return direct + sub;
  }

  generateRuleForTechnique(tech: Technique): SigmaRule {
    const logsource = this.pickLogsource(tech);
    const detectionHint = this.buildDetectionHint(tech);
    const tags = this.buildTags(tech);

    const yaml = this.buildYaml({
      title: `Detect ${tech.name}`,
      id: this.generateGuid(),
      status: 'experimental',
      description: `Detects activity related to ATT&CK technique ${tech.attackId} - ${tech.name}. ${detectionHint.comment}`,
      references: [`https://attack.mitre.org/techniques/${tech.attackId.replace('.', '/')}`],
      author: 'ATT&CK Navigator Export',
      date: new Date().toISOString().split('T')[0],
      modified: new Date().toISOString().split('T')[0],
      tags,
      logsource,
      detection: detectionHint.detection,
      fields: detectionHint.fields,
      falsepositives: ['Legitimate administrative activity'],
      level: this.inferLevel(tech),
    });

    return { techniqueId: tech.attackId, techniqueName: tech.name, yaml };
  }

  generateRulesForTechniques(techs: Technique[]): string {
    const rules = techs.map(t => this.generateRuleForTechnique(t).yaml);
    return rules.join('\n---\n\n');
  }

  exportRules(techs: Technique[]): void {
    const content = this.generateRulesForTechniques(techs);
    const filename = techs.length === 1
      ? `sigma-${techs[0].attackId}.yml`
      : `sigma-rules-${new Date().toISOString().split('T')[0]}.yml`;
    const blob = new Blob([content], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: filename });
    a.click();
    URL.revokeObjectURL(url);
  }

  private pickLogsource(tech: Technique): Record<string, string> {
    for (const ds of (tech.dataSources ?? [])) {
      for (const [key, val] of Object.entries(DATASOURCE_TO_LOGSOURCE)) {
        if (ds.toLowerCase().includes(key.toLowerCase())) return val as Record<string, string>;
      }
    }
    // Platform-based fallback
    if (tech.platforms?.includes('Windows')) return { product: 'windows', category: 'process_creation' };
    if (tech.platforms?.includes('Linux') || tech.platforms?.includes('macOS')) return { category: 'process_creation' };
    return { category: 'process_creation' };
  }

  private buildDetectionHint(tech: Technique): { detection: Record<string, any>; fields: string[]; comment: string } {
    const name = tech.name.toLowerCase();

    // Detection patterns based on technique name
    if (name.includes('powershell') || tech.attackId === 'T1059.001') {
      return {
        comment: 'Look for PowerShell execution with encoded commands or suspicious flags.',
        detection: {
          selection: { Image: ['*\\powershell.exe', '*\\pwsh.exe'], CommandLine: ['*-enc *', '*-EncodedCommand*', '*IEX*', '*Invoke-Expression*', '*-w hidden*'] },
          condition: 'selection'
        },
        fields: ['CommandLine', 'ParentImage', 'User']
      };
    }
    if (name.includes('cmd') || tech.attackId === 'T1059.003') {
      return {
        comment: 'Look for cmd.exe spawned with suspicious flags.',
        detection: {
          selection: { Image: '*\\cmd.exe', CommandLine: ['*/c *', '*/k *'] },
          filter: { ParentImage: ['*\\explorer.exe'] },
          condition: 'selection and not filter'
        },
        fields: ['CommandLine', 'ParentImage']
      };
    }
    if (name.includes('scheduled task')) {
      return {
        comment: 'Detect scheduled task creation via schtasks.exe or Task Scheduler service.',
        detection: {
          selection: { Image: '*\\schtasks.exe', CommandLine: '*/create *' },
          condition: 'selection'
        },
        fields: ['CommandLine', 'User', 'ParentImage']
      };
    }
    if (name.includes('registry') || tech.attackId.startsWith('T1547') || tech.attackId.startsWith('T1112')) {
      return {
        comment: 'Detect suspicious registry key modifications used for persistence.',
        detection: {
          selection: {
            TargetObject: [
              '*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*',
              '*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce*',
              '*\\SYSTEM\\CurrentControlSet\\Services*'
            ]
          },
          condition: 'selection'
        },
        fields: ['TargetObject', 'Details', 'Image', 'User']
      };
    }
    if (name.includes('credential') || name.includes('password') || name.includes('lsass')) {
      return {
        comment: 'Detect credential access activity targeting LSASS or credential stores.',
        detection: {
          selection: { TargetImage: '*\\lsass.exe', GrantedAccess: ['0x1010', '0x1410', '0x1418', '0x1fffff'] },
          condition: 'selection'
        },
        fields: ['SourceImage', 'TargetImage', 'GrantedAccess', 'CallTrace']
      };
    }
    if (name.includes('network') || name.includes('connect') || name.includes('c2') || name.includes('c&c')) {
      return {
        comment: 'Detect suspicious outbound network connections.',
        detection: {
          selection: { Initiated: 'true' },
          filter: { DestinationIp: ['127.0.0.1', '::1', '10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12'] },
          condition: 'selection and not filter'
        },
        fields: ['Image', 'DestinationIp', 'DestinationPort', 'User']
      };
    }
    if (name.includes('phish')) {
      return {
        comment: 'Detect spearphishing document execution vectors.',
        detection: {
          selection: { ParentImage: ['*\\winword.exe', '*\\excel.exe', '*\\outlook.exe', '*\\msedge.exe'], Image: ['*\\cmd.exe', '*\\powershell.exe', '*\\wscript.exe', '*\\cscript.exe'] },
          condition: 'selection'
        },
        fields: ['Image', 'CommandLine', 'ParentImage']
      };
    }
    if (name.includes('injection') || name.includes('inject')) {
      return {
        comment: 'Detect process injection activity via suspicious cross-process access.',
        detection: {
          selection: { GrantedAccess: ['0x1f0fff', '0x1fffff', '0x40', '0x80'] },
          filter: { SourceImage: ['*\\System32\\*', '*\\SysWow64\\*'] },
          condition: 'selection and not filter'
        },
        fields: ['SourceImage', 'TargetImage', 'GrantedAccess']
      };
    }

    // Generic fallback based on technique type
    const detText = tech.detectionText ?? '';
    return {
      comment: detText.length > 50 ? detText.substring(0, 200) + '...' : 'Customize detection based on your environment.',
      detection: {
        keywords: [`# TODO: Add detection conditions for ${tech.attackId} - ${tech.name}`, '# Reference: ' + `https://attack.mitre.org/techniques/${tech.attackId.replace('.', '/')}`],
        condition: 'keywords'
      },
      fields: ['CommandLine', 'Image', 'User']
    };
  }

  private buildTags(tech: Technique): string[] {
    const tags = [`attack.${tech.attackId.toLowerCase()}`];
    for (const tactic of (tech.tacticShortnames ?? [])) {
      tags.push(`attack.${tactic.replace(/-/g, '_')}`);
    }
    return tags;
  }

  private inferLevel(tech: Technique): string {
    const id = tech.attackId;
    // High-priority techniques
    const high = ['T1059', 'T1078', 'T1021', 'T1003', 'T1055', 'T1190', 'T1203', 'T1548', 'T1068'];
    if (high.some(h => id.startsWith(h))) return 'high';
    const medium = ['T1547', 'T1053', 'T1112', 'T1505', 'T1040', 'T1557'];
    if (medium.some(m => id.startsWith(m))) return 'medium';
    return 'low';
  }

  private generateGuid(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }

  private buildYaml(rule: any): string {
    const lines: string[] = [];
    lines.push(`title: ${rule.title}`);
    lines.push(`id: ${rule.id}`);
    lines.push(`status: ${rule.status}`);
    lines.push(`description: '${rule.description.replace(/'/g, "''")}'`);
    lines.push('references:');
    for (const r of rule.references) lines.push(`  - '${r}'`);
    lines.push(`author: '${rule.author}'`);
    lines.push(`date: ${rule.date}`);
    lines.push(`modified: ${rule.modified}`);
    lines.push('tags:');
    for (const t of rule.tags) lines.push(`  - ${t}`);
    lines.push('logsource:');
    for (const [k, v] of Object.entries(rule.logsource)) lines.push(`  ${k}: ${v}`);
    lines.push('detection:');
    lines.push(this.yamlDetection(rule.detection, 2));
    lines.push(`  condition: ${rule.detection.condition}`);
    if (rule.fields?.length) {
      lines.push('fields:');
      for (const f of rule.fields) lines.push(`  - ${f}`);
    }
    lines.push('falsepositives:');
    for (const fp of rule.falsepositives) lines.push(`  - ${fp}`);
    lines.push(`level: ${rule.level}`);
    return lines.join('\n');
  }

  private yamlDetection(detection: Record<string, any>, indent: number): string {
    const lines: string[] = [];
    const pad = ' '.repeat(indent);
    for (const [key, val] of Object.entries(detection)) {
      if (key === 'condition') continue;
      if (Array.isArray(val)) {
        lines.push(`${pad}${key}:`);
        for (const item of val) lines.push(`${pad}  - '${item}'`);
      } else if (typeof val === 'object') {
        lines.push(`${pad}${key}:`);
        for (const [k2, v2] of Object.entries(val)) {
          if (Array.isArray(v2)) {
            lines.push(`${pad}  ${k2}:`);
            for (const item of v2 as any[]) lines.push(`${pad}    - '${item}'`);
          } else {
            lines.push(`${pad}  ${k2}: '${v2}'`);
          }
        }
      } else {
        lines.push(`${pad}${key}: '${val}'`);
      }
    }
    return lines.join('\n');
  }
}
