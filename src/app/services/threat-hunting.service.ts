// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

export interface HuntingQuery {
  title: string;
  tactic: string;
  techniqueId: string;
  platform: string;      // "Defender for Endpoint" or "Microsoft Sentinel"
  url: string;
  source: string;        // "Cyb3r-Monk"
}

/** Maps tactic folder names from the Cyb3r-Monk repo to ATT&CK tactic names */
const TACTIC_FOLDER_MAP: Record<string, string> = {
  'credential access': 'Credential Access',
  'credential-access': 'Credential Access',
  'defense evasion': 'Defense Evasion',
  'defense-evasion': 'Defense Evasion',
  'discovery': 'Discovery',
  'execution': 'Execution',
  'exfiltration': 'Exfiltration',
  'initial access': 'Initial Access',
  'initial-access': 'Initial Access',
  'lateral movement': 'Lateral Movement',
  'lateral-movement': 'Lateral Movement',
  'persistence': 'Persistence',
  'privilege escalation': 'Privilege Escalation',
  'privilege-escalation': 'Privilege Escalation',
  'collection': 'Collection',
  'command and control': 'Command and Control',
  'command-and-control': 'Command and Control',
  'reconnaissance': 'Reconnaissance',
  'resource development': 'Resource Development',
  'resource-development': 'Resource Development',
  'impact': 'Impact',
};

/** Extract technique IDs from a filename or path */
function extractTechniqueIds(path: string): string[] {
  const ids: string[] = [];
  const regex = /T\d{4}(?:\.\d{3})?/gi;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(path)) !== null) {
    ids.push(m[0].toUpperCase());
  }
  return ids;
}

/** Derive tactic from path segments */
function extractTactic(path: string): string {
  const parts = path.split('/').map(p => p.toLowerCase().trim());
  for (const part of parts) {
    if (TACTIC_FOLDER_MAP[part]) return TACTIC_FOLDER_MAP[part];
  }
  return 'Unknown';
}

/** Derive platform from path segments */
function extractPlatform(path: string): string {
  const lower = path.toLowerCase();
  if (lower.includes('defender for endpoint') || lower.includes('mde')) return 'Defender for Endpoint';
  if (lower.includes('sentinel') || lower.includes('microsoft sentinel')) return 'Microsoft Sentinel';
  if (lower.includes('m365') || lower.includes('microsoft 365')) return 'Microsoft 365';
  return 'Defender for Endpoint';
}

/** Simple retry-with-backoff for fetch */
async function retryFetch(url: string, maxRetries = 3): Promise<Response> {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const resp = await fetch(url);
      if (resp.ok) return resp;
      if (resp.status === 403 || resp.status === 429) {
        const wait = Math.pow(2, attempt) * 1000;
        await new Promise(r => setTimeout(r, wait));
        continue;
      }
      throw new Error('HTTP ' + resp.status);
    } catch (e) {
      if (attempt === maxRetries - 1) throw e;
      await new Promise(r => setTimeout(r, Math.pow(2, attempt) * 1000));
    }
  }
  throw new Error('Max retries exceeded');
}

@Injectable({ providedIn: 'root' })
export class ThreatHuntingService {
  private byTechnique = new Map<string, HuntingQuery[]>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$: Observable<boolean> = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  total$: Observable<number> = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  covered$: Observable<number> = this.coveredSubject.asObservable();

  constructor() {
    this.loadQueries();
  }

  private async loadQueries(): Promise<void> {
    try {
      const resp = await retryFetch(
        'https://api.github.com/repos/Cyb3r-Monk/Threat-Hunting-and-Detection/git/trees/main?recursive=1',
      );
      const data: { tree: { path: string; type: string }[] } = await resp.json();

      const queries: HuntingQuery[] = [];

      for (const item of data.tree) {
        if (item.type !== 'blob') continue;
        if (!item.path.endsWith('.kql') && !item.path.endsWith('.md')) continue;

        const techniqueIds = extractTechniqueIds(item.path);
        if (techniqueIds.length === 0) continue;

        const tactic = extractTactic(item.path);
        const platform = extractPlatform(item.path);
        const filename = item.path.split('/').pop() ?? item.path;
        const title = filename
          .replace(/\.kql$/, '')
          .replace(/\.md$/, '')
          .replace(/[-_]/g, ' ')
          .replace(/T\d{4}(?:\.\d{3})?/gi, '')
          .trim() || filename;

        for (const tid of techniqueIds) {
          const query: HuntingQuery = {
            title,
            tactic,
            techniqueId: tid,
            platform,
            url: 'https://github.com/Cyb3r-Monk/Threat-Hunting-and-Detection/blob/main/' + item.path,
            source: 'Cyb3r-Monk',
          };
          queries.push(query);

          const list = this.byTechnique.get(tid) ?? [];
          list.push(query);
          this.byTechnique.set(tid, list);
        }
      }

      this.totalSubject.next(queries.length);
      this.coveredSubject.next(this.byTechnique.size);
      this.loadedSubject.next(true);
    } catch {
      // Silently fail on network errors (GitHub rate limits, etc.)
      this.loadedSubject.next(true);
    }
  }

  getQueriesForTechnique(techniqueId: string): HuntingQuery[] {
    return this.byTechnique.get(techniqueId) ?? [];
  }
}
