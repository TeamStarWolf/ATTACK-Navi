// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { of } from 'rxjs';
import { retryWithBackoff } from '../utils/retry';

export interface IoC {
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email' | 'cve';
  value: string;
  source: string;
  techniqueIds: string[];
  date: string;
}

/** Maps IoC types to the ATT&CK techniques they most commonly relate to. */
const IOC_TYPE_TECHNIQUES: Record<IoC['type'], string[]> = {
  ip:     ['T1071.001', 'T1090'],
  domain: ['T1071.001', 'T1583.001'],
  hash:   ['T1204.002', 'T1059'],
  url:    ['T1189', 'T1566.002'],
  email:  ['T1566.001', 'T1598'],
  cve:    [],
};

const MAX_IOCS = 1000;

@Injectable({ providedIn: 'root' })
export class IocFeedService {
  /** stamparm/ipsum level-3 (high confidence) IP blocklist. */
  private static readonly IPSUM_URL =
    'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt';

  private iocs: IoC[] = [];
  private byTechnique = new Map<string, IoC[]>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  total$ = this.totalSubject.asObservable();

  private initialized = false;

  constructor(private http: HttpClient) {}

  /** Trigger data fetch on first use. Safe to call multiple times. */
  loadOnDemand(): void {
    if (this.initialized) return;
    this.initialized = true;
    this.loadFeeds();
  }

  /** Fetch public IP blocklist and index by technique. */
  loadFeeds(): void {
    this.http
      .get(IocFeedService.IPSUM_URL, { responseType: 'text' })
      .pipe(retryWithBackoff(), catchError(() => of('')))
      .subscribe((text) => {
        if (text) this.parseIpsum(text);
        this.rebuildIndex();
        this.totalSubject.next(this.iocs.length);
        this.loadedSubject.next(true);
      });
  }

  /** Parse stamparm/ipsum format: one IP per line, comments start with #. */
  private parseIpsum(raw: string): void {
    const today = new Date().toISOString().slice(0, 10);
    const lines = raw.split('\n');
    for (const line of lines) {
      if (this.iocs.length >= MAX_IOCS) break;
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      // Format: IP<tab>level  (we only need the IP)
      const ip = trimmed.split(/\s+/)[0];
      if (!this.isValidIp(ip)) continue;
      this.iocs.push({
        type: 'ip',
        value: ip,
        source: 'stamparm/ipsum (level 3)',
        techniqueIds: [...IOC_TYPE_TECHNIQUES.ip],
        date: today,
      });
    }
  }

  /** Parse IoC patterns from arbitrary text (IPs, domains, hashes, CVEs). */
  parseIocsFromText(text: string, source: string): IoC[] {
    const found: IoC[] = [];
    const today = new Date().toISOString().slice(0, 10);
    const seen = new Set<string>();

    // IP addresses
    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    for (const match of text.matchAll(ipRegex)) {
      const val = match[0];
      if (!seen.has(val) && this.isValidIp(val)) {
        seen.add(val);
        found.push({ type: 'ip', value: val, source, techniqueIds: [...IOC_TYPE_TECHNIQUES.ip], date: today });
      }
    }

    // MD5 hashes (32 hex)
    const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
    for (const match of text.matchAll(md5Regex)) {
      const val = match[0].toLowerCase();
      if (!seen.has(val)) {
        seen.add(val);
        found.push({ type: 'hash', value: val, source, techniqueIds: [...IOC_TYPE_TECHNIQUES.hash], date: today });
      }
    }

    // SHA-256 hashes (64 hex)
    const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
    for (const match of text.matchAll(sha256Regex)) {
      const val = match[0].toLowerCase();
      if (!seen.has(val)) {
        seen.add(val);
        found.push({ type: 'hash', value: val, source, techniqueIds: [...IOC_TYPE_TECHNIQUES.hash], date: today });
      }
    }

    // CVE IDs
    const cveRegex = /CVE-\d{4}-\d{4,}/gi;
    for (const match of text.matchAll(cveRegex)) {
      const val = match[0].toUpperCase();
      if (!seen.has(val)) {
        seen.add(val);
        found.push({ type: 'cve', value: val, source, techniqueIds: [], date: today });
      }
    }

    // Domains (simple heuristic — word.tld pattern, excluding IPs)
    const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|tk|info|biz|cc|pw|club)\b/gi;
    for (const match of text.matchAll(domainRegex)) {
      const val = match[0].toLowerCase();
      if (!seen.has(val)) {
        seen.add(val);
        found.push({ type: 'domain', value: val, source, techniqueIds: [...IOC_TYPE_TECHNIQUES.domain], date: today });
      }
    }

    return found;
  }

  private isValidIp(ip: string): boolean {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every(p => {
      const n = Number(p);
      return Number.isInteger(n) && n >= 0 && n <= 255;
    });
  }

  private rebuildIndex(): void {
    this.byTechnique.clear();
    for (const ioc of this.iocs) {
      for (const tid of ioc.techniqueIds) {
        const list = this.byTechnique.get(tid) ?? [];
        list.push(ioc);
        this.byTechnique.set(tid, list);
      }
    }
  }

  getIocsForTechnique(attackId: string): IoC[] {
    return this.byTechnique.get(attackId) ?? [];
  }

  getAllIocs(): IoC[] {
    return this.iocs;
  }

  searchIocs(query: string): IoC[] {
    const q = query.toLowerCase();
    return this.iocs.filter(
      (ioc) => ioc.value.toLowerCase().includes(q) || ioc.source.toLowerCase().includes(q),
    );
  }
}
