// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { AttackCveService } from './attack-cve.service';
import { CveService } from './cve.service';
import { EpssService } from './epss.service';

export interface Asset {
  id: string;
  hostname: string;
  os: string;
  software: string[];
  cpes: string[];
  tags: string[];
  criticality: 'critical' | 'high' | 'medium' | 'low';
  addedAt: string;
}

export interface AssetExposure {
  asset: Asset;
  cveId: string;
  attackIds: string[];
  epssScore: number | null;
  isKev: boolean;
  cvssScore: number | null;
}

/** Known vendor/product heuristics for CPE generation */
const SOFTWARE_CPE_MAP: Record<string, { vendor: string; product: string }> = {
  'apache': { vendor: 'apache', product: 'http_server' },
  'httpd': { vendor: 'apache', product: 'http_server' },
  'nginx': { vendor: 'f5', product: 'nginx' },
  'openssl': { vendor: 'openssl', product: 'openssl' },
  'openssh': { vendor: 'openbsd', product: 'openssh' },
  'log4j': { vendor: 'apache', product: 'log4j' },
  'tomcat': { vendor: 'apache', product: 'tomcat' },
  'mysql': { vendor: 'oracle', product: 'mysql' },
  'postgres': { vendor: 'postgresql', product: 'postgresql' },
  'postgresql': { vendor: 'postgresql', product: 'postgresql' },
  'redis': { vendor: 'redis', product: 'redis' },
  'mongodb': { vendor: 'mongodb', product: 'mongodb' },
  'elasticsearch': { vendor: 'elastic', product: 'elasticsearch' },
  'kibana': { vendor: 'elastic', product: 'kibana' },
  'docker': { vendor: 'docker', product: 'docker' },
  'kubernetes': { vendor: 'kubernetes', product: 'kubernetes' },
  'jenkins': { vendor: 'jenkins', product: 'jenkins' },
  'gitlab': { vendor: 'gitlab', product: 'gitlab' },
  'php': { vendor: 'php', product: 'php' },
  'python': { vendor: 'python', product: 'python' },
  'node': { vendor: 'nodejs', product: 'node.js' },
  'nodejs': { vendor: 'nodejs', product: 'node.js' },
  'java': { vendor: 'oracle', product: 'jdk' },
  'jdk': { vendor: 'oracle', product: 'jdk' },
  'jre': { vendor: 'oracle', product: 'jre' },
  'iis': { vendor: 'microsoft', product: 'internet_information_services' },
  'exchange': { vendor: 'microsoft', product: 'exchange_server' },
  'sharepoint': { vendor: 'microsoft', product: 'sharepoint_server' },
  'wordpress': { vendor: 'wordpress', product: 'wordpress' },
  'drupal': { vendor: 'drupal', product: 'drupal' },
  'joomla': { vendor: 'joomla', product: 'joomla\\!' },
  'spring': { vendor: 'vmware', product: 'spring_framework' },
  'struts': { vendor: 'apache', product: 'struts' },
  'curl': { vendor: 'haxx', product: 'curl' },
  'bind': { vendor: 'isc', product: 'bind' },
  'grafana': { vendor: 'grafana', product: 'grafana' },
  'prometheus': { vendor: 'prometheus', product: 'prometheus' },
  'rabbitmq': { vendor: 'vmware', product: 'rabbitmq' },
  'kafka': { vendor: 'apache', product: 'kafka' },
  'zookeeper': { vendor: 'apache', product: 'zookeeper' },
  'vault': { vendor: 'hashicorp', product: 'vault' },
  'terraform': { vendor: 'hashicorp', product: 'terraform' },
  'ansible': { vendor: 'redhat', product: 'ansible' },
  'puppet': { vendor: 'puppet', product: 'puppet' },
  'squid': { vendor: 'squid-cache', product: 'squid' },
  'haproxy': { vendor: 'haproxy', product: 'haproxy' },
  'varnish': { vendor: 'varnish-software', product: 'varnish_cache' },
  'memcached': { vendor: 'memcached', product: 'memcached' },
  'samba': { vendor: 'samba', product: 'samba' },
};

/** OS-level CPE mapping */
const OS_CPE_MAP: Record<string, { vendor: string; product: string }> = {
  'windows': { vendor: 'microsoft', product: 'windows' },
  'ubuntu': { vendor: 'canonical', product: 'ubuntu_linux' },
  'debian': { vendor: 'debian', product: 'debian_linux' },
  'centos': { vendor: 'centos', product: 'centos' },
  'rhel': { vendor: 'redhat', product: 'enterprise_linux' },
  'red hat': { vendor: 'redhat', product: 'enterprise_linux' },
  'fedora': { vendor: 'fedoraproject', product: 'fedora' },
  'suse': { vendor: 'suse', product: 'linux_enterprise_server' },
  'macos': { vendor: 'apple', product: 'macos' },
  'mac os': { vendor: 'apple', product: 'macos' },
  'freebsd': { vendor: 'freebsd', product: 'freebsd' },
  'alpine': { vendor: 'alpinelinux', product: 'alpine_linux' },
  'amazon linux': { vendor: 'amazon', product: 'linux' },
  'oracle linux': { vendor: 'oracle', product: 'linux' },
};

const STORAGE_KEY = 'mitre-nav-assets-v1';

@Injectable({ providedIn: 'root' })
export class AssetInventoryService {
  private assetsSubject = new BehaviorSubject<Asset[]>([]);
  private countSubject = new BehaviorSubject<number>(0);
  private exposureMapSubject = new BehaviorSubject<Map<string, number>>(new Map());

  assets$: Observable<Asset[]> = this.assetsSubject.asObservable();
  count$: Observable<number> = this.countSubject.asObservable();
  exposureMap$: Observable<Map<string, number>> = this.exposureMapSubject.asObservable();

  constructor(
    private attackCveService: AttackCveService,
    private cveService: CveService,
    private epssService: EpssService,
  ) {
    this.loadFromStorage();
  }

  // ── CRUD ────────────────────────────────────────────────

  addAsset(partial: Partial<Asset>): Asset {
    const asset: Asset = {
      id: this.uuid(),
      hostname: partial.hostname ?? 'unknown',
      os: partial.os ?? '',
      software: partial.software ?? [],
      cpes: [],
      tags: partial.tags ?? [],
      criticality: partial.criticality ?? 'medium',
      addedAt: new Date().toISOString(),
    };
    asset.cpes = this.generateCpes(asset);
    const current = this.assetsSubject.value;
    const next = [...current, asset];
    this.assetsSubject.next(next);
    this.countSubject.next(next.length);
    this.saveToStorage(next);
    this.recomputeExposure(next);
    return asset;
  }

  removeAsset(id: string): void {
    const next = this.assetsSubject.value.filter(a => a.id !== id);
    this.assetsSubject.next(next);
    this.countSubject.next(next.length);
    this.saveToStorage(next);
    this.recomputeExposure(next);
  }

  getAll(): Asset[] {
    return this.assetsSubject.value;
  }

  clearAll(): void {
    this.assetsSubject.next([]);
    this.countSubject.next(0);
    this.exposureMapSubject.next(new Map());
    this.saveToStorage([]);
  }

  // ── CSV import / export ─────────────────────────────────

  importCsv(csvText: string): Asset[] {
    const lines = csvText.replace(/\r/g, '').split('\n');
    if (lines.length < 2) return [];

    const header = lines[0].toLowerCase().split(',').map(h => h.trim());
    const hostnameIdx = header.indexOf('hostname');
    const osIdx = header.indexOf('os');
    const softwareIdx = header.indexOf('software');
    const tagsIdx = header.indexOf('tags');
    const criticalityIdx = header.indexOf('criticality');

    if (hostnameIdx < 0) return [];

    const imported: Asset[] = [];

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      const cols = this.parseCsvLine(line);

      const hostname = cols[hostnameIdx]?.trim() ?? '';
      if (!hostname) continue;

      const os = cols[osIdx]?.trim() ?? '';
      const software = (cols[softwareIdx] ?? '')
        .split(';')
        .map(s => s.trim())
        .filter(Boolean);
      const tags = (cols[tagsIdx] ?? '')
        .split(';')
        .map(s => s.trim())
        .filter(Boolean);
      const crit = (cols[criticalityIdx]?.trim().toLowerCase() ?? 'medium') as Asset['criticality'];
      const criticality = ['critical', 'high', 'medium', 'low'].includes(crit) ? crit : 'medium';

      const asset = this.addAsset({ hostname, os, software, tags, criticality });
      imported.push(asset);
    }

    return imported;
  }

  exportCsv(): string {
    const assets = this.assetsSubject.value;
    const lines = ['hostname,os,software,tags,criticality'];
    for (const a of assets) {
      const sw = a.software.join(';');
      const tg = a.tags.join(';');
      lines.push(`"${a.hostname}","${a.os}","${sw}","${tg}","${a.criticality}"`);
    }
    return lines.join('\n');
  }

  // ── CPE generation ──────────────────────────────────────

  generateCpes(asset: Asset): string[] {
    const cpes: string[] = [];

    // OS CPE
    if (asset.os) {
      const osLower = asset.os.toLowerCase();
      const version = asset.os.match(/[\d]+(?:\.[\d]+)*/)?.[0] ?? '*';
      for (const [key, mapping] of Object.entries(OS_CPE_MAP)) {
        if (osLower.includes(key)) {
          cpes.push(`cpe:2.3:o:${mapping.vendor}:${mapping.product}:${version}:*:*:*:*:*:*:*`);
          break;
        }
      }
    }

    // Software CPEs
    for (const sw of asset.software) {
      const cpe = this.softwareToCpe(sw);
      if (cpe) cpes.push(cpe);
    }

    return cpes;
  }

  private softwareToCpe(software: string): string | null {
    const normalized = software.trim();
    if (!normalized) return null;

    // Try to split "Product Version" pattern
    const match = normalized.match(/^(.+?)\s+([\d]+(?:\.[\d]+)*)(.*)$/);
    let productName: string;
    let version: string;

    if (match) {
      productName = match[1].trim();
      version = match[2];
    } else {
      productName = normalized;
      version = '*';
    }

    const productLower = productName.toLowerCase().replace(/[^a-z0-9]/g, '');

    // Look up in known mappings
    for (const [key, mapping] of Object.entries(SOFTWARE_CPE_MAP)) {
      if (productLower.includes(key) || key.includes(productLower)) {
        return `cpe:2.3:a:${mapping.vendor}:${mapping.product}:${version}:*:*:*:*:*:*:*`;
      }
    }

    // Heuristic fallback: use product name as both vendor and product
    const vendor = productLower.replace(/\s+/g, '_') || 'unknown';
    const product = productLower.replace(/\s+/g, '_') || 'unknown';
    return `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;
  }

  // ── Exposure computation ────────────────────────────────

  computeExposure(assets: Asset[]): Map<string, number> {
    const techniqueExposure = new Map<string, number>();

    for (const asset of assets) {
      // Get all software keywords from the asset
      const keywords = this.extractKeywords(asset);

      // Find CVEs via AttackCveService by iterating technique mappings
      const matchedTechniqueIds = new Set<string>();

      // For each keyword, check if any CVE descriptions or IDs relate
      // We use the technique->CVE mappings and match CPE-like patterns
      for (const keyword of keywords) {
        // Search through all mapped techniques for related CVEs
        // This is a heuristic: map software names to the techniques
        // their known CVEs affect
        this.findTechniquesForSoftware(keyword, matchedTechniqueIds);
      }

      // Increment exposure count for each matched technique
      for (const techId of matchedTechniqueIds) {
        techniqueExposure.set(techId, (techniqueExposure.get(techId) ?? 0) + 1);
      }
    }

    return techniqueExposure;
  }

  /** Get detailed per-asset exposure entries for display */
  getExposureDetails(assets: Asset[]): AssetExposure[] {
    const details: AssetExposure[] = [];

    for (const asset of assets) {
      const keywords = this.extractKeywords(asset);
      const seenCves = new Set<string>();

      for (const keyword of keywords) {
        const cveIds = this.findCvesForSoftware(keyword);
        for (const cveId of cveIds) {
          if (seenCves.has(cveId)) continue;
          seenCves.add(cveId);

          const mapping = this.attackCveService.getMappingForCve(cveId);
          if (!mapping) continue;

          const attackIds = [
            ...new Set([
              ...mapping.primaryImpact,
              ...mapping.secondaryImpact,
              ...mapping.exploitationTechnique,
            ]),
          ];

          details.push({
            asset,
            cveId,
            attackIds,
            epssScore: null, // Will be enriched asynchronously
            isKev: this.cveService.isKev(cveId),
            cvssScore: null,
          });
        }
      }
    }

    return details;
  }

  /** Recompute exposure map and emit to subscribers */
  recomputeExposure(assets?: Asset[]): void {
    const all = assets ?? this.assetsSubject.value;
    const exposureMap = this.computeExposure(all);
    this.exposureMapSubject.next(exposureMap);
  }

  // ── Private helpers ─────────────────────────────────────

  private findTechniquesForSoftware(keyword: string, result: Set<string>): void {
    const lower = keyword.toLowerCase();

    // Heuristic mapping: software name -> commonly exploited ATT&CK techniques.
    // This is keyword-based and approximate. For precise CVE-to-asset matching,
    // import a vulnerability scan report with CPE data.
    const softwareTechMap: Record<string, string[]> = {
      // Web servers
      'log4j': ['T1190', 'T1059', 'T1059.004', 'T1105', 'T1071.001'],
      'apache': ['T1190', 'T1505.003', 'T1059'],
      'nginx': ['T1190', 'T1505.003'],
      'tomcat': ['T1190', 'T1059'],
      'iis': ['T1190', 'T1505.003'],
      // Microsoft ecosystem
      'exchange': ['T1190', 'T1078'],
      'sharepoint': ['T1190', 'T1213'],
      'office': ['T1204.002', 'T1566.001'],
      'outlook': ['T1566', 'T1204'],
      'teams': ['T1566', 'T1204'],
      'edge': ['T1189', 'T1203'],
      // Databases
      'mysql': ['T1190', 'T1059'],
      'postgres': ['T1190', 'T1059'],
      'postgresql': ['T1190', 'T1059'],
      'redis': ['T1190'],
      'mongodb': ['T1190'],
      'elasticsearch': ['T1190', 'T1005'],
      // CI/CD & DevOps
      'jenkins': ['T1190', 'T1059'],
      'gitlab': ['T1190', 'T1213'],
      'docker': ['T1610', 'T1609'],
      'kubernetes': ['T1610', 'T1609'],
      // Collaboration & Productivity
      'jira': ['T1190', 'T1213'],
      'confluence': ['T1190', 'T1213'],
      'grafana': ['T1190'],
      'zoom': ['T1204', 'T1566'],
      // Browsers
      'chrome': ['T1189', 'T1203'],
      'firefox': ['T1189', 'T1203'],
      // CMS
      'wordpress': ['T1190'],
      'drupal': ['T1190'],
      // Languages & runtimes
      'java': ['T1190', 'T1203'],
      'python': ['T1059.006'],
      'node': ['T1059.007'],
      'nodejs': ['T1059.007'],
      'php': ['T1190', 'T1059'],
      // VPN / Network infrastructure
      'vmware': ['T1190', 'T1021'],
      'citrix': ['T1190', 'T1133'],
      'fortinet': ['T1190', 'T1133'],
      'paloalto': ['T1190'],
      'cisco': ['T1190', 'T1133'],
      // Supply chain
      'solarwinds': ['T1195.002'],
      // Crypto & Auth
      'openssl': ['T1573', 'T1040', 'T1557'],
      'openssh': ['T1021.004', 'T1078', 'T1110'],
      'vault': ['T1078', 'T1552'],
      // Document / PDF
      'adobe reader': ['T1203', 'T1204.002'],
      'acrobat': ['T1203', 'T1204.002'],
      // Frameworks
      'spring': ['T1190', 'T1059'],
      'struts': ['T1190', 'T1059'],
      // Other infrastructure
      'samba': ['T1021.002', 'T1210'],
      'bind': ['T1190', 'T1584.002'],
      'curl': ['T1105', 'T1071.001'],
      'rabbitmq': ['T1190'],
      'kafka': ['T1190'],
      'haproxy': ['T1190'],
      'squid': ['T1190'],
    };

    // Check direct keyword match
    for (const [sw, techs] of Object.entries(softwareTechMap)) {
      if (lower.includes(sw)) {
        for (const t of techs) result.add(t);
      }
    }

    // Also check CTID-curated CVE mappings for software name mentions
    const allMappings = this.attackCveService.getAllCtidMappings();
    const swFirstWord = lower.split(' ')[0];
    if (swFirstWord.length >= 3) { // Avoid matching very short keywords
      for (const mapping of allMappings) {
        if (mapping.description?.toLowerCase().includes(swFirstWord)) {
          for (const techId of [...mapping.primaryImpact, ...mapping.secondaryImpact, ...mapping.exploitationTechnique]) {
            result.add(techId);
          }
        }
      }
    }
  }

  private findCvesForSoftware(keyword: string): string[] {
    // Use the software->technique->CVE chain.
    // First, find technique IDs for this keyword using the shared heuristic method,
    // then look up CVEs mapped to those techniques.
    const matchedTechniqueIds = new Set<string>();
    this.findTechniquesForSoftware(keyword, matchedTechniqueIds);

    const cveIds: string[] = [];
    for (const techId of matchedTechniqueIds) {
      const mappings = this.attackCveService.getCvesForTechnique(techId);
      for (const m of mappings) {
        if (!cveIds.includes(m.cveId)) cveIds.push(m.cveId);
      }
    }

    return cveIds.slice(0, 50); // Limit for performance
  }

  private extractKeywords(asset: Asset): string[] {
    const keywords: string[] = [];

    // Extract keywords from software names
    for (const sw of asset.software) {
      const name = sw.replace(/[\d.]+/g, '').trim().toLowerCase();
      if (name) keywords.push(name);
      // Also push the full name for exact matching
      keywords.push(sw.toLowerCase());
    }

    // Extract from OS
    if (asset.os) {
      const osName = asset.os.replace(/[\d.]+/g, '').trim().toLowerCase();
      if (osName) keywords.push(osName);
    }

    return [...new Set(keywords)];
  }

  private parseCsvLine(line: string): string[] {
    const result: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (ch === ',' && !inQuotes) {
        result.push(current);
        current = '';
      } else {
        current += ch;
      }
    }
    result.push(current);
    return result;
  }

  private uuid(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
  }

  private saveToStorage(assets: Asset[]): void {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(assets));
    } catch { /* quota exceeded */ }
  }

  private loadFromStorage(): void {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const assets: Asset[] = JSON.parse(raw);
        this.assetsSubject.next(assets);
        this.countSubject.next(assets.length);
        // Defer exposure computation to let other services load
        setTimeout(() => this.recomputeExposure(assets), 2000);
      }
    } catch { /* corrupted data */ }
  }
}
