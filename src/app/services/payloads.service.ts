import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable } from 'rxjs';

export interface PayloadRef {
  title: string;
  url: string;
  category: string;
}

/**
 * Maps PayloadsAllTheThings directory names to ATT&CK technique IDs.
 */
const DIRECTORY_TO_ATTACK: Record<string, string> = {
  'SQL Injection': 'T1190',
  'XSS Injection': 'T1059.007',
  'Command Injection': 'T1059',
  'XXE Injection': 'T1190',
  'SSRF': 'T1190',
  'Server Side Request Forgery': 'T1190',
  'File Inclusion': 'T1059',
  'Directory Traversal': 'T1083',
  'Path Traversal': 'T1083',
  'CSRF Injection': 'T1185',
  'CRLF Injection': 'T1190',
  'LDAP Injection': 'T1190',
  'NoSQL Injection': 'T1190',
  'OAuth': 'T1550',
  'Open Redirect': 'T1204.001',
  'Race Condition': 'T1499.004',
  'Upload Insecure Files': 'T1105',
  'Insecure Deserialization': 'T1190',
  'JWT Security': 'T1550.001',
  'API Key Leaks': 'T1552.001',
  'Methodology and Resources/Active Directory Attack': 'T1484',
  'Windows - Privilege Escalation': 'T1068',
  'Linux - Privilege Escalation': 'T1068',
  'Windows - Persistence': 'T1547',
  'Linux - Persistence': 'T1547',
  'Reverse Shell Cheatsheet': 'T1059',
  'CVE Exploits': 'T1190',
  'Web Sockets': 'T1071.001',
  'GraphQL Injection': 'T1190',
  'SSTI Injection': 'T1190',
  'Type Juggling': 'T1190',
  'Prompt Injection': 'T1059',
  'Mass Assignment': 'T1190',
  'HTTP Parameter Pollution': 'T1190',
  'Account Takeover': 'T1078',
  'DNS Rebinding': 'T1071.004',
  'Prototype Pollution': 'T1059.007',
  'CORS Misconfiguration': 'T1557',
  'Clickjacking': 'T1204.001',
  'LaTeX Injection': 'T1203',
  'CSV Injection': 'T1203',
};

/**
 * Additional keyword-based pattern matching for tree paths
 */
const KEYWORD_PATTERNS: Array<{ pattern: RegExp; attackId: string; category: string }> = [
  { pattern: /sql.?injection/i, attackId: 'T1190', category: 'SQL Injection' },
  { pattern: /xss/i, attackId: 'T1059.007', category: 'XSS' },
  { pattern: /command.?injection/i, attackId: 'T1059', category: 'Command Injection' },
  { pattern: /xxe/i, attackId: 'T1190', category: 'XXE' },
  { pattern: /ssrf/i, attackId: 'T1190', category: 'SSRF' },
  { pattern: /file.?inclusion/i, attackId: 'T1059', category: 'File Inclusion' },
  { pattern: /deserialization/i, attackId: 'T1190', category: 'Deserialization' },
  { pattern: /upload/i, attackId: 'T1105', category: 'File Upload' },
  { pattern: /reverse.?shell/i, attackId: 'T1059', category: 'Reverse Shell' },
  { pattern: /privilege.?escalation/i, attackId: 'T1068', category: 'Privilege Escalation' },
  { pattern: /persistence/i, attackId: 'T1547', category: 'Persistence' },
  { pattern: /ldap/i, attackId: 'T1190', category: 'LDAP Injection' },
  { pattern: /nosql/i, attackId: 'T1190', category: 'NoSQL Injection' },
  { pattern: /active.?directory/i, attackId: 'T1484', category: 'Active Directory' },
  { pattern: /kerberos/i, attackId: 'T1558', category: 'Kerberos' },
  { pattern: /csrf/i, attackId: 'T1185', category: 'CSRF' },
  { pattern: /jwt/i, attackId: 'T1550.001', category: 'JWT' },
  { pattern: /oauth/i, attackId: 'T1550', category: 'OAuth' },
  { pattern: /ssti/i, attackId: 'T1190', category: 'SSTI' },
  { pattern: /graphql/i, attackId: 'T1190', category: 'GraphQL' },
];

const GITHUB_BASE = 'https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master';

@Injectable({ providedIn: 'root' })
export class PayloadsService {
  private payloadMap = new Map<string, PayloadRef[]>();
  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$: Observable<boolean> = this.loadedSubject.asObservable();

  constructor(private http: HttpClient) {
    this.loadPayloads();
  }

  private loadPayloads(): void {
    this.http.get<{ tree: Array<{ path: string; type: string }> }>(
      'https://api.github.com/repos/swisskyrepo/PayloadsAllTheThings/git/trees/master?recursive=1'
    ).subscribe({
      next: (response) => {
        this.buildMap(response.tree || []);
        this.loadedSubject.next(true);
      },
      error: () => {
        // If GitHub API fails (rate limit, etc.), use the static directory mapping
        this.buildStaticMap();
        this.loadedSubject.next(true);
      },
    });
  }

  private buildMap(tree: Array<{ path: string; type: string }>): void {
    // Only look at top-level directories that contain interesting content
    const directories = tree.filter(item => item.type === 'tree');
    const readmeFiles = new Set(
      tree.filter(item => item.type === 'blob' && /README\.md$/i.test(item.path)).map(item => item.path)
    );

    for (const dir of directories) {
      const parts = dir.path.split('/');
      const topDir = parts[0];

      // Try direct directory name match first
      let attackId = DIRECTORY_TO_ATTACK[topDir];
      let category = topDir;

      // Try keyword pattern matching if no direct match
      if (!attackId) {
        for (const kp of KEYWORD_PATTERNS) {
          if (kp.pattern.test(dir.path)) {
            attackId = kp.attackId;
            category = kp.category;
            break;
          }
        }
      }

      if (!attackId) continue;

      // Build the URL — prefer the directory with a README
      const hasReadme = readmeFiles.has(dir.path + '/README.md');
      const url = `${GITHUB_BASE}/${encodeURIComponent(dir.path).replace(/%2F/g, '/')}`;

      const ref: PayloadRef = {
        title: parts[parts.length - 1].replace(/-/g, ' ').replace(/_/g, ' '),
        url: hasReadme ? url : url,
        category,
      };

      const existing = this.payloadMap.get(attackId) || [];
      // Avoid duplicate titles for the same technique
      if (!existing.some(e => e.title === ref.title)) {
        existing.push(ref);
        this.payloadMap.set(attackId, existing);
      }
    }
  }

  private buildStaticMap(): void {
    for (const [dirName, attackId] of Object.entries(DIRECTORY_TO_ATTACK)) {
      const ref: PayloadRef = {
        title: dirName,
        url: `${GITHUB_BASE}/${encodeURIComponent(dirName)}`,
        category: dirName,
      };
      const existing = this.payloadMap.get(attackId) || [];
      existing.push(ref);
      this.payloadMap.set(attackId, existing);
    }
  }

  getPayloadsForTechnique(attackId: string): PayloadRef[] {
    return this.payloadMap.get(attackId) ?? [];
  }

  getPayloadCount(attackId: string): number {
    return (this.payloadMap.get(attackId) ?? []).length;
  }
}
