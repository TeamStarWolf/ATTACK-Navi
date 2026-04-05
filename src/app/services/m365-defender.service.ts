import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { catchError, of } from 'rxjs';
import { retryWithBackoff } from '../utils/retry';

export interface M365Query {
  title: string;      // filename without extension
  tactic: string;     // parent folder name
  url: string;        // GitHub raw URL
  path: string;       // repo path
}

interface GitHubTree {
  sha: string;
  url: string;
  tree: Array<{
    path: string;
    mode: string;
    type: string;
    sha: string;
    size?: number;
    url: string;
  }>;
  truncated: boolean;
}

/**
 * Map of ATT&CK tactic display names (as used in the Microsoft 365 Defender
 * Hunting Queries repo folder structure) to ATT&CK tactic shortnames used
 * in the MITRE ATT&CK framework.
 */
const TACTIC_FOLDER_MAP: Record<string, string> = {
  'Reconnaissance': 'reconnaissance',
  'Resource Development': 'resource-development',
  'Initial Access': 'initial-access',
  'initial-access': 'initial-access',
  'Execution': 'execution',
  'Persistence': 'persistence',
  'Privilege Escalation': 'privilege-escalation',
  'Defense Evasion': 'defense-evasion',
  'Credential Access': 'credential-access',
  'Discovery': 'discovery',
  'Lateral Movement': 'lateral-movement',
  'Collection': 'collection',
  'Command and Control': 'command-and-control',
  'Exfiltration': 'exfiltration',
  'Impact': 'impact',
  // Common alternate casing/naming
  'Command And Control': 'command-and-control',
  'CredentialAccess': 'credential-access',
  'DefenseEvasion': 'defense-evasion',
  'InitialAccess': 'initial-access',
  'LateralMovement': 'lateral-movement',
  'PrivilegeEscalation': 'privilege-escalation',
  'ResourceDevelopment': 'resource-development',
};

/**
 * Map of ATT&CK tactic shortnames to technique ID prefixes.
 * Used as a fallback when files don't contain explicit technique IDs.
 */
const TACTIC_TECHNIQUE_PREFIXES: Record<string, string[]> = {
  'reconnaissance': ['T1595', 'T1592', 'T1589', 'T1590', 'T1591', 'T1596', 'T1593', 'T1594', 'T1597', 'T1598'],
  'resource-development': ['T1583', 'T1584', 'T1585', 'T1586', 'T1587', 'T1588', 'T1608'],
  'initial-access': ['T1189', 'T1190', 'T1133', 'T1200', 'T1566', 'T1091', 'T1195', 'T1199', 'T1078'],
  'execution': ['T1059', 'T1203', 'T1559', 'T1106', 'T1053', 'T1129', 'T1072', 'T1569', 'T1047', 'T1204'],
  'persistence': ['T1098', 'T1197', 'T1547', 'T1037', 'T1136', 'T1543', 'T1546', 'T1133', 'T1574', 'T1525', 'T1556', 'T1137', 'T1542', 'T1053', 'T1505', 'T1205', 'T1078'],
  'privilege-escalation': ['T1548', 'T1134', 'T1547', 'T1037', 'T1543', 'T1484', 'T1546', 'T1068', 'T1574', 'T1055', 'T1053', 'T1078'],
  'defense-evasion': ['T1548', 'T1134', 'T1197', 'T1140', 'T1006', 'T1484', 'T1480', 'T1211', 'T1222', 'T1564', 'T1574', 'T1562', 'T1036', 'T1556', 'T1578', 'T1112', 'T1601', 'T1599', 'T1027', 'T1542', 'T1055', 'T1207', 'T1014', 'T1218', 'T1216', 'T1553', 'T1221', 'T1205', 'T1127', 'T1535', 'T1550', 'T1078', 'T1497', 'T1600', 'T1220'],
  'credential-access': ['T1557', 'T1110', 'T1555', 'T1212', 'T1187', 'T1606', 'T1056', 'T1556', 'T1111', 'T1621', 'T1040', 'T1003', 'T1528', 'T1558', 'T1539', 'T1552'],
  'discovery': ['T1087', 'T1010', 'T1217', 'T1580', 'T1538', 'T1526', 'T1482', 'T1083', 'T1615', 'T1046', 'T1135', 'T1040', 'T1201', 'T1120', 'T1069', 'T1057', 'T1012', 'T1018', 'T1518', 'T1082', 'T1614', 'T1016', 'T1049', 'T1033', 'T1007', 'T1124', 'T1497'],
  'lateral-movement': ['T1210', 'T1534', 'T1570', 'T1563', 'T1021', 'T1091', 'T1072', 'T1080', 'T1550'],
  'collection': ['T1557', 'T1560', 'T1123', 'T1119', 'T1185', 'T1115', 'T1530', 'T1602', 'T1213', 'T1005', 'T1039', 'T1025', 'T1074', 'T1114', 'T1056', 'T1113', 'T1125'],
  'command-and-control': ['T1071', 'T1092', 'T1132', 'T1001', 'T1568', 'T1573', 'T1008', 'T1105', 'T1104', 'T1095', 'T1571', 'T1572', 'T1090', 'T1219', 'T1205', 'T1102'],
  'exfiltration': ['T1020', 'T1030', 'T1048', 'T1041', 'T1011', 'T1052', 'T1567', 'T1029', 'T1537'],
  'impact': ['T1531', 'T1485', 'T1486', 'T1565', 'T1491', 'T1561', 'T1499', 'T1495', 'T1490', 'T1498', 'T1496', 'T1489', 'T1529'],
};

const GITHUB_TREE_URL =
  'https://api.github.com/repos/microsoft/Microsoft-365-Defender-Hunting-Queries/git/trees/master?recursive=1';

const GITHUB_BLOB_BASE =
  'https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master';

@Injectable({ providedIn: 'root' })
export class M365DefenderService {
  /** Direct mapping: attackId (e.g. 'T1059' or 'T1059.001') -> M365Query[] */
  private queryMap = new Map<string, M365Query[]>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  readonly total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  readonly covered$ = this.coveredSubject.asObservable();

  constructor(private http: HttpClient) {
    this.loadTree();
  }

  // ─── Public API ──────────────────────────────────────────────────────────────

  /** Returns all M365 Defender hunting queries mapped to a technique. */
  getQueriesForTechnique(attackId: string): M365Query[] {
    const direct = this.queryMap.get(attackId) ?? [];
    // Also check parent technique for sub-technique queries
    if (attackId.includes('.')) {
      const parent = attackId.split('.')[0];
      const parentQueries = this.queryMap.get(parent) ?? [];
      return [...direct, ...parentQueries.filter(q => !direct.some(d => d.path === q.path))];
    }
    // For parent technique, also roll up sub-technique queries
    const results = [...direct];
    const prefix = attackId + '.';
    for (const [id, queries] of this.queryMap) {
      if (id.startsWith(prefix)) {
        for (const q of queries) {
          if (!results.some(r => r.path === q.path)) results.push(q);
        }
      }
    }
    return results;
  }

  /** Query count for a technique (with parent rollup), used as heatmap score. */
  getHeatScore(attackId: string): number {
    return this.getQueriesForTechnique(attackId).length;
  }

  // ─── Private ─────────────────────────────────────────────────────────────────

  private loadTree(): void {
    this.http.get<GitHubTree>(GITHUB_TREE_URL)
      .pipe(retryWithBackoff(), catchError(() => of(null)))
      .subscribe(tree => {
        if (tree?.tree?.length) {
          this.parseTree(tree);
        }
        this.loadedSubject.next(true);
      });
  }

  private parseTree(tree: GitHubTree): void {
    const validExtensions = ['.kql', '.md', '.kusto', '.csl'];
    let totalQueries = 0;
    const coveredIds = new Set<string>();

    for (const node of tree.tree) {
      if (node.type !== 'blob') continue;

      const ext = this.getExtension(node.path);
      if (!validExtensions.includes(ext)) continue;

      // Skip root-level README and non-query files
      const parts = node.path.split('/');
      if (parts.length < 2) continue;
      if (node.path.toLowerCase().includes('readme')) continue;

      const folderName = parts[0];
      const fileName = parts[parts.length - 1];
      const title = fileName.replace(/\.(kql|md|kusto|csl)$/i, '').replace(/[-_]/g, ' ');

      // Determine tactic from folder name
      const tacticShortname = TACTIC_FOLDER_MAP[folderName];
      if (!tacticShortname) continue; // Not a recognized tactic folder

      const query: M365Query = {
        title,
        tactic: folderName,
        url: `${GITHUB_BLOB_BASE}/${encodeURI(node.path)}`,
        path: node.path,
      };

      // Extract technique IDs from the filename (e.g. T1059, T1059.001)
      const techIds = this.extractTechniqueIds(node.path);
      totalQueries++;

      if (techIds.length > 0) {
        for (const id of techIds) {
          const existing = this.queryMap.get(id) ?? [];
          existing.push(query);
          this.queryMap.set(id, existing);
          coveredIds.add(id.split('.')[0]); // count parent technique as covered
        }
      } else {
        // No technique ID found -- associate with the tactic's known techniques
        const tacticTechs = TACTIC_TECHNIQUE_PREFIXES[tacticShortname] ?? [];
        for (const techPrefix of tacticTechs) {
          const existing = this.queryMap.get(techPrefix) ?? [];
          // Avoid duplicating the same query file for the same technique
          if (!existing.some(q => q.path === query.path)) {
            existing.push(query);
            this.queryMap.set(techPrefix, existing);
            coveredIds.add(techPrefix);
          }
        }
      }
    }

    this.totalSubject.next(totalQueries);
    this.coveredSubject.next(coveredIds.size);
  }

  /** Extract T-codes from a file path like "Execution/T1059-PowerShell.kql" */
  private extractTechniqueIds(path: string): string[] {
    const ids: string[] = [];
    // Match T followed by 4 digits, optionally .3 digits for sub-technique
    const regex = /T(\d{4})(?:\.(\d{3}))?/g;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(path)) !== null) {
      const id = match[2] ? `T${match[1]}.${match[2]}` : `T${match[1]}`;
      if (!ids.includes(id)) ids.push(id);
    }
    return ids;
  }

  private getExtension(path: string): string {
    const lastDot = path.lastIndexOf('.');
    return lastDot >= 0 ? path.substring(lastDot).toLowerCase() : '';
  }
}
