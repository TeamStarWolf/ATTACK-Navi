import { Injectable } from '@angular/core';
import { Domain } from '../models/domain';
import { ImplementationService, ImplStatus } from './implementation.service';

export interface ComplianceControl {
  controlId: string;
  description: string;
}

export type ComplianceFramework = 'SOC 2' | 'ISO 27001' | 'PCI DSS';

interface FrameworkMapping {
  map: Record<string, string[]>;
  descriptions: Record<string, string>;
}

const SOC2_MAP: Record<string, string[]> = {
  'CC6.1': ['T1078', 'T1110', 'T1556'],
  'CC6.2': ['T1078', 'T1021'],
  'CC6.3': ['T1078', 'T1548'],
  'CC6.6': ['T1190', 'T1133'],
  'CC6.7': ['T1040', 'T1557'],
  'CC6.8': ['T1059', 'T1203', 'T1068'],
  'CC7.1': ['T1190', 'T1189'],
  'CC7.2': ['T1059', 'T1053'],
  'CC7.3': ['T1486', 'T1485'],
  'CC7.4': ['T1486', 'T1490'],
  'CC8.1': ['T1195', 'T1059'],
};

const SOC2_DESCRIPTIONS: Record<string, string> = {
  'CC6.1': 'Logical Access Security',
  'CC6.2': 'Restrict Access Credentials',
  'CC6.3': 'Least Privilege',
  'CC6.6': 'External Threats',
  'CC6.7': 'Transmission Security',
  'CC6.8': 'Malicious Software Prevention',
  'CC7.1': 'Detection/Monitoring',
  'CC7.2': 'Anomaly Detection',
  'CC7.3': 'Incident Response',
  'CC7.4': 'Incident Recovery',
  'CC8.1': 'Change Management',
};

const ISO27001_MAP: Record<string, string[]> = {
  'A.5.15': ['T1078', 'T1548'],
  'A.5.17': ['T1078', 'T1110'],
  'A.8.1':  ['T1078', 'T1087'],
  'A.8.5':  ['T1078', 'T1556'],
  'A.8.7':  ['T1059', 'T1203'],
  'A.8.8':  ['T1190', 'T1068'],
  'A.8.12': ['T1041', 'T1567'],
  'A.8.15': ['T1059', 'T1547'],
  'A.8.16': ['T1190', 'T1189'],
  'A.8.20': ['T1040', 'T1557'],
  'A.8.23': ['T1190', 'T1133'],
  'A.8.24': ['T1573', 'T1040'],
  'A.8.25': ['T1059', 'T1195'],
  'A.8.28': ['T1059', 'T1195'],
};

const ISO27001_DESCRIPTIONS: Record<string, string> = {
  'A.5.15': 'Access Control',
  'A.5.17': 'Authentication',
  'A.8.1':  'User Endpoints',
  'A.8.5':  'Secure Authentication',
  'A.8.7':  'Malware Protection',
  'A.8.8':  'Technical Vulnerabilities',
  'A.8.12': 'Data Leakage Prevention',
  'A.8.15': 'Logging',
  'A.8.16': 'Monitoring',
  'A.8.20': 'Network Security',
  'A.8.23': 'Web Filtering',
  'A.8.24': 'Cryptography',
  'A.8.25': 'SDLC',
  'A.8.28': 'Secure Coding',
};

const PCIDSS_MAP: Record<string, string[]> = {
  '1.2':   ['T1190', 'T1133'],
  '2.2':   ['T1078', 'T1552'],
  '5.2':   ['T1059', 'T1203'],
  '5.3':   ['T1059', 'T1547'],
  '6.2':   ['T1190', 'T1068'],
  '6.3':   ['T1190', 'T1059'],
  '7.2':   ['T1078', 'T1548'],
  '8.3':   ['T1078', 'T1110'],
  '10.2':  ['T1059', 'T1547'],
  '10.4':  ['T1070', 'T1565'],
  '11.3':  ['T1190', 'T1595'],
  '11.4':  ['T1190', 'T1040'],
  '12.10': ['T1486', 'T1485'],
};

const PCIDSS_DESCRIPTIONS: Record<string, string> = {
  '1.2':   'Network Security Controls',
  '2.2':   'Secure Configuration',
  '5.2':   'Malware Protection',
  '5.3':   'Anti-Malware Mechanisms',
  '6.2':   'Secure Development',
  '6.3':   'Security Vulnerabilities',
  '7.2':   'Access Restriction',
  '8.3':   'Strong Authentication',
  '10.2':  'Audit Logging',
  '10.4':  'Log Review',
  '11.3':  'Vulnerability Scanning',
  '11.4':  'Penetration Testing',
  '12.10': 'Incident Response',
};

@Injectable({ providedIn: 'root' })
export class ComplianceMapperService {
  private frameworks: Record<ComplianceFramework, FrameworkMapping> = {
    'SOC 2':     { map: SOC2_MAP,     descriptions: SOC2_DESCRIPTIONS },
    'ISO 27001': { map: ISO27001_MAP, descriptions: ISO27001_DESCRIPTIONS },
    'PCI DSS':   { map: PCIDSS_MAP,   descriptions: PCIDSS_DESCRIPTIONS },
  };

  constructor(private implService: ImplementationService) {}

  getFrameworks(): ComplianceFramework[] {
    return ['SOC 2', 'ISO 27001', 'PCI DSS'];
  }

  getControlsForTechnique(attackId: string, framework: ComplianceFramework): ComplianceControl[] {
    const fw = this.frameworks[framework];
    if (!fw) return [];
    const results: ComplianceControl[] = [];
    for (const [controlId, techIds] of Object.entries(fw.map)) {
      if (techIds.includes(attackId)) {
        results.push({ controlId, description: fw.descriptions[controlId] ?? controlId });
      }
    }
    return results;
  }

  getTechniquesForControl(controlId: string, framework: ComplianceFramework): string[] {
    const fw = this.frameworks[framework];
    if (!fw) return [];
    return fw.map[controlId] ?? [];
  }

  getAllControls(framework: ComplianceFramework): ComplianceControl[] {
    const fw = this.frameworks[framework];
    if (!fw) return [];
    return Object.entries(fw.descriptions).map(([controlId, description]) => ({
      controlId,
      description,
    }));
  }

  generateEvidenceStatement(attackId: string, framework: ComplianceFramework): string {
    const controls = this.getControlsForTechnique(attackId, framework);
    if (controls.length === 0) {
      return `No ${framework} controls are mapped to technique ${attackId}.`;
    }
    const controlList = controls.map(c => c.controlId).join(', ');
    const fw = this.frameworks[framework];
    const techIds = new Set<string>();
    for (const c of controls) {
      for (const t of (fw.map[c.controlId] ?? [])) techIds.add(t);
    }
    return `Control${controls.length > 1 ? 's' : ''} ${controlList} ${controls.length > 1 ? 'are' : 'is'} addressed by implementing mitigations for techniques ${[...techIds].join(', ')}`;
  }

  getControlStatus(controlId: string, framework: ComplianceFramework, domain: Domain): ImplStatus | null {
    const techIds = this.getTechniquesForControl(controlId, framework);
    if (techIds.length === 0) return null;
    const statuses: (ImplStatus | null)[] = [];
    for (const attackId of techIds) {
      const tech = domain.techniques.find(t => t.attackId === attackId);
      if (!tech) continue;
      const mits = domain.mitigationsByTechnique.get(tech.id) ?? [];
      for (const rel of mits) {
        statuses.push(this.implService.getStatus(rel.mitigation.id));
      }
    }
    if (statuses.length === 0) return null;
    if (statuses.every(s => s === 'implemented')) return 'implemented';
    if (statuses.some(s => s === 'implemented' || s === 'in-progress')) return 'in-progress';
    if (statuses.some(s => s === 'planned')) return 'planned';
    return 'not-started';
  }

  exportComplianceReport(framework: ComplianceFramework, domain: Domain): string {
    const fw = this.frameworks[framework];
    if (!fw) return '';
    const rows: string[] = ['Control ID,Control Description,ATT&CK Techniques,Implementation Status'];
    for (const [controlId, description] of Object.entries(fw.descriptions)) {
      const techIds = fw.map[controlId] ?? [];
      const status = this.getControlStatus(controlId, framework, domain);
      const statusLabel = status ?? 'Unknown';
      rows.push(`"${controlId}","${description}","${techIds.join('; ')}","${statusLabel}"`);
    }
    return rows.join('\n');
  }
}
