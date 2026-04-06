// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';

export interface WazuhRule {
  ruleGroup: string;
  ruleId: string;
  techniqueIds: string[];
  description: string;
  level: number;
}

const WAZUH_RULES: WazuhRule[] = [
  // Authentication
  { ruleGroup: 'authentication_failed', ruleId: '5710', techniqueIds: ['T1110', 'T1078'], description: 'Multiple authentication failures', level: 10 },
  { ruleGroup: 'authentication_success', ruleId: '5715', techniqueIds: ['T1078'], description: 'Authentication success after failures', level: 8 },
  { ruleGroup: 'sshd', ruleId: '5712', techniqueIds: ['T1021.004', 'T1110'], description: 'SSH brute force attempt', level: 10 },
  // Malware/Rootkit
  { ruleGroup: 'rootcheck', ruleId: '510', techniqueIds: ['T1014', 'T1547'], description: 'Rootkit detection', level: 12 },
  { ruleGroup: 'syscheck', ruleId: '550', techniqueIds: ['T1565.001', 'T1070'], description: 'File integrity monitoring alert', level: 7 },
  { ruleGroup: 'syscheck_new_entry', ruleId: '554', techniqueIds: ['T1105', 'T1059'], description: 'New file detected', level: 5 },
  { ruleGroup: 'syscheck_deleted', ruleId: '553', techniqueIds: ['T1070.004', 'T1485'], description: 'File deleted', level: 7 },
  // Windows
  { ruleGroup: 'windows_audit', ruleId: '60100', techniqueIds: ['T1059', 'T1059.001'], description: 'PowerShell execution audit', level: 6 },
  { ruleGroup: 'windows_process', ruleId: '61100', techniqueIds: ['T1059', 'T1204.002'], description: 'Suspicious process creation', level: 8 },
  { ruleGroup: 'windows_registry', ruleId: '61600', techniqueIds: ['T1547.001', 'T1112'], description: 'Registry modification', level: 6 },
  { ruleGroup: 'windows_defender', ruleId: '61050', techniqueIds: ['T1562.001'], description: 'Windows Defender disabled', level: 12 },
  { ruleGroup: 'windows_account', ruleId: '60140', techniqueIds: ['T1136', 'T1098'], description: 'Account creation or modification', level: 8 },
  { ruleGroup: 'windows_logon', ruleId: '60106', techniqueIds: ['T1078', 'T1021.001'], description: 'Remote logon detected', level: 4 },
  // Network
  { ruleGroup: 'firewall', ruleId: '4100', techniqueIds: ['T1046', 'T1190'], description: 'Firewall rule triggered', level: 5 },
  { ruleGroup: 'ids', ruleId: '4101', techniqueIds: ['T1190', 'T1595'], description: 'IDS signature match', level: 8 },
  // Web
  { ruleGroup: 'web_attack', ruleId: '31100', techniqueIds: ['T1190', 'T1059.007'], description: 'Web attack detected (SQLi/XSS/RFI)', level: 10 },
  { ruleGroup: 'web_scan', ruleId: '31100', techniqueIds: ['T1595.002', 'T1190'], description: 'Web vulnerability scan detected', level: 6 },
  // Privilege Escalation
  { ruleGroup: 'sudo', ruleId: '5400', techniqueIds: ['T1548.003', 'T1068'], description: 'Sudo abuse detected', level: 8 },
  { ruleGroup: 'pam', ruleId: '5501', techniqueIds: ['T1556', 'T1078'], description: 'PAM authentication event', level: 5 },
  // Docker/Container
  { ruleGroup: 'docker', ruleId: '87900', techniqueIds: ['T1610', 'T1609'], description: 'Docker container activity', level: 5 },
  // Cloud
  { ruleGroup: 'aws_cloudtrail', ruleId: '80200', techniqueIds: ['T1078.004', 'T1087'], description: 'AWS CloudTrail suspicious activity', level: 6 },
  { ruleGroup: 'azure', ruleId: '81300', techniqueIds: ['T1078.004', 'T1098'], description: 'Azure AD suspicious activity', level: 7 },
];

@Injectable({ providedIn: 'root' })
export class WazuhService {
  private byTechnique = new Map<string, WazuhRule[]>();

  constructor() {
    this.buildIndex();
  }

  private buildIndex(): void {
    for (const rule of WAZUH_RULES) {
      for (const tid of rule.techniqueIds) {
        const list = this.byTechnique.get(tid) ?? [];
        list.push(rule);
        this.byTechnique.set(tid, list);
      }
    }
  }

  getRulesForTechnique(attackId: string): WazuhRule[] {
    return this.byTechnique.get(attackId) ?? [];
  }

  getAllRules(): WazuhRule[] {
    return WAZUH_RULES;
  }

  getRulesByGroup(group: string): WazuhRule[] {
    return WAZUH_RULES.filter(r => r.ruleGroup === group);
  }
}
