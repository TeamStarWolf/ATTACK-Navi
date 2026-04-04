import { Injectable } from '@angular/core';

export interface EngageActivity {
  id: string;           // e.g., "EAC0002"
  name: string;
  category: 'Prepare' | 'Expose' | 'Affect' | 'Elicit' | 'Understand';
  definition: string;
  url: string;
  attackIds: string[];  // ATT&CK technique IDs this activity targets
}

const ENGAGE_ACTIVITIES: EngageActivity[] = [
  // Expose Operations — learn about adversary
  { id: 'EAC0001', name: 'API Monitoring', category: 'Expose', definition: 'Monitoring API calls to detect adversary tool activity and tradecraft.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1059', 'T1055', 'T1106', 'T1047'] },
  { id: 'EAC0002', name: 'Behavioral Analytics', category: 'Expose', definition: 'Using behavioral detection to identify adversary activity based on actions, not signatures.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1059', 'T1078', 'T1055', 'T1021', 'T1071'] },
  { id: 'EAC0004', name: 'Network Monitoring', category: 'Expose', definition: 'Capturing and analyzing network traffic to detect adversary C2 and exfiltration.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1071', 'T1041', 'T1095', 'T1046', 'T1040', 'T1572'] },
  { id: 'EAC0005', name: 'Software Manipulation', category: 'Expose', definition: 'Altering software behavior to reveal adversary interaction with a system.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1195', 'T1554', 'T1574'] },
  { id: 'EAC0014', name: 'System Activity Monitoring', category: 'Expose', definition: 'Collecting system telemetry to track adversary host-based activity.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1059', 'T1078', 'T1021', 'T1053', 'T1543', 'T1547'] },
  { id: 'EAC0015', name: 'Email Monitoring', category: 'Expose', definition: 'Monitoring email communications for phishing and adversary use of email infrastructure.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1566', 'T1598', 'T1534', 'T1114'] },
  // Affect Operations — degrade adversary capability
  { id: 'EAC0003', name: 'Burn-In', category: 'Affect', definition: 'Operating a deception environment long-term to build adversary confidence before disruption.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1204', 'T1566', 'T1059'] },
  { id: 'EAC0007', name: 'Disruption', category: 'Affect', definition: 'Interrupting adversary operations to prevent achievement of objectives.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1485', 'T1490', 'T1489'] },
  { id: 'EAC0008', name: 'Isolation', category: 'Affect', definition: 'Containing adversary access to limit lateral movement and impact.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1021', 'T1570', 'T1534', 'T1080'] },
  { id: 'EAC0009', name: 'Malware Detonation', category: 'Affect', definition: 'Executing adversary malware in a controlled environment to study behavior.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1204', 'T1059', 'T1027', 'T1566.001'] },
  { id: 'EAC0018', name: 'Peripheral Management', category: 'Affect', definition: 'Controlling physical I/O devices to prevent unauthorized data transfer.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1091', 'T1052', 'T1200'] },
  // Elicit — draw out adversary TTPs
  { id: 'EAC0016', name: 'Pocket Litter', category: 'Elicit', definition: 'Placing realistic but fake artifacts (documents, credentials, configs) to attract adversary interaction.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1082', 'T1083', 'T1005', 'T1213'] },
  { id: 'EAC0017', name: 'Honey Credentials', category: 'Elicit', definition: 'Deploying fake credentials to detect unauthorized access attempts.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1078', 'T1003', 'T1552', 'T1110'] },
  { id: 'EAC0021', name: 'Lures', category: 'Elicit', definition: 'Presenting enticing artifacts to direct adversary toward monitored deception environments.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1204', 'T1566', 'T1598'] },
  // Prepare — set conditions
  { id: 'EAC0010', name: 'Network Diversity', category: 'Prepare', definition: 'Varying network configurations to complicate adversary lateral movement planning.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1046', 'T1018', 'T1016'] },
  { id: 'EAC0011', name: 'Baseline', category: 'Prepare', definition: 'Establishing normal activity baselines to detect deviations caused by adversary activity.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1059', 'T1078', 'T1021', 'T1071'] },
  { id: 'EAC0022', name: 'Attack Vector Migration', category: 'Prepare', definition: 'Moving critical assets away from anticipated adversary attack paths.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1190', 'T1133', 'T1566'] },
  // Understand — analyze engagement outcomes
  { id: 'EAC0019', name: 'Threat Intelligence Collection', category: 'Understand', definition: 'Collecting indicators and TTP data from adversary engagement for future defense.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1059', 'T1071', 'T1041', 'T1055', 'T1078'] },
  { id: 'EAC0020', name: 'Adversary Capability Analysis', category: 'Understand', definition: 'Analyzing adversary tools and techniques observed during the engagement.', url: 'https://engage.mitre.org/matrix/', attackIds: ['T1027', 'T1059', 'T1055', 'T1562'] },
];

@Injectable({ providedIn: 'root' })
export class EngageService {
  private byAttackId = new Map<string, EngageActivity[]>();

  constructor() {
    for (const act of ENGAGE_ACTIVITIES) {
      for (const id of act.attackIds) {
        if (!this.byAttackId.has(id)) this.byAttackId.set(id, []);
        this.byAttackId.get(id)!.push(act);
      }
    }
  }

  getActivities(attackId: string): EngageActivity[] {
    const direct = this.byAttackId.get(attackId) ?? [];
    const parentId = attackId.includes('.') ? attackId.split('.')[0] : null;
    const parent = parentId ? (this.byAttackId.get(parentId) ?? []) : [];
    return [...direct, ...parent.filter(p => !direct.some(d => d.id === p.id))];
  }
}
