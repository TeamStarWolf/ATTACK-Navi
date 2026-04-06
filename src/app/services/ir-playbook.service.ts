// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { Technique } from '../models/technique';
import { Domain } from '../models/domain';
import { SigmaService } from './sigma.service';
import { ElasticService } from './elastic.service';

export interface PlaybookStep {
  phase: 'identify' | 'contain' | 'eradicate' | 'recover' | 'lessons';
  action: string;
  details: string;
  tools: string[];
  commands: string[];
  logSources: string[];
  automatable: boolean;
}

export interface IRPlaybook {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  summary: string;
  steps: PlaybookStep[];
  indicators: string[];
  relatedTechniques: string[];
}

const TACTIC_ORDER = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
];

// Response patterns by tactic
const TACTIC_RESPONSES: Record<string, { contain: string[]; eradicate: string[]; recover: string[] }> = {
  'initial-access': {
    contain: ['Block source IP/domain at perimeter firewall', 'Quarantine affected endpoint', 'Disable compromised user account'],
    eradicate: ['Remove malicious email/attachment', 'Patch exploited vulnerability', 'Update email filtering rules'],
    recover: ['Re-enable account with new credentials', 'Verify no lateral movement occurred', 'Update IDS/IPS signatures'],
  },
  'execution': {
    contain: ['Terminate malicious process', 'Isolate host from network', 'Block script interpreter if possible'],
    eradicate: ['Scan for dropped payloads', 'Remove malicious scripts/binaries', 'Check for scheduled tasks/services'],
    recover: ['Rebuild if rootkit suspected', 'Restore from known-good backup', 'Verify process integrity'],
  },
  'persistence': {
    contain: ['Disable auto-start entries', 'Remove scheduled tasks', 'Block persistence mechanism'],
    eradicate: ['Clean registry run keys', 'Remove implanted services', 'Delete web shells', 'Remove unauthorized accounts'],
    recover: ['Audit all persistence locations', 'Harden startup configurations', 'Implement application whitelisting'],
  },
  'privilege-escalation': {
    contain: ['Revoke elevated tokens', 'Disable compromised privileged account', 'Apply emergency patches'],
    eradicate: ['Patch vulnerable service', 'Remove exploit artifacts', 'Reset service account credentials'],
    recover: ['Audit all privileged accounts', 'Implement least privilege', 'Enable PAM/PIM monitoring'],
  },
  'defense-evasion': {
    contain: ['Re-enable disabled security tools', 'Restore tampered logs', 'Block evasion tool hashes'],
    eradicate: ['Remove rootkits/packers', 'Restore security configurations', 'Re-enable logging'],
    recover: ['Validate security tool integrity', 'Verify log completeness', 'Update detection rules for evasion variant'],
  },
  'credential-access': {
    contain: ['Force password reset for affected accounts', 'Disable NTLM where possible', 'Revoke active sessions'],
    eradicate: ['Rotate all compromised credentials', 'Reset Kerberos KRBTGT twice', 'Remove credential dumping tools'],
    recover: ['Implement MFA on all accounts', 'Deploy credential guard', 'Audit service account usage'],
  },
  'discovery': {
    contain: ['Monitor for follow-up actions', 'Restrict network reconnaissance tools', 'Enable enhanced logging'],
    eradicate: ['Remove enumeration tools', 'Block unauthorized scanning', 'Review accessed directories'],
    recover: ['Reduce information exposure', 'Segment sensitive networks', 'Implement need-to-know access'],
  },
  'lateral-movement': {
    contain: ['Isolate affected network segment', 'Disable remote services on compromised hosts', 'Block lateral protocols (SMB/RDP/WinRM)'],
    eradicate: ['Audit all systems accessed from compromised host', 'Remove implants from lateral targets', 'Reset credentials used for movement'],
    recover: ['Re-segment network', 'Implement jump servers', 'Enable lateral movement detection rules'],
  },
  'collection': {
    contain: ['Block data staging locations', 'Disable unauthorized archive tools', 'Monitor file access patterns'],
    eradicate: ['Remove staging directories', 'Delete unauthorized archives', 'Identify scope of collected data'],
    recover: ['Assess data exposure', 'Notify affected parties if PII involved', 'Implement DLP controls'],
  },
  'command-and-control': {
    contain: ['Block C2 domains/IPs at DNS and firewall', 'Sinkhole C2 domains', 'Isolate beaconing hosts'],
    eradicate: ['Remove C2 implants', 'Clean DNS cache', 'Block C2 protocol patterns'],
    recover: ['Update threat intel feeds', 'Add C2 indicators to blocklists', 'Monitor for fallback C2 channels'],
  },
  'exfiltration': {
    contain: ['Block outbound to exfil destination', 'Throttle/block large outbound transfers', 'Disable cloud sync tools'],
    eradicate: ['Identify all exfiltrated data', 'Remove exfiltration tools/scripts', 'Close unauthorized channels'],
    recover: ['Assess data breach scope', 'Initiate breach notification if required', 'Implement egress filtering'],
  },
  'impact': {
    contain: ['Isolate affected systems immediately', 'Activate business continuity plan', 'Preserve forensic evidence'],
    eradicate: ['Remove ransomware/wiper', 'Identify encryption keys if possible', 'Patch entry vector'],
    recover: ['Restore from offline backups', 'Rebuild affected systems', 'Validate data integrity'],
  },
};

@Injectable({ providedIn: 'root' })
export class IRPlaybookService {

  constructor(
    private sigmaService: SigmaService,
    private elasticService: ElasticService,
  ) {}

  generatePlaybook(technique: Technique, domain: Domain): IRPlaybook {
    const tactic = technique.tacticShortnames?.[0] || 'execution';
    const responses = TACTIC_RESPONSES[tactic] || TACTIC_RESPONSES['execution'];
    const severity = this.computeSeverity(technique, domain);
    const dataSources = technique.dataSources || [];
    const logSources = this.mapToLogSources(dataSources);
    const hasSigma = this.sigmaService.getRuleCount(technique.attackId) > 0;
    const hasElastic = this.elasticService.getRuleCount(technique.attackId) > 0;

    const steps: PlaybookStep[] = [];

    // Phase 1: Identify
    steps.push({
      phase: 'identify',
      action: `Detect ${technique.name} activity`,
      details: `Monitor for indicators of ${technique.name} (${technique.attackId}). ${technique.detectionText ? technique.detectionText.substring(0, 200) : 'Review ATT&CK detection guidance for this technique.'}`,
      tools: ['SIEM', hasSigma ? 'Sigma Rules' : '', hasElastic ? 'Elastic Detection Rules' : '', 'EDR'].filter(Boolean),
      commands: this.getDetectionCommands(technique, tactic),
      logSources,
      automatable: hasSigma || hasElastic,
    });

    // Phase 2: Contain
    for (const action of responses.contain) {
      steps.push({
        phase: 'contain',
        action,
        details: `Immediate containment action for ${tactic.replace(/-/g, ' ')} activity.`,
        tools: this.getContainmentTools(tactic),
        commands: this.getContainmentCommands(tactic, action),
        logSources: [],
        automatable: action.includes('Block') || action.includes('Disable'),
      });
    }

    // Phase 3: Eradicate
    for (const action of responses.eradicate) {
      steps.push({
        phase: 'eradicate',
        action,
        details: `Remove threat artifacts related to ${technique.name}.`,
        tools: this.getEradicationTools(tactic),
        commands: this.getEradicationCommands(tactic, action),
        logSources: [],
        automatable: false,
      });
    }

    // Phase 4: Recover
    for (const action of responses.recover) {
      steps.push({
        phase: 'recover',
        action,
        details: `Restore operations and harden against ${technique.name} recurrence.`,
        tools: ['Configuration Management', 'Backup System', 'Patch Management'],
        commands: [],
        logSources: [],
        automatable: false,
      });
    }

    // Phase 5: Lessons Learned
    steps.push({
      phase: 'lessons',
      action: 'Document incident timeline',
      details: 'Create a detailed timeline of events from initial detection through recovery.',
      tools: ['Ticketing System', 'Wiki/Documentation'],
      commands: [],
      logSources: [],
      automatable: false,
    });
    steps.push({
      phase: 'lessons',
      action: 'Update detection rules',
      details: `Add/improve detection rules for ${technique.attackId} based on observed TTPs.`,
      tools: ['SIEM', 'Sigma', 'EDR'],
      commands: [],
      logSources: [],
      automatable: false,
    });
    steps.push({
      phase: 'lessons',
      action: 'Review and update mitigations',
      details: `Evaluate whether current mitigations for ${technique.name} are sufficient. Consider implementing additional controls.`,
      tools: ['GRC Platform', 'Vulnerability Scanner'],
      commands: [],
      logSources: [],
      automatable: false,
    });

    // Related techniques
    const related: string[] = [];
    const mitigations = domain.mitigationsByTechnique?.get(technique.id) || [];
    for (const m of mitigations.slice(0, 3)) {
      const techsForMit = domain.techniquesByMitigation?.get(m.mitigation.id) || [];
      for (const t of techsForMit.slice(0, 3)) {
        if (t.attackId !== technique.attackId && !related.includes(t.attackId)) {
          related.push(t.attackId);
        }
      }
    }

    return {
      techniqueId: technique.attackId,
      techniqueName: technique.name,
      tactic: tactic.replace(/-/g, ' '),
      severity,
      summary: `Incident response playbook for ${technique.attackId} - ${technique.name}. This technique falls under the ${tactic.replace(/-/g, ' ')} tactic.`,
      steps,
      indicators: this.getIndicators(technique, tactic),
      relatedTechniques: related.slice(0, 5),
    };
  }

  exportMarkdown(playbook: IRPlaybook): string {
    const lines: string[] = [
      `# IR Playbook: ${playbook.techniqueId} - ${playbook.techniqueName}`,
      '',
      `**Tactic:** ${playbook.tactic} | **Severity:** ${playbook.severity.toUpperCase()}`,
      '',
      playbook.summary,
      '',
    ];

    const phases = ['identify', 'contain', 'eradicate', 'recover', 'lessons'] as const;
    const phaseLabels = { identify: 'Identify', contain: 'Contain', eradicate: 'Eradicate', recover: 'Recover', lessons: 'Lessons Learned' };

    for (const phase of phases) {
      const phaseSteps = playbook.steps.filter(s => s.phase === phase);
      if (phaseSteps.length === 0) continue;
      lines.push(`## ${phaseLabels[phase]}`, '');
      for (const step of phaseSteps) {
        lines.push(`### ${step.action}`, '', step.details, '');
        if (step.tools.length) lines.push(`**Tools:** ${step.tools.join(', ')}`, '');
        if (step.commands.length) {
          lines.push('**Commands:**', '```');
          for (const cmd of step.commands) lines.push(cmd);
          lines.push('```', '');
        }
        if (step.logSources.length) lines.push(`**Log Sources:** ${step.logSources.join(', ')}`, '');
      }
    }

    if (playbook.indicators.length) {
      lines.push('## Indicators of Compromise', '');
      for (const ioc of playbook.indicators) lines.push(`- ${ioc}`);
      lines.push('');
    }

    if (playbook.relatedTechniques.length) {
      lines.push('## Related Techniques', '');
      for (const t of playbook.relatedTechniques) lines.push(`- ${t}`);
    }

    return lines.join('\n');
  }

  exportJson(playbook: IRPlaybook): string {
    return JSON.stringify(playbook, null, 2);
  }

  private computeSeverity(technique: Technique, domain: Domain): 'critical' | 'high' | 'medium' | 'low' {
    const groups = domain.groupsByTechnique?.get(technique.id)?.length || 0;
    const tactic = technique.tacticShortnames?.[0] || '';
    const highImpact = ['impact', 'exfiltration', 'credential-access'].includes(tactic);
    if (groups > 10 && highImpact) return 'critical';
    if (groups > 5 || highImpact) return 'high';
    if (groups > 2) return 'medium';
    return 'low';
  }

  private mapToLogSources(dataSources: string[]): string[] {
    const map: Record<string, string> = {
      'Process': 'Sysmon Event ID 1 / Windows Security 4688',
      'File': 'Sysmon Event ID 11 / Windows Security 4663',
      'Network Traffic': 'Zeek conn.log / Firewall logs',
      'Windows Registry': 'Sysmon Event ID 12-14',
      'Command': 'PowerShell ScriptBlock Logging 4104',
      'Module': 'Sysmon Event ID 7',
      'Logon Session': 'Windows Security 4624/4625',
      'User Account': 'Windows Security 4720/4726',
    };
    const sources: string[] = [];
    for (const ds of dataSources) {
      for (const [key, val] of Object.entries(map)) {
        if (ds.toLowerCase().includes(key.toLowerCase()) && !sources.includes(val)) {
          sources.push(val);
        }
      }
    }
    return sources.length ? sources : ['Review ATT&CK data sources for this technique'];
  }

  private getDetectionCommands(technique: Technique, tactic: string): string[] {
    const id = technique.attackId.toLowerCase();
    const cmds: string[] = [];
    cmds.push(`# Search SIEM for ${technique.attackId} indicators`);
    if (tactic === 'execution' || tactic === 'persistence') {
      cmds.push(`Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} | Where-Object {$_.Message -match '${technique.name.split(' ')[0]}'}`);
    }
    if (tactic === 'credential-access') {
      cmds.push(`Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} | Select-Object -First 50`);
    }
    if (tactic === 'lateral-movement') {
      cmds.push(`Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} | Where-Object {$_.Properties[8].Value -eq 3}`);
    }
    cmds.push(`# Check Sigma rule coverage: sigma-cli check --technique ${technique.attackId}`);
    return cmds;
  }

  private getContainmentTools(tactic: string): string[] {
    const base = ['EDR Console', 'Firewall'];
    if (['credential-access', 'lateral-movement'].includes(tactic)) base.push('Active Directory');
    if (['command-and-control', 'exfiltration'].includes(tactic)) base.push('DNS Sinkhole', 'Proxy');
    if (['initial-access'].includes(tactic)) base.push('Email Gateway');
    return base;
  }

  private getContainmentCommands(tactic: string, action: string): string[] {
    if (action.includes('Block') && action.includes('IP')) return ['# netsh advfirewall firewall add rule name="Block Threat" dir=out action=block remoteip=<THREAT_IP>'];
    if (action.includes('Isolate')) return ['# EDR: Isolate host via console API', '# Alternative: Disable network adapter'];
    if (action.includes('Disable') && action.includes('account')) return ['Disable-ADAccount -Identity <COMPROMISED_USER>'];
    if (action.includes('Terminate')) return ['Stop-Process -Name <PROCESS_NAME> -Force'];
    return [];
  }

  private getEradicationTools(tactic: string): string[] {
    const base = ['EDR', 'Antimalware'];
    if (['persistence'].includes(tactic)) base.push('Autoruns', 'Registry Editor');
    if (['credential-access'].includes(tactic)) base.push('LAPS', 'Azure AD');
    return base;
  }

  private getEradicationCommands(tactic: string, action: string): string[] {
    if (action.includes('registry')) return ['# Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "<MALICIOUS_ENTRY>"'];
    if (action.includes('scheduled task')) return ['Unregister-ScheduledTask -TaskName "<MALICIOUS_TASK>" -Confirm:$false'];
    if (action.includes('web shell')) return ['# Remove-Item -Path "C:\\inetpub\\wwwroot\\<WEBSHELL>" -Force'];
    if (action.includes('credential') || action.includes('password')) return ['# Reset-ADAccountPassword -Identity <USER>', '# Set-ADAccountPassword -Identity <USER> -NewPassword (ConvertTo-SecureString -AsPlainText "<NEW_PASS>" -Force)'];
    return [];
  }

  private getIndicators(technique: Technique, tactic: string): string[] {
    const indicators: string[] = [];
    indicators.push(`ATT&CK Technique: ${technique.attackId}`);
    if (tactic === 'execution') indicators.push('Suspicious process creation', 'Encoded command line arguments', 'Unusual parent-child process relationships');
    if (tactic === 'persistence') indicators.push('New registry run key entries', 'Unauthorized scheduled tasks', 'Modified startup folders');
    if (tactic === 'credential-access') indicators.push('LSASS memory access', 'Unusual authentication failures', 'Kerberoasting activity');
    if (tactic === 'lateral-movement') indicators.push('Unusual SMB/RDP connections', 'Pass-the-hash/ticket activity', 'Remote service creation');
    if (tactic === 'command-and-control') indicators.push('Beaconing traffic patterns', 'DNS tunneling indicators', 'Unusual outbound connections');
    if (tactic === 'exfiltration') indicators.push('Large outbound data transfers', 'Connections to cloud storage', 'Encrypted traffic to unknown destinations');
    if (tactic === 'impact') indicators.push('Mass file encryption', 'Volume shadow copy deletion', 'Service disruption');
    if (indicators.length === 1) indicators.push('Review technique-specific IOCs in threat intelligence feeds');
    return indicators;
  }
}
