import { Injectable } from '@angular/core';

export interface LogConfig {
  source: string;
  eventId: string;
  command: string;
  description?: string;
}

/**
 * Maps ATT&CK techniques to recommended Windows event log configurations.
 * Based on patterns from blackhillsinfosec/EventLogging and Microsoft security baselines.
 */
const TECHNIQUE_TO_LOGGING: Record<string, LogConfig[]> = {
  'T1059.001': [{
    source: 'PowerShell ScriptBlock Logging',
    eventId: '4104',
    command: 'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Force\nSet-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1',
    description: 'Logs all PowerShell script blocks for analysis',
  }, {
    source: 'PowerShell Module Logging',
    eventId: '4103',
    command: 'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" -Force\nSet-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" -Name "EnableModuleLogging" -Value 1\nNew-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames" -Force\nSet-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames" -Name "*" -Value "*"',
    description: 'Logs PowerShell module usage including parameters',
  }, {
    source: 'PowerShell Transcription',
    eventId: 'N/A',
    command: 'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription" -Force\nSet-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription" -Name "EnableTranscripting" -Value 1\nSet-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription" -Name "OutputDirectory" -Value "C:\\PSTranscripts"',
    description: 'Creates full transcripts of all PowerShell sessions',
  }],
  'T1059.003': [{
    source: 'Command Line Process Auditing',
    eventId: '4688',
    command: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1',
    description: 'Logs command-line arguments in process creation events',
  }],
  'T1059.005': [{
    source: 'Windows Script Host Logging',
    eventId: '4688',
    command: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1\nSet-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings" -Name "Enabled" -Value 1',
    description: 'Tracks VBScript/JScript execution via process auditing',
  }],
  'T1003.001': [{
    source: 'LSASS Protection',
    eventId: '4656',
    command: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RunAsPPL" -Value 1',
    description: 'Enables LSASS as PPL to prevent credential dumping',
  }, {
    source: 'LSASS Audit Access',
    eventId: '4663',
    command: '# Enable auditing of LSASS access\nauditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable',
    description: 'Audits access to the LSASS process',
  }],
  'T1003.002': [{
    source: 'SAM Database Auditing',
    eventId: '4661',
    command: 'auditpol /set /subcategory:"SAM" /success:enable /failure:enable',
    description: 'Audits access to the SAM database',
  }],
  'T1003.003': [{
    source: 'NTDS Auditing',
    eventId: '4662',
    command: 'auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable',
    description: 'Audits Active Directory object access for DCSync detection',
  }],
  'T1053.005': [{
    source: 'Scheduled Task Auditing',
    eventId: '4698',
    command: 'auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable',
    description: 'Logs creation of new scheduled tasks',
  }],
  'T1021.001': [{
    source: 'RDP Logon Auditing',
    eventId: '4624',
    command: 'auditpol /set /subcategory:"Logon" /success:enable /failure:enable\nauditpol /set /subcategory:"Special Logon" /success:enable /failure:enable',
    description: 'Tracks RDP logon events (Type 10) and special logons',
  }],
  'T1021.002': [{
    source: 'SMB Share Auditing',
    eventId: '5140',
    command: 'auditpol /set /subcategory:"File Share" /success:enable /failure:enable\nauditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable',
    description: 'Audits SMB share access and detailed operations',
  }],
  'T1021.006': [{
    source: 'WinRM Logging',
    eventId: '91',
    command: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service" -Name "AllowAutoConfig" -Value 1\nwevtutil sl Microsoft-Windows-WinRM/Operational /e:true',
    description: 'Enables WinRM operational logging for remote management detection',
  }],
  'T1547.001': [{
    source: 'Registry Auditing',
    eventId: '4657',
    command: 'auditpol /set /subcategory:"Registry" /success:enable /failure:enable',
    description: 'Audits registry modifications for persistence in Run keys',
  }],
  'T1543.003': [{
    source: 'Service Creation Auditing',
    eventId: '4697',
    command: 'auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable',
    description: 'Logs new service installations',
  }],
  'T1078': [{
    source: 'Account Logon Auditing',
    eventId: '4624/4625',
    command: 'auditpol /set /subcategory:"Logon" /success:enable /failure:enable\nauditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable\nauditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable',
    description: 'Tracks valid/invalid account usage and lockouts',
  }],
  'T1055': [{
    source: 'Process Injection Detection',
    eventId: '8/10',
    command: '# Requires Sysmon - install from https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon\n# Configure Sysmon with CreateRemoteThread (Event 8) and ProcessAccess (Event 10)\nSet-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1',
    description: 'Detects process injection via Sysmon events',
  }],
  'T1027': [{
    source: 'AMSI Logging',
    eventId: '1116',
    command: 'Set-MpPreference -DisableRealtimeMonitoring $false\nSet-MpPreference -MAPSReporting Advanced',
    description: 'Ensures AMSI is active for obfuscated script detection',
  }],
  'T1087': [{
    source: 'Account Discovery Auditing',
    eventId: '4798/4799',
    command: 'auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable\nauditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable',
    description: 'Tracks account and group enumeration activity',
  }],
  'T1069': [{
    source: 'Permission Group Discovery',
    eventId: '4799',
    command: 'auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable',
    description: 'Audits security group enumeration',
  }],
  'T1570': [{
    source: 'Lateral Tool Transfer',
    eventId: '5145',
    command: 'auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable',
    description: 'Detailed file share auditing to detect lateral movement tool transfers',
  }],
  'T1036': [{
    source: 'Process Creation with Full Path',
    eventId: '4688',
    command: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1',
    description: 'Full command line logging to detect masquerading',
  }],
  'T1218': [{
    source: 'Signed Binary Proxy Execution',
    eventId: '4688',
    command: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1',
    description: 'Tracks execution of LOLBins like mshta, rundll32, regsvr32',
  }],
  'T1112': [{
    source: 'Registry Modification',
    eventId: '4657',
    command: 'auditpol /set /subcategory:"Registry" /success:enable /failure:enable',
    description: 'Audits registry key and value modifications',
  }],
  'T1070.001': [{
    source: 'Event Log Clearing Detection',
    eventId: '1102',
    command: 'auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable',
    description: 'Detects when event logs are cleared (Security log clear event)',
  }],
  'T1548.002': [{
    source: 'UAC Bypass Detection',
    eventId: '4688',
    command: 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "ConsentPromptBehaviorAdmin" -Value 2\nSet-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1',
    description: 'Monitors for UAC bypass attempts via process creation',
  }],
  'T1134': [{
    source: 'Token Manipulation Auditing',
    eventId: '4672',
    command: 'auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable\nauditpol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:enable',
    description: 'Tracks special privilege assignment and token adjustments',
  }],
  'T1110': [{
    source: 'Brute Force Detection',
    eventId: '4625',
    command: 'auditpol /set /subcategory:"Logon" /success:enable /failure:enable\nauditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable',
    description: 'Monitors failed logon attempts for brute force detection',
  }],
};

@Injectable({ providedIn: 'root' })
export class EventLoggingService {
  getLoggingConfig(attackId: string): LogConfig[] {
    return TECHNIQUE_TO_LOGGING[attackId] ?? [];
  }

  getAllMappedTechniques(): string[] {
    return Object.keys(TECHNIQUE_TO_LOGGING);
  }

  getConfigCount(attackId: string): number {
    return (TECHNIQUE_TO_LOGGING[attackId] ?? []).length;
  }

  generateScript(attackIds: string[]): string {
    const seen = new Set<string>();
    const commands: string[] = [];

    commands.push('# Windows Event Logging Configuration Script');
    commands.push('# Generated by MITRE ATT&CK Navigator');
    commands.push(`# Date: ${new Date().toISOString().split('T')[0]}`);
    commands.push(`# Techniques: ${attackIds.join(', ')}`);
    commands.push('#');
    commands.push('# Run this script as Administrator in an elevated PowerShell session.');
    commands.push('#requires -RunAsAdministrator');
    commands.push('');

    for (const attackId of attackIds) {
      const configs = TECHNIQUE_TO_LOGGING[attackId];
      if (!configs) continue;

      commands.push(`# ── ${attackId} ──────────────────────���───────────`);
      for (const config of configs) {
        const key = config.command.trim();
        if (seen.has(key)) continue;
        seen.add(key);

        commands.push(`# ${config.source} (Event ID: ${config.eventId})`);
        if (config.description) {
          commands.push(`# ${config.description}`);
        }
        commands.push(config.command);
        commands.push('');
      }
    }

    commands.push('Write-Host "Event logging configuration complete." -ForegroundColor Green');

    return commands.join('\n');
  }
}
