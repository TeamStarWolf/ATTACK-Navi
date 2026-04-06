// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';

export interface SiemQuery {
  platform: 'splunk' | 'elastic' | 'microsoft' | 'chronicle' | 'crowdstrike';
  platformLabel: string;
  query: string;
  title: string;
  description: string;
  dataSource: string;
  confidence: 'high' | 'medium' | 'low';
}

interface TacticTemplate {
  tactic: string;
  platforms: {
    splunk: string;
    elastic: string;
    microsoft: string;
    chronicle: string;
    crowdstrike: string;
  };
  title: string;
  description: string;
  dataSource: string;
  confidence: 'high' | 'medium' | 'low';
}

const PLATFORM_LABELS: Record<string, string> = {
  splunk: 'Splunk SPL',
  elastic: 'Elastic KQL',
  microsoft: 'Microsoft Sentinel KQL',
  chronicle: 'Google Chronicle YARA-L',
  crowdstrike: 'CrowdStrike LogScale',
};

/**
 * Tactic-based query templates. Each template uses `{{TECHNIQUE}}` and
 * `{{TECHNIQUE_NAME}}` placeholders that are substituted at runtime.
 */
const TACTIC_TEMPLATES: TacticTemplate[] = [
  // ── Initial Access ─────────────────────────────────────────────────────────
  {
    tactic: 'initial-access',
    title: 'Web Server Exploitation / Email Delivery',
    description: 'Detect suspicious inbound web requests or email attachment execution indicative of initial access vectors.',
    dataSource: 'Web Server Logs, Email Gateway Logs',
    confidence: 'medium',
    platforms: {
      splunk: [
        '| ===== {{TECHNIQUE}} — Initial Access Detection =====',
        'index=web sourcetype=access_combined',
        '| search (status>=400 OR uri_path IN ("*exploit*","*shell*","*upload*","*cmd*","*eval*"))',
        '| stats count as hits, dc(src_ip) as unique_sources by uri_path, status, dest',
        '| where hits > 10 OR unique_sources > 5',
        '| eval technique="{{TECHNIQUE}}", tactic="initial-access"',
        '| sort -hits',
      ].join('\n'),
      elastic: [
        '// {{TECHNIQUE}} — Initial Access Detection',
        'http.response.status_code >= 400 AND',
        '  (url.path: (*exploit* OR *shell* OR *upload* OR *cmd* OR *eval*))',
        '| Stats by url.path, source.ip',
      ].join('\n'),
      microsoft: [
        '// {{TECHNIQUE}} — Initial Access Detection',
        'CommonSecurityLog',
        '| where DeviceAction has "Allowed" and RequestURL has_any ("exploit","shell","upload","cmd","eval")',
        '| summarize HitCount=count(), UniqueIPs=dcount(SourceIP) by RequestURL, DestinationIP',
        '| where HitCount > 10 or UniqueIPs > 5',
        '| extend Technique = "{{TECHNIQUE}}", Tactic = "initial-access"',
      ].join('\n'),
      chronicle: [
        '// {{TECHNIQUE}} — Initial Access Detection',
        'rule initial_access_{{TECHNIQUE_SAFE}} {',
        '  meta:',
        '    description = "Detect exploitation attempts for {{TECHNIQUE}}"',
        '  events:',
        '    $http.metadata.event_type = "NETWORK_HTTP"',
        '    re.regex($http.target.url, `.*exploit|shell|upload|cmd|eval.*`)',
        '    $http.network.http.response_code >= 400',
        '  condition:',
        '    $http',
        '}',
      ].join('\n'),
      crowdstrike: [
        '// {{TECHNIQUE}} — Initial Access Detection',
        '#event_simpleName=NetworkConnectIP4',
        '| RemoteAddressIP4=* RemotePort IN (80, 443, 8080, 8443)',
        '| search ContextBaseFileName IN ("w3wp.exe", "httpd.exe", "nginx.exe", "java.exe")',
        '| stats count(aid) as ConnectionCount by RemoteAddressIP4, ContextBaseFileName, aid',
        '| where ConnectionCount > 20',
      ].join('\n'),
    },
  },

  // ── Execution ──────────────────────────────────────────────────────────────
  {
    tactic: 'execution',
    title: 'Suspicious Process Execution & Script Block Logging',
    description: 'Detect command-line interpreters, scripting engines, and suspicious process creation events.',
    dataSource: 'Process Creation (Sysmon EID 1, Security EID 4688), PowerShell Script Block Logging',
    confidence: 'high',
    platforms: {
      splunk: [
        '| ===== {{TECHNIQUE}} — Execution Detection =====',
        'index=main sourcetype=WinEventLog (EventCode=4688 OR EventCode=4104)',
        '| search CommandLine="*powershell*" OR CommandLine="*cmd.exe*" OR CommandLine="*wscript*" OR CommandLine="*cscript*" OR CommandLine="*mshta*"',
        '| eval suspicious=if(match(CommandLine,"(?i)(-enc|-nop|iex |Invoke-Expression|DownloadString|bypass|hidden)"),1,0)',
        '| where suspicious=1',
        '| stats count by ComputerName, CommandLine, User, ParentProcessName',
        '| eval technique="{{TECHNIQUE}}", tactic="execution"',
        '| sort -count',
      ].join('\n'),
      elastic: [
        '// {{TECHNIQUE}} — Execution Detection',
        'event.code: ("4688" OR "1") AND',
        '  process.command_line: (*powershell* OR *cmd.exe* OR *wscript* OR *cscript* OR *mshta*) AND',
        '  process.command_line: (*-enc* OR *-nop* OR *iex* OR *Invoke-Expression* OR *DownloadString* OR *bypass* OR *hidden*)',
      ].join('\n'),
      microsoft: [
        '// {{TECHNIQUE}} — Execution Detection',
        'DeviceProcessEvents',
        '| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe")',
        '| where ProcessCommandLine has_any ("-enc","-nop","iex","Invoke-Expression","DownloadString","bypass","hidden")',
        '| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName',
        '| extend Technique = "{{TECHNIQUE}}", Tactic = "execution"',
      ].join('\n'),
      chronicle: [
        '// {{TECHNIQUE}} — Execution Detection',
        'rule execution_{{TECHNIQUE_SAFE}} {',
        '  meta:',
        '    description = "Detect suspicious process execution for {{TECHNIQUE}}"',
        '  events:',
        '    $process.metadata.event_type = "PROCESS_LAUNCH"',
        '    $process.target.process.file.full_path = /powershell|cmd\\.exe|wscript|cscript|mshta/ nocase',
        '    $process.target.process.command_line = /\\-enc|\\-nop|iex|Invoke\\-Expression|DownloadString|bypass|hidden/ nocase',
        '  condition:',
        '    $process',
        '}',
      ].join('\n'),
      crowdstrike: [
        '// {{TECHNIQUE}} — Execution Detection',
        '#event_simpleName=ProcessRollup2',
        '| ImageFileName IN ("*\\\\powershell.exe","*\\\\cmd.exe","*\\\\wscript.exe","*\\\\cscript.exe","*\\\\mshta.exe")',
        '| CommandLine=/(\\-enc|\\-nop|iex|Invoke\\-Expression|DownloadString|bypass|hidden)/i',
        '| stats count(aid) as Executions by aid, UserName, ImageFileName, CommandLine',
        '| sort -Executions',
      ].join('\n'),
    },
  },

  // ── Persistence ────────────────────────────────────────────────────────────
  {
    tactic: 'persistence',
    title: 'Registry Run Keys, Scheduled Tasks & Service Installation',
    description: 'Detect modifications to autostart registry keys, new scheduled tasks, or service installations used for persistence.',
    dataSource: 'Registry Events (Sysmon EID 13), Scheduled Task Events (4698), Service Install (7045)',
    confidence: 'high',
    platforms: {
      splunk: [
        '| ===== {{TECHNIQUE}} — Persistence Detection =====',
        'index=main sourcetype=WinEventLog (EventCode=13 OR EventCode=4698 OR EventCode=7045)',
        '| search TargetObject="*\\\\CurrentVersion\\\\Run*" OR TaskName="*" OR ServiceName="*"',
        '| eval persistence_type=case(',
        '    EventCode=13, "Registry Run Key",',
        '    EventCode=4698, "Scheduled Task",',
        '    EventCode=7045, "Service Install",',
        '    true(), "Unknown")',
        '| stats count by Computer, persistence_type, TargetObject, TaskName, ServiceName, User',
        '| eval technique="{{TECHNIQUE}}", tactic="persistence"',
        '| sort -count',
      ].join('\n'),
      elastic: [
        '// {{TECHNIQUE}} — Persistence Detection',
        '(event.code: "13" AND registry.path: *CurrentVersion\\\\Run*) OR',
        '(event.code: "4698") OR',
        '(event.code: "7045")',
      ].join('\n'),
      microsoft: [
        '// {{TECHNIQUE}} — Persistence Detection',
        'union DeviceRegistryEvents, DeviceEvents',
        '| where (RegistryKey has "CurrentVersion\\\\Run") or',
        '        (ActionType == "ScheduledTaskCreated") or',
        '        (ActionType == "ServiceInstalled")',
        '| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, FileName',
        '| extend Technique = "{{TECHNIQUE}}", Tactic = "persistence"',
      ].join('\n'),
      chronicle: [
        '// {{TECHNIQUE}} — Persistence Detection',
        'rule persistence_{{TECHNIQUE_SAFE}} {',
        '  meta:',
        '    description = "Detect persistence mechanisms for {{TECHNIQUE}}"',
        '  events:',
        '    ($reg.metadata.event_type = "REGISTRY_MODIFICATION"',
        '     and re.regex($reg.target.registry.registry_key, `.*CurrentVersion\\\\Run.*`))',
        '    or $reg.metadata.event_type = "SCHEDULED_TASK"',
        '  condition:',
        '    $reg',
        '}',
      ].join('\n'),
      crowdstrike: [
        '// {{TECHNIQUE}} — Persistence Detection',
        '#event_simpleName IN (AsepValueUpdate, ScheduledTaskRegistered, ServiceStarted)',
        '| search RegObjectName="*\\\\CurrentVersion\\\\Run*" OR TaskName=*',
        '| stats count(aid) as Events by aid, event_simpleName, RegObjectName, TaskName, UserName',
        '| sort -Events',
      ].join('\n'),
    },
  },

  // ── Privilege Escalation ───────────────────────────────────────────────────
  {
    tactic: 'privilege-escalation',
    title: 'Token Manipulation & Elevated Service Creation',
    description: 'Detect access token manipulation, UAC bypass attempts, and creation of services running as SYSTEM.',
    dataSource: 'Process Creation, Security Events (4673, 4672), Sysmon EID 1',
    confidence: 'medium',
    platforms: {
      splunk: [
        '| ===== {{TECHNIQUE}} — Privilege Escalation Detection =====',
        'index=main sourcetype=WinEventLog (EventCode=4672 OR EventCode=4673 OR EventCode=7045)',
        '| eval priv_esc_type=case(',
        '    EventCode=4672, "Special Privileges Assigned",',
        '    EventCode=4673, "Privileged Service Called",',
        '    EventCode=7045 AND ServiceStartType="auto start" AND ServiceAccount="LocalSystem", "SYSTEM Service Install",',
        '    true(), "Other")',
        '| where priv_esc_type != "Other"',
        '| stats count by Computer, SubjectUserName, priv_esc_type, ProcessName, ServiceName',
        '| eval technique="{{TECHNIQUE}}", tactic="privilege-escalation"',
        '| sort -count',
      ].join('\n'),
      elastic: [
        '// {{TECHNIQUE}} — Privilege Escalation Detection',
        '(event.code: "4672" OR event.code: "4673") OR',
        '(event.code: "7045" AND winlog.event_data.ServiceAccount: "LocalSystem")',
      ].join('\n'),
      microsoft: [
        '// {{TECHNIQUE}} — Privilege Escalation Detection',
        'union DeviceProcessEvents, DeviceEvents',
        '| where (ActionType == "ElevatedProcess") or',
        '        (FileName in~ ("cmd.exe","powershell.exe") and ProcessIntegrityLevel == "High" and InitiatingProcessIntegrityLevel != "High")',
        '| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ProcessIntegrityLevel',
        '| extend Technique = "{{TECHNIQUE}}", Tactic = "privilege-escalation"',
      ].join('\n'),
      chronicle: [
        '// {{TECHNIQUE}} — Privilege Escalation Detection',
        'rule privesc_{{TECHNIQUE_SAFE}} {',
        '  meta:',
        '    description = "Detect privilege escalation for {{TECHNIQUE}}"',
        '  events:',
        '    $proc.metadata.event_type = "PROCESS_LAUNCH"',
        '    $proc.target.process.file.full_path = /cmd\\.exe|powershell\\.exe/ nocase',
        '    $proc.security_result.action = "ELEVATED"',
        '  condition:',
        '    $proc',
        '}',
      ].join('\n'),
      crowdstrike: [
        '// {{TECHNIQUE}} — Privilege Escalation Detection',
        '#event_simpleName=ProcessRollup2',
        '| IntegrityLevel=High',
        '| ParentBaseFileName NOT IN ("services.exe","svchost.exe","wininit.exe")',
        '| stats count(aid) as Events by aid, UserName, ImageFileName, ParentBaseFileName, IntegrityLevel',
        '| sort -Events',
      ].join('\n'),
    },
  },

  // ── Defense Evasion ────────────────────────────────────────────────────────
  {
    tactic: 'defense-evasion',
    title: 'Process Injection, Timestomping & Log Clearing',
    description: 'Detect process injection (CreateRemoteThread), file timestamp manipulation, and security log clearing.',
    dataSource: 'Sysmon EID 8 (CreateRemoteThread), EID 2 (FileCreateTime), Security EID 1102',
    confidence: 'high',
    platforms: {
      splunk: [
        '| ===== {{TECHNIQUE}} — Defense Evasion Detection =====',
        'index=main sourcetype=WinEventLog (EventCode=8 OR EventCode=2 OR EventCode=1102)',
        '| eval evasion_type=case(',
        '    EventCode=8, "Process Injection (CreateRemoteThread)",',
        '    EventCode=2, "Timestomp (FileCreateTime Changed)",',
        '    EventCode=1102, "Security Log Cleared",',
        '    true(), "Unknown")',
        '| where NOT match(SourceImage, "(?i)(defender|sysmon|splunk|antivirus)")',
        '| stats count by Computer, evasion_type, SourceImage, TargetImage, User',
        '| eval technique="{{TECHNIQUE}}", tactic="defense-evasion"',
        '| sort -count',
      ].join('\n'),
      elastic: [
        '// {{TECHNIQUE}} — Defense Evasion Detection',
        '(event.code: "8" AND NOT process.executable: (*defender* OR *sysmon*)) OR',
        'event.code: "2" OR',
        'event.code: "1102"',
      ].join('\n'),
      microsoft: [
        '// {{TECHNIQUE}} — Defense Evasion Detection',
        'union DeviceProcessEvents, DeviceEvents',
        '| where ActionType in ("CreateRemoteThreadApiCall","ProcessInjection") or',
        '        ActionType == "SecurityLogCleared" or',
        '        ActionType == "TimestampChanged"',
        '| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessFileName, ProcessCommandLine',
        '| extend Technique = "{{TECHNIQUE}}", Tactic = "defense-evasion"',
      ].join('\n'),
      chronicle: [
        '// {{TECHNIQUE}} — Defense Evasion Detection',
        'rule defense_evasion_{{TECHNIQUE_SAFE}} {',
        '  meta:',
        '    description = "Detect defense evasion for {{TECHNIQUE}}"',
        '  events:',
        '    ($inject.metadata.event_type = "PROCESS_INJECTION")',
        '    or ($inject.metadata.event_type = "GENERIC_EVENT"',
        '        and $inject.security_result.summary = "Security log cleared")',
        '  condition:',
        '    $inject',
        '}',
      ].join('\n'),
      crowdstrike: [
        '// {{TECHNIQUE}} — Defense Evasion Detection',
        '#event_simpleName IN (CreateRemoteThread, InjectedThread, ClearEventLog)',
        '| TargetProcessId_decimal=*',
        '| stats count(aid) as Events by aid, event_simpleName, ContextBaseFileName, TargetProcessId_decimal',
        '| sort -Events',
      ].join('\n'),
    },
  },

  // ── Credential Access ──────────────────────────────────────────────────────
  {
    tactic: 'credential-access',
    title: 'LSASS Access, Kerberos Anomalies & Credential Dumping',
    description: 'Detect LSASS memory access, Kerberoasting, AS-REP roasting, and credential dumping tool artifacts.',
    dataSource: 'Sysmon EID 10 (ProcessAccess), Security EID 4656/4768/4769',
    confidence: 'high',
    platforms: {
      splunk: [
        '| ===== {{TECHNIQUE}} — Credential Access Detection =====',
        'index=main sourcetype=WinEventLog (EventCode=4656 OR EventCode=10 OR EventCode=4768 OR EventCode=4769)',
        '| search ObjectName="*\\\\lsass.exe*" OR TargetImage="*\\\\lsass.exe" OR TicketEncryptionType="0x17"',
        '| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|svchost|lsass|defender)")',
        '| stats count by Computer, SourceImage, TargetImage, GrantedAccess, TicketEncryptionType, User',
        '| eval technique="{{TECHNIQUE}}", tactic="credential-access"',
        '| sort -count',
      ].join('\n'),
      elastic: [
        '// {{TECHNIQUE}} — Credential Access Detection',
        '(event.code: "4656" AND winlog.event_data.ObjectName: *lsass.exe*) OR',
        '(event.code: "10" AND winlog.event_data.TargetImage: *lsass.exe) OR',
        '(event.code: "4769" AND winlog.event_data.TicketEncryptionType: "0x17")',
      ].join('\n'),
      microsoft: [
        '// {{TECHNIQUE}} — Credential Access Detection',
        'DeviceProcessEvents',
        '| where FileName == "lsass.exe" and ActionType == "ProcessAccessed"',
        '| where InitiatingProcessFileName !in~ ("MsMpEng.exe","csrss.exe","svchost.exe","lsass.exe")',
        '| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine',
        '| extend Technique = "{{TECHNIQUE}}", Tactic = "credential-access"',
      ].join('\n'),
      chronicle: [
        '// {{TECHNIQUE}} — Credential Access Detection',
        'rule credential_access_{{TECHNIQUE_SAFE}} {',
        '  meta:',
        '    description = "Detect credential access for {{TECHNIQUE}}"',
        '  events:',
        '    $access.metadata.event_type = "PROCESS_OPEN"',
        '    $access.target.process.file.full_path = /lsass\\.exe/ nocase',
        '    not $access.principal.process.file.full_path = /MsMpEng|csrss|svchost/ nocase',
        '  condition:',
        '    $access',
        '}',
      ].join('\n'),
      crowdstrike: [
        '// {{TECHNIQUE}} — Credential Access Detection',
        '#event_simpleName=ProcessRollup2 OR #event_simpleName=LsassHandleOperation',
        '| TargetProcessImageFileName="*\\\\lsass.exe"',
        '| ContextBaseFileName NOT IN ("MsMpEng.exe","csrss.exe","svchost.exe")',
        '| stats count(aid) as Events by aid, ContextBaseFileName, TargetProcessImageFileName',
        '| sort -Events',
      ].join('\n'),
    },
  },

  // ── Discovery ──────────────────────────────────────────────────────────────
  {
    tactic: 'discovery',
    title: 'AD Enumeration, Network Scanning & System Discovery',
    description: 'Detect Active Directory enumeration tools, network reconnaissance commands, and system information gathering.',
    dataSource: 'Process Creation, LDAP Queries, Network Connection Logs',
    confidence: 'medium',
    platforms: {
      splunk: [
        '| ===== {{TECHNIQUE}} — Discovery Detection =====',
        'index=main sourcetype=WinEventLog EventCode=4688',
        '| search CommandLine IN ("*net group*","*net user*","*nltest*","*dsquery*","*whoami*","*systeminfo*","*ipconfig*","*nslookup*","*arp -a*","*net view*")',
        '| stats count by Computer, SubjectUserName, CommandLine, ParentProcessName',
        '| where count > 3',
        '| eval technique="{{TECHNIQUE}}", tactic="discovery"',
        '| sort -count',
      ].join('\n'),
      elastic: [
        '// {{TECHNIQUE}} — Discovery Detection',
        'event.code: "4688" AND',
        '  process.command_line: (*"net group"* OR *"net user"* OR *nltest* OR *dsquery* OR *whoami* OR *systeminfo* OR *ipconfig* OR *"arp -a"*)',
      ].join('\n'),
      microsoft: [
        '// {{TECHNIQUE}} — Discovery Detection',
        'DeviceProcessEvents',
        '| where ProcessCommandLine has_any ("net group","net user","nltest","dsquery","whoami","systeminfo","ipconfig","nslookup","arp -a","net view")',
        '| summarize CommandCount=count(), Commands=make_set(ProcessCommandLine) by DeviceName, AccountName, bin(Timestamp, 5m)',
        '| where CommandCount > 3',
        '| extend Technique = "{{TECHNIQUE}}", Tactic = "discovery"',
      ].join('\n'),
      chronicle: [
        '// {{TECHNIQUE}} — Discovery Detection',
        'rule discovery_{{TECHNIQUE_SAFE}} {',
        '  meta:',
        '    description = "Detect discovery/enumeration for {{TECHNIQUE}}"',
        '  events:',
        '    $proc.metadata.event_type = "PROCESS_LAUNCH"',
        '    re.regex($proc.target.process.command_line, `(?i)net (group|user|view)|nltest|dsquery|whoami|systeminfo|ipconfig|arp \\-a`)',
        '  match:',
        '    $proc.principal.hostname over 5m',
        '  condition:',
        '    #proc > 3',
        '}',
      ].join('\n'),
      crowdstrike: [
        '// {{TECHNIQUE}} — Discovery Detection',
        '#event_simpleName=ProcessRollup2',
        '| CommandLine=/(net (group|user|view)|nltest|dsquery|whoami|systeminfo|ipconfig|arp \\-a)/i',
        '| stats count(aid) as Executions, dc(CommandLine) as UniqueCommands by aid, UserName',
        '| where Executions > 3 OR UniqueCommands > 2',
        '| sort -Executions',
      ].join('\n'),
    },
  },

  // ── Lateral Movement ───────────────────────────────────────────────────────
  {
    tactic: 'lateral-movement',
    title: 'SMB, RDP, WinRM & Remote Service Connections',
    description: 'Detect lateral movement via SMB file shares, RDP sessions, WinRM connections, and PsExec-like tools.',
    dataSource: 'Logon Events (4624 Type 3/10), SMB (5140/5145), WinRM (91)',
    confidence: 'high',
    platforms: {
      splunk: [
        '| ===== {{TECHNIQUE}} — Lateral Movement Detection =====',
        'index=main sourcetype=WinEventLog (EventCode=4624 OR EventCode=5140 OR EventCode=5145)',
        '| where Logon_Type IN (3, 10)',
        '| stats count as login_count, dc(Computer) as unique_targets by Account_Name, src_ip, Logon_Type',
        '| where login_count > 5 OR unique_targets > 3',
        '| eval technique="{{TECHNIQUE}}", tactic="lateral-movement"',
        '| sort -unique_targets',
      ].join('\n'),
      elastic: [
        '// {{TECHNIQUE}} — Lateral Movement Detection',
        '(event.code: "4624" AND winlog.event_data.LogonType: ("3" OR "10")) OR',
        'event.code: ("5140" OR "5145")',
        '| Stats by source.ip, user.name, host.name',
      ].join('\n'),
      microsoft: [
        '// {{TECHNIQUE}} — Lateral Movement Detection',
        'DeviceLogonEvents',
        '| where LogonType in ("Network","RemoteInteractive","CachedRemoteInteractive")',
        '| summarize LogonCount=count(), UniqueDevices=dcount(DeviceName) by AccountName, RemoteIP, LogonType',
        '| where LogonCount > 5 or UniqueDevices > 3',
        '| extend Technique = "{{TECHNIQUE}}", Tactic = "lateral-movement"',
        '| sort by UniqueDevices desc',
      ].join('\n'),
      chronicle: [
        '// {{TECHNIQUE}} — Lateral Movement Detection',
        'rule lateral_movement_{{TECHNIQUE_SAFE}} {',
        '  meta:',
        '    description = "Detect lateral movement for {{TECHNIQUE}}"',
        '  events:',
        '    $logon.metadata.event_type = "USER_LOGIN"',
        '    $logon.extensions.auth.type = "NETWORK" or $logon.extensions.auth.type = "REMOTE"',
        '    $logon.principal.ip != ""',
        '  match:',
        '    $logon.principal.ip over 10m',
        '  condition:',
        '    #logon > 5',
        '}',
      ].join('\n'),
      crowdstrike: [
        '// {{TECHNIQUE}} — Lateral Movement Detection',
        '#event_simpleName=UserLogon',
        '| LogonType IN (3, 10)',
        '| stats count(aid) as Logons, dc(aid) as UniqueTargets by UserName, RemoteAddressIP4',
        '| where Logons > 5 OR UniqueTargets > 3',
        '| sort -UniqueTargets',
      ].join('\n'),
    },
  },

  // ── Collection ─────────────────────────────────────────────────────────────
  {
    tactic: 'collection',
    title: 'Data Staging, Screen Capture & Keylogging Artifacts',
    description: 'Detect data staging to archive files, screen capture utilities, and keylogging artifacts.',
    dataSource: 'File Creation Events, Process Creation, Sysmon EID 11',
    confidence: 'medium',
    platforms: {
      splunk: [
        '| ===== {{TECHNIQUE}} — Collection Detection =====',
        'index=main sourcetype=WinEventLog (EventCode=11 OR EventCode=4688)',
        '| search (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z" OR CommandLine="*compress*" OR CommandLine="*archive*")',
        '| eval staging=if(match(TargetFilename,"(?i)(staging|exfil|collect|dump|temp)"),1,0)',
        '| stats count by Computer, User, TargetFilename, CommandLine, staging',
        '| eval technique="{{TECHNIQUE}}", tactic="collection"',
        '| sort -count',
      ].join('\n'),
      elastic: [
        '// {{TECHNIQUE}} — Collection Detection',
        '(event.code: "11" AND file.extension: ("zip" OR "rar" OR "7z")) OR',
        '(process.command_line: (*compress* OR *archive* OR *staging*))',
      ].join('\n'),
      microsoft: [
        '// {{TECHNIQUE}} — Collection Detection',
        'DeviceFileEvents',
        '| where FileName endswith_cs ".zip" or FileName endswith_cs ".rar" or FileName endswith_cs ".7z"',
        '| where FolderPath has_any ("Temp","staging","exfil","dump")',
        '| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName',
        '| extend Technique = "{{TECHNIQUE}}", Tactic = "collection"',
      ].join('\n'),
      chronicle: [
        '// {{TECHNIQUE}} — Collection Detection',
        'rule collection_{{TECHNIQUE_SAFE}} {',
        '  meta:',
        '    description = "Detect data collection/staging for {{TECHNIQUE}}"',
        '  events:',
        '    $file.metadata.event_type = "FILE_CREATION"',
        '    re.regex($file.target.file.full_path, `(?i)\\.(zip|rar|7z)$`)',
        '    re.regex($file.target.file.full_path, `(?i)(staging|exfil|collect|dump|temp)`)',
        '  condition:',
        '    $file',
        '}',
      ].join('\n'),
      crowdstrike: [
        '// {{TECHNIQUE}} — Collection Detection',
        '#event_simpleName=NewScriptWritten OR #event_simpleName=WrittenFileCreation',
        '| TargetFileName=/(\\.(zip|rar|7z))$/i',
        '| TargetDirectoryName=/(staging|exfil|collect|dump|temp)/i',
        '| stats count(aid) as Events by aid, TargetFileName, TargetDirectoryName, ContextBaseFileName',
        '| sort -Events',
      ].join('\n'),
    },
  },

  // ── Command and Control ────────────────────────────────────────────────────
  {
    tactic: 'command-and-control',
    title: 'DNS Beaconing, HTTP C2 Patterns & Encrypted Channel Detection',
    description: 'Detect DNS beaconing with high-frequency low-entropy queries, HTTP C2 callback patterns, and unusual encrypted traffic.',
    dataSource: 'DNS Logs, Proxy/Firewall Logs, Network Traffic',
    confidence: 'medium',
    platforms: {
      splunk: [
        '| ===== {{TECHNIQUE}} — Command and Control Detection =====',
        'index=dns sourcetype=stream:dns',
        '| stats count as query_count, dc(query) as unique_queries, avg(query_length) as avg_len by src_ip, query_type',
        '| where query_count > 100 AND avg_len > 30',
        '| eval technique="{{TECHNIQUE}}", tactic="command-and-control"',
        '| append [',
        '  search index=proxy sourcetype=bluecoat',
        '  | stats count as beacon_count by src_ip, url',
        '  | where beacon_count > 50',
        '  | eval technique="{{TECHNIQUE}}", tactic="command-and-control"',
        ']',
        '| sort -query_count',
      ].join('\n'),
      elastic: [
        '// {{TECHNIQUE}} — Command and Control Detection',
        'dns.question.name: * AND',
        '  NOT dns.question.name: (*.microsoft.com OR *.windows.com OR *.googleapis.com)',
        '| Stats by source.ip, dns.question.name',
        '// Filter for high-frequency beaconing patterns',
      ].join('\n'),
      microsoft: [
        '// {{TECHNIQUE}} — Command and Control Detection',
        'DeviceNetworkEvents',
        '| where RemotePort in (80, 443, 8080, 8443, 53)',
        '| summarize ConnectionCount=count(), BytesSent=sum(SentBytes), BytesRecv=sum(ReceivedBytes)',
        '    by DeviceName, RemoteUrl, RemoteIP, RemotePort, bin(Timestamp, 5m)',
        '| where ConnectionCount > 50 or BytesSent > 10000000',
        '| extend Technique = "{{TECHNIQUE}}", Tactic = "command-and-control"',
        '| sort by ConnectionCount desc',
      ].join('\n'),
      chronicle: [
        '// {{TECHNIQUE}} — Command and Control Detection',
        'rule c2_beaconing_{{TECHNIQUE_SAFE}} {',
        '  meta:',
        '    description = "Detect C2 beaconing for {{TECHNIQUE}}"',
        '  events:',
        '    $dns.metadata.event_type = "NETWORK_DNS"',
        '    $dns.network.dns.questions.name != /microsoft\\.com|windows\\.com|googleapis\\.com/',
        '    $dns.network.dns.questions.name = /.{30,}/',
        '  match:',
        '    $dns.principal.ip over 5m',
        '  condition:',
        '    #dns > 100',
        '}',
      ].join('\n'),
      crowdstrike: [
        '// {{TECHNIQUE}} — Command and Control Detection',
        '#event_simpleName=DnsRequest',
        '| DomainName != /(microsoft|windows|googleapis)\\.com$/',
        '| stats count(aid) as DNSCount, dc(DomainName) as UniqueDomains by aid, ContextBaseFileName',
        '| where DNSCount > 100 AND UniqueDomains < 5',
        '| sort -DNSCount',
      ].join('\n'),
    },
  },

  // ── Exfiltration ───────────────────────────────────────────────────────────
  {
    tactic: 'exfiltration',
    title: 'Large Data Transfers, Cloud Uploads & Unusual Outbound Traffic',
    description: 'Detect large data transfers to external destinations, cloud storage uploads, and anomalous outbound traffic volumes.',
    dataSource: 'Network Traffic, Proxy Logs, Cloud Audit Logs',
    confidence: 'medium',
    platforms: {
      splunk: [
        '| ===== {{TECHNIQUE}} — Exfiltration Detection =====',
        'index=proxy OR index=firewall sourcetype IN (bluecoat, pan:traffic)',
        '| stats sum(bytes_out) as total_bytes_out, count as connection_count by src_ip, dest_ip, dest_port',
        '| where total_bytes_out > 104857600',
        '| eval MB_out=round(total_bytes_out/1048576,2)',
        '| eval technique="{{TECHNIQUE}}", tactic="exfiltration"',
        '| sort -MB_out',
        '| append [',
        '  search index=proxy url IN ("*drive.google.com*","*dropbox.com*","*mega.nz*","*onedrive.live.com*","*pastebin.com*")',
        '  | stats sum(bytes_out) as cloud_bytes by src_ip, url',
        '  | where cloud_bytes > 52428800',
        '  | eval MB_out=round(cloud_bytes/1048576,2)',
        '  | eval technique="{{TECHNIQUE}}", tactic="exfiltration"',
        ']',
      ].join('\n'),
      elastic: [
        '// {{TECHNIQUE}} — Exfiltration Detection',
        'network.bytes > 104857600 AND',
        '  destination.ip: NOT (10.* OR 172.16.* OR 192.168.*)',
        '| Stats sum(network.bytes) by source.ip, destination.ip',
      ].join('\n'),
      microsoft: [
        '// {{TECHNIQUE}} — Exfiltration Detection',
        'DeviceNetworkEvents',
        '| where RemoteIPType == "Public"',
        '| summarize TotalBytesSent=sum(SentBytes), Connections=count() by DeviceName, RemoteIP, RemoteUrl',
        '| where TotalBytesSent > 104857600',
        '| extend MB_Sent = round(TotalBytesSent / 1048576.0, 2)',
        '| extend Technique = "{{TECHNIQUE}}", Tactic = "exfiltration"',
        '| sort by TotalBytesSent desc',
      ].join('\n'),
      chronicle: [
        '// {{TECHNIQUE}} — Exfiltration Detection',
        'rule exfiltration_{{TECHNIQUE_SAFE}} {',
        '  meta:',
        '    description = "Detect data exfiltration for {{TECHNIQUE}}"',
        '  events:',
        '    $net.metadata.event_type = "NETWORK_CONNECTION"',
        '    $net.network.sent_bytes > 104857600',
        '    not net.is_internal($net.target.ip)',
        '  match:',
        '    $net.principal.hostname over 1h',
        '  condition:',
        '    $net',
        '}',
      ].join('\n'),
      crowdstrike: [
        '// {{TECHNIQUE}} — Exfiltration Detection',
        '#event_simpleName=NetworkConnectIP4',
        '| RemoteAddressIP4 != "10.*" AND RemoteAddressIP4 != "172.16.*" AND RemoteAddressIP4 != "192.168.*"',
        '| stats sum(BytesSent) as TotalBytesSent, count(aid) as Connections by aid, RemoteAddressIP4',
        '| where TotalBytesSent > 104857600',
        '| eval MB_Sent=TotalBytesSent/1048576',
        '| sort -MB_Sent',
      ].join('\n'),
    },
  },

  // ── Impact ─────────────────────────────────────────────────────────────────
  {
    tactic: 'impact',
    title: 'Ransomware Indicators, Data Destruction & Service Disruption',
    description: 'Detect ransomware file encryption patterns, mass file deletion, volume shadow copy deletion, and service stop events.',
    dataSource: 'File Events (Sysmon EID 11), Process Creation, Security EID 4688',
    confidence: 'high',
    platforms: {
      splunk: [
        '| ===== {{TECHNIQUE}} — Impact Detection =====',
        'index=main sourcetype=WinEventLog (EventCode=4688 OR EventCode=11)',
        '| search CommandLine IN ("*vssadmin delete shadows*","*wmic shadowcopy delete*","*bcdedit*","*wbadmin delete*") OR',
        '    TargetFilename="*.encrypted" OR TargetFilename="*.locked" OR TargetFilename="*.ransom"',
        '| stats count by Computer, User, CommandLine, TargetFilename',
        '| eval technique="{{TECHNIQUE}}", tactic="impact"',
        '| sort -count',
      ].join('\n'),
      elastic: [
        '// {{TECHNIQUE}} — Impact Detection',
        'process.command_line: (*"vssadmin delete shadows"* OR *"wmic shadowcopy delete"* OR *bcdedit* OR *"wbadmin delete"*) OR',
        '(file.extension: ("encrypted" OR "locked" OR "ransom"))',
      ].join('\n'),
      microsoft: [
        '// {{TECHNIQUE}} — Impact Detection',
        'DeviceProcessEvents',
        '| where ProcessCommandLine has_any ("vssadmin delete shadows","wmic shadowcopy delete","bcdedit /set","wbadmin delete")',
        '| union (',
        '  DeviceFileEvents | where FileName endswith ".encrypted" or FileName endswith ".locked"',
        ')',
        '| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine',
        '| extend Technique = "{{TECHNIQUE}}", Tactic = "impact"',
      ].join('\n'),
      chronicle: [
        '// {{TECHNIQUE}} — Impact Detection',
        'rule impact_{{TECHNIQUE_SAFE}} {',
        '  meta:',
        '    description = "Detect impact/destruction for {{TECHNIQUE}}"',
        '  events:',
        '    $proc.metadata.event_type = "PROCESS_LAUNCH"',
        '    re.regex($proc.target.process.command_line, `(?i)vssadmin delete|wmic shadowcopy delete|bcdedit|wbadmin delete`)',
        '  condition:',
        '    $proc',
        '}',
      ].join('\n'),
      crowdstrike: [
        '// {{TECHNIQUE}} — Impact Detection',
        '#event_simpleName=ProcessRollup2',
        '| CommandLine=/(vssadmin delete|wmic shadowcopy delete|bcdedit|wbadmin delete)/i',
        '| stats count(aid) as Events by aid, UserName, ImageFileName, CommandLine',
        '| sort -Events',
      ].join('\n'),
    },
  },

  // ── Reconnaissance ─────────────────────────────────────────────────────────
  {
    tactic: 'reconnaissance',
    title: 'External Scanning & Information Gathering',
    description: 'Detect external port scanning, OSINT tool usage, and information gathering activities targeting the organization.',
    dataSource: 'Firewall Logs, IDS/IPS Alerts, Web Server Logs',
    confidence: 'low',
    platforms: {
      splunk: [
        '| ===== {{TECHNIQUE}} — Reconnaissance Detection =====',
        'index=firewall sourcetype=pan:traffic action=denied',
        '| stats count as denied_count, dc(dest_port) as unique_ports by src_ip, dest_ip',
        '| where unique_ports > 20 OR denied_count > 100',
        '| eval technique="{{TECHNIQUE}}", tactic="reconnaissance"',
        '| sort -unique_ports',
      ].join('\n'),
      elastic: [
        '// {{TECHNIQUE}} — Reconnaissance Detection',
        'event.action: "denied" AND',
        '  source.ip: NOT (10.* OR 172.16.* OR 192.168.*)',
        '| Stats count by source.ip, destination.ip, destination.port',
      ].join('\n'),
      microsoft: [
        '// {{TECHNIQUE}} — Reconnaissance Detection',
        'DeviceNetworkEvents',
        '| where ActionType == "ConnectionFailed" and RemoteIPType == "Public"',
        '| summarize PortsScanned=dcount(RemotePort), AttemptCount=count() by RemoteIP, DeviceName',
        '| where PortsScanned > 20 or AttemptCount > 100',
        '| extend Technique = "{{TECHNIQUE}}", Tactic = "reconnaissance"',
      ].join('\n'),
      chronicle: [
        '// {{TECHNIQUE}} — Reconnaissance Detection',
        'rule recon_{{TECHNIQUE_SAFE}} {',
        '  meta:',
        '    description = "Detect reconnaissance activity for {{TECHNIQUE}}"',
        '  events:',
        '    $net.metadata.event_type = "NETWORK_CONNECTION"',
        '    $net.security_result.action = "BLOCK"',
        '    not net.is_internal($net.principal.ip)',
        '  match:',
        '    $net.principal.ip over 5m',
        '  condition:',
        '    #net > 100',
        '}',
      ].join('\n'),
      crowdstrike: [
        '// {{TECHNIQUE}} — Reconnaissance Detection',
        '#event_simpleName=NetworkConnectIP4',
        '| ConnectionFlags=BLOCKED',
        '| stats count(aid) as BlockedConnections, dc(RemotePort) as UniquePorts by RemoteAddressIP4',
        '| where UniquePorts > 20 OR BlockedConnections > 100',
        '| sort -UniquePorts',
      ].join('\n'),
    },
  },

  // ── Resource Development ───────────────────────────────────────────────────
  {
    tactic: 'resource-development',
    title: 'Infrastructure Acquisition & Tool Staging',
    description: 'Detect connections to newly registered domains, known staging infrastructure, and dynamic DNS providers.',
    dataSource: 'DNS Logs, Proxy Logs, Threat Intelligence Feeds',
    confidence: 'low',
    platforms: {
      splunk: [
        '| ===== {{TECHNIQUE}} — Resource Development Detection =====',
        'index=dns sourcetype=stream:dns',
        '| lookup domain_age_lookup domain AS query OUTPUT age_days',
        '| where age_days < 30 OR isnull(age_days)',
        '| stats count by src_ip, query, age_days',
        '| where count > 5',
        '| eval technique="{{TECHNIQUE}}", tactic="resource-development"',
        '| sort -count',
      ].join('\n'),
      elastic: [
        '// {{TECHNIQUE}} — Resource Development Detection',
        'dns.question.name: * AND',
        '  dns.question.name: (*.duckdns.org OR *.no-ip.com OR *.ngrok.io OR *.serveo.net)',
      ].join('\n'),
      microsoft: [
        '// {{TECHNIQUE}} — Resource Development Detection',
        'DeviceNetworkEvents',
        '| where RemoteUrl has_any (".duckdns.org",".no-ip.com",".ngrok.io",".serveo.net",".portmap.io")',
        '| summarize Connections=count() by DeviceName, RemoteUrl, RemoteIP',
        '| extend Technique = "{{TECHNIQUE}}", Tactic = "resource-development"',
      ].join('\n'),
      chronicle: [
        '// {{TECHNIQUE}} — Resource Development Detection',
        'rule resource_dev_{{TECHNIQUE_SAFE}} {',
        '  meta:',
        '    description = "Detect resource development for {{TECHNIQUE}}"',
        '  events:',
        '    $dns.metadata.event_type = "NETWORK_DNS"',
        '    re.regex($dns.network.dns.questions.name, `(?i)(duckdns\\.org|no-ip\\.com|ngrok\\.io|serveo\\.net)`)',
        '  condition:',
        '    $dns',
        '}',
      ].join('\n'),
      crowdstrike: [
        '// {{TECHNIQUE}} — Resource Development Detection',
        '#event_simpleName=DnsRequest',
        '| DomainName=/(duckdns\\.org|no-ip\\.com|ngrok\\.io|serveo\\.net)$/i',
        '| stats count(aid) as Requests by aid, ContextBaseFileName, DomainName',
        '| sort -Requests',
      ].join('\n'),
    },
  },
];

/**
 * Maps a tactic shortname from a technique to the best-matching template tactic.
 * Many ATT&CK tactics use hyphenated shortnames that match our template keys directly.
 */
function matchTactic(tacticShortname: string): string | null {
  const direct = TACTIC_TEMPLATES.find(t => t.tactic === tacticShortname);
  if (direct) return direct.tactic;
  // Fuzzy fallback
  const normalized = tacticShortname.toLowerCase().replace(/[\s_]/g, '-');
  const fuzzy = TACTIC_TEMPLATES.find(t => t.tactic === normalized);
  return fuzzy ? fuzzy.tactic : null;
}

@Injectable({ providedIn: 'root' })
export class SiemQueryService {
  private readonly platforms: Array<SiemQuery['platform']> = [
    'splunk', 'elastic', 'microsoft', 'chronicle', 'crowdstrike',
  ];

  /**
   * Return all platform queries for a given ATT&CK technique and tactic.
   * If tactic is empty or unknown, falls back to execution or returns empty.
   */
  getQueriesForTechnique(attackId: string, tactic: string): SiemQuery[] {
    const matched = matchTactic(tactic);
    if (!matched) return [];

    const template = TACTIC_TEMPLATES.find(t => t.tactic === matched);
    if (!template) return [];

    const safeTechId = attackId.replace(/\./g, '_');

    return this.platforms.map(platform => ({
      platform,
      platformLabel: PLATFORM_LABELS[platform] ?? platform,
      query: template.platforms[platform]
        .replace(/\{\{TECHNIQUE\}\}/g, attackId)
        .replace(/\{\{TECHNIQUE_NAME\}\}/g, attackId)
        .replace(/\{\{TECHNIQUE_SAFE\}\}/g, safeTechId),
      title: `${template.title} (${attackId})`,
      description: template.description,
      dataSource: template.dataSource,
      confidence: template.confidence,
    }));
  }

  /**
   * Return a single query for a specific platform.
   */
  getQueryForPlatform(attackId: string, tactic: string, platform: SiemQuery['platform']): SiemQuery | null {
    const queries = this.getQueriesForTechnique(attackId, tactic);
    return queries.find(q => q.platform === platform) ?? null;
  }

  /**
   * Return all supported platform identifiers.
   */
  getAllPlatforms(): Array<SiemQuery['platform']> {
    return [...this.platforms];
  }

  /**
   * Return all available tactic template names.
   */
  getAvailableTactics(): string[] {
    return TACTIC_TEMPLATES.map(t => t.tactic);
  }

  /**
   * Return queries for all matching tactics of a technique.
   * A technique may belong to multiple tactics; returns unique queries across all.
   */
  getAllQueriesForTechnique(attackId: string, tacticShortnames: string[]): SiemQuery[] {
    const seen = new Set<string>();
    const results: SiemQuery[] = [];
    for (const tactic of tacticShortnames) {
      const queries = this.getQueriesForTechnique(attackId, tactic);
      for (const q of queries) {
        const key = `${q.platform}:${q.title}`;
        if (!seen.has(key)) {
          seen.add(key);
          results.push(q);
        }
      }
    }
    return results;
  }
}
