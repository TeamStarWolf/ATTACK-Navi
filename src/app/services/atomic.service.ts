import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

/** Rich test record fetched live from the Atomic Red Team GitHub YAML index. */
export interface AtomicLiveTest {
  name: string;
  description: string;       // first 250 chars of description
  platforms: string[];
  executorName: string;      // 'powershell', 'command_prompt', 'bash', 'sh', 'manual'
  guid: string;
  attackId: string;
  githubUrl: string;
}

export interface AtomicTest {
  attackId: string;        // ATT&CK technique ID (e.g. "T1059.001")
  name: string;            // Test name
  platforms: string[];
  inputArgs?: string;      // Brief description of what inputs are needed
  url: string;             // Link to the atomic test on GitHub
}

interface AtomicNavigatorLayer {
  name?: string;
  domain?: string;
  techniques: Array<{
    techniqueID: string;
    score?: number;
    tactic?: string;
    enabled?: boolean;
  }>;
}

// Bundled detail records for key techniques — used for sidebar view.
// Full counts come from the live Navigator layer fetch.
const ATOMIC_DETAIL_TESTS: AtomicTest[] = [
  // T1059 - Command and Scripting Interpreter
  { attackId: 'T1059.001', name: 'PowerShell Download', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md', inputArgs: 'Remote file URL' },
  { attackId: 'T1059.001', name: 'Mimikatz PowerShell', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md', inputArgs: 'None' },
  { attackId: 'T1059.001', name: 'PowerShell Encoded Command', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md', inputArgs: 'Encoded command string' },
  { attackId: 'T1059.003', name: 'Create and Execute Bat File', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md', inputArgs: 'None' },
  { attackId: 'T1059.003', name: 'Cmd.exe Used to Run Commands', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md', inputArgs: 'None' },
  { attackId: 'T1059.004', name: 'Bash Reverse Shell', platforms: ['Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md', inputArgs: 'Attacker IP, port' },
  { attackId: 'T1059.006', name: 'Python Script Execution', platforms: ['Linux', 'macOS', 'Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.006/T1059.006.md', inputArgs: 'None' },
  { attackId: 'T1059.007', name: 'JavaScript via Node.js', platforms: ['Windows', 'Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md', inputArgs: 'None' },
  // T1055 - Process Injection
  { attackId: 'T1055.001', name: 'Process Injection via mavinject.exe', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md', inputArgs: 'Target PID, DLL path' },
  { attackId: 'T1055.002', name: 'PE Injection via PowerShell', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.002/T1055.002.md', inputArgs: 'None' },
  { attackId: 'T1055.012', name: 'Process Hollowing', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.012/T1055.012.md', inputArgs: 'None' },
  // T1003 - Credential Dumping
  { attackId: 'T1003.001', name: 'Dump LSASS via ProcDump', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md', inputArgs: 'ProcDump path' },
  { attackId: 'T1003.001', name: 'Dump LSASS via Task Manager', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md', inputArgs: 'None' },
  { attackId: 'T1003.001', name: 'Mimikatz sekurlsa::logonpasswords', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md', inputArgs: 'Mimikatz binary' },
  { attackId: 'T1003.002', name: 'Registry Dump of SAM', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md', inputArgs: 'None' },
  { attackId: 'T1003.003', name: 'NTDS.dit File Extraction', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md', inputArgs: 'None' },
  // T1078 - Valid Accounts
  { attackId: 'T1078.002', name: 'Create Admin Account', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.002/T1078.002.md', inputArgs: 'Username, password' },
  { attackId: 'T1078.003', name: 'SSH Login with Valid Credentials', platforms: ['Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md', inputArgs: 'SSH host, user, key' },
  // T1021 - Remote Services
  { attackId: 'T1021.001', name: 'RDP to DomainController', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md', inputArgs: 'DC hostname, credentials' },
  { attackId: 'T1021.002', name: 'Net Use to Map Share', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md', inputArgs: 'Share path' },
  { attackId: 'T1021.004', name: 'SSH Remote Execution', platforms: ['Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md', inputArgs: 'SSH host, user' },
  { attackId: 'T1021.006', name: 'WinRM Remote Execute', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.006/T1021.006.md', inputArgs: 'Remote host, credentials' },
  // T1053 - Scheduled Task/Job
  { attackId: 'T1053.005', name: 'Scheduled Task Startup Script', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md', inputArgs: 'None' },
  { attackId: 'T1053.005', name: 'Scheduled Task Lateral Movement', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md', inputArgs: 'Remote host' },
  { attackId: 'T1053.003', name: 'Cron Job File Write', platforms: ['Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.003/T1053.003.md', inputArgs: 'None' },
  // T1566 - Phishing
  { attackId: 'T1566.001', name: 'Send Spearphishing Email with Attachment', platforms: ['Windows', 'macOS', 'Linux'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md', inputArgs: 'Recipient email, payload file' },
  { attackId: 'T1566.002', name: 'Spearphishing Link via Outlook', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md', inputArgs: 'Target email' },
  // T1047 - WMI
  { attackId: 'T1047', name: 'WMI Reconnaissance', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md', inputArgs: 'None' },
  { attackId: 'T1047', name: 'Remote WMI Execute', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md', inputArgs: 'Remote host, credentials' },
  // T1027 - Obfuscated Files
  { attackId: 'T1027', name: 'Encode Payload via Certutil', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md', inputArgs: 'Input file' },
  { attackId: 'T1027', name: 'XOR Payload Encoding', platforms: ['Windows', 'Linux'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md', inputArgs: 'Payload file' },
  { attackId: 'T1027.010', name: 'Command Obfuscation via PowerShell', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.010/T1027.010.md', inputArgs: 'None' },
  // T1110 - Brute Force
  { attackId: 'T1110.001', name: 'Password Guessing via Hydra', platforms: ['Linux'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.001/T1110.001.md', inputArgs: 'Target, wordlist' },
  { attackId: 'T1110.003', name: 'Password Spray via Spray.ps1', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md', inputArgs: 'User list, target domain' },
  // T1070 - Indicator Removal
  { attackId: 'T1070.001', name: 'Clear Windows Event Logs', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md', inputArgs: 'None' },
  { attackId: 'T1070.004', name: 'Delete a Single File', platforms: ['Windows', 'Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md', inputArgs: 'File path' },
  { attackId: 'T1070.006', name: 'Timestomp File Modification', platforms: ['Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md', inputArgs: 'Target file' },
  // T1547 - Boot Persistence
  { attackId: 'T1547.001', name: 'HKCU\\Run Key Persistence', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md', inputArgs: 'None' },
  { attackId: 'T1547.001', name: 'Startup Folder Persistence', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md', inputArgs: 'Executable path' },
  // T1548 - Privilege Escalation
  { attackId: 'T1548.002', name: 'Bypass UAC via fodhelper', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md', inputArgs: 'None' },
  { attackId: 'T1548.002', name: 'Bypass UAC via EventViewer', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md', inputArgs: 'None' },
  // T1082 - System Info Discovery
  { attackId: 'T1082', name: 'System Info Discovery via systeminfo', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md', inputArgs: 'None' },
  { attackId: 'T1082', name: 'System Info via uname', platforms: ['Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md', inputArgs: 'None' },
  // T1046 - Network Scanning
  { attackId: 'T1046', name: 'Port Scan via nmap', platforms: ['Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md', inputArgs: 'Target subnet' },
  { attackId: 'T1046', name: 'Port Scan via PowerShell', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md', inputArgs: 'Target host' },
  // T1041 - Exfiltration over C2
  { attackId: 'T1041', name: 'Exfiltration via PowerShell WebClient', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md', inputArgs: 'Exfil server URL' },
  // T1048 - Exfiltration via Alternative Protocol
  { attackId: 'T1048.003', name: 'Exfiltration via DNS TXT', platforms: ['Linux'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md', inputArgs: 'DNS server' },
  // T1190 - Exploit Public-Facing Application
  { attackId: 'T1190', name: 'SQL Injection via sqlmap', platforms: ['Linux'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1190/T1190.md', inputArgs: 'Target URL' },
  // T1136 - Create Account
  { attackId: 'T1136.001', name: 'Create a Local Account', platforms: ['Windows', 'Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md', inputArgs: 'Username, password' },
  { attackId: 'T1136.002', name: 'Create Domain Account', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.002/T1136.002.md', inputArgs: 'Username, domain' },
  // T1098 - Account Manipulation
  { attackId: 'T1098.001', name: 'Add to Domain Admin Group', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.001/T1098.001.md', inputArgs: 'Username' },
  { attackId: 'T1098.004', name: 'SSH Authorized Key Persistence', platforms: ['Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.004/T1098.004.md', inputArgs: 'Public key' },
  // T1112 - Modify Registry
  { attackId: 'T1112', name: 'Modify Registry Value', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md', inputArgs: 'Registry path, value' },
  { attackId: 'T1112', name: 'Disable Security via Registry', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md', inputArgs: 'None' },
  // T1562 - Impair Defenses
  { attackId: 'T1562.001', name: 'Disable Windows Defender', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md', inputArgs: 'None' },
  { attackId: 'T1562.004', name: 'Disable Windows Firewall', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.004/T1562.004.md', inputArgs: 'None' },
  // T1543 - Create or Modify System Process
  { attackId: 'T1543.003', name: 'Create Windows Service', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md', inputArgs: 'Service name, binary path' },
  { attackId: 'T1543.001', name: 'Launch Agent Persistence', platforms: ['macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.001/T1543.001.md', inputArgs: 'Plist path' },
  // T1204 - User Execution
  { attackId: 'T1204.001', name: 'Execute Malicious Link', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.001/T1204.001.md', inputArgs: 'URL' },
  { attackId: 'T1204.002', name: 'Execute Malicious Attachment', platforms: ['Windows', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md', inputArgs: 'Attachment file' },
  // T1485 - Data Destruction
  { attackId: 'T1485', name: 'rm -rf Recursive Deletion', platforms: ['Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md', inputArgs: 'Target path' },
  { attackId: 'T1485', name: 'Format Volume via cmd', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md', inputArgs: 'Drive letter' },
  // T1490 - Inhibit System Recovery
  { attackId: 'T1490', name: 'Disable System Recovery via bcdedit', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md', inputArgs: 'None' },
  { attackId: 'T1490', name: 'Delete VSS Shadow Copies', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md', inputArgs: 'None' },
  // T1560 - Archive Collected Data
  { attackId: 'T1560.001', name: 'Compress Data with 7-Zip', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md', inputArgs: 'Source dir, 7-Zip path' },
  { attackId: 'T1560.001', name: 'Archive Files with tar', platforms: ['Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md', inputArgs: 'Source dir' },
  // T1197 - BITS Jobs
  { attackId: 'T1197', name: 'BITSAdmin Download via HTTP', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md', inputArgs: 'URL, local path' },
  // T1218 - System Binary Proxy Execution
  { attackId: 'T1218.010', name: 'Execute via Regsvr32', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md', inputArgs: 'SCT file URL' },
  { attackId: 'T1218.011', name: 'Rundll32 Execution', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md', inputArgs: 'DLL path' },
  { attackId: 'T1218.005', name: 'Mshta Execute JavaScript', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md', inputArgs: 'URL or file' },
  // T1105 - Ingress Tool Transfer
  { attackId: 'T1105', name: 'Download via PowerShell', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md', inputArgs: 'URL, local path' },
  { attackId: 'T1105', name: 'Download via certutil', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md', inputArgs: 'URL, local path' },
  { attackId: 'T1105', name: 'Download via curl', platforms: ['Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md', inputArgs: 'URL' },
  // T1036 - Masquerading
  { attackId: 'T1036.003', name: 'Rename System Utilities', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.md', inputArgs: 'Binary name' },
  { attackId: 'T1036.005', name: 'Masquerade as Legitimate Executable', platforms: ['Windows', 'Linux'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md', inputArgs: 'Binary path' },
  // T1574 - Hijack Execution Flow
  { attackId: 'T1574.001', name: 'DLL Search Order Hijacking', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md', inputArgs: 'DLL path' },
  { attackId: 'T1574.002', name: 'DLL Side-Loading', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.002/T1574.002.md', inputArgs: 'DLL path' },
  // T1087 - Account Discovery
  { attackId: 'T1087.001', name: 'Enumerate Local Accounts', platforms: ['Windows', 'Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md', inputArgs: 'None' },
  { attackId: 'T1087.002', name: 'Enumerate Domain Accounts', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md', inputArgs: 'None' },
  // T1069 - Permission Groups Discovery
  { attackId: 'T1069.001', name: 'Local Groups Enumeration', platforms: ['Windows', 'Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md', inputArgs: 'None' },
  { attackId: 'T1069.002', name: 'Domain Groups Enumeration', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md', inputArgs: 'None' },
  // T1040 - Network Sniffing
  { attackId: 'T1040', name: 'Packet Capture via tcpdump', platforms: ['Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md', inputArgs: 'Interface name' },
  // T1083 - File and Directory Discovery
  { attackId: 'T1083', name: 'File/Dir Discovery via dir', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md', inputArgs: 'None' },
  { attackId: 'T1083', name: 'Find Command for Sensitive Files', platforms: ['Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md', inputArgs: 'None' },
  // T1552 - Unsecured Credentials
  { attackId: 'T1552.001', name: 'Find Credentials in Files', platforms: ['Linux', 'macOS', 'Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md', inputArgs: 'None' },
  { attackId: 'T1552.002', name: 'Credentials in Registry', platforms: ['Windows'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.002/T1552.002.md', inputArgs: 'None' },
  // T1505 - Server Software Component
  { attackId: 'T1505.003', name: 'Web Shell via Chinese Chopper', platforms: ['Windows', 'Linux'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md', inputArgs: 'Web server path' },
  // T1071 - Application Layer Protocol C2
  { attackId: 'T1071.001', name: 'C2 over HTTP', platforms: ['Windows', 'Linux', 'macOS'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md', inputArgs: 'C2 server URL' },
  { attackId: 'T1071.004', name: 'DNS C2 Exfiltration', platforms: ['Linux'], url: 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md', inputArgs: 'DNS server' },
];

@Injectable({ providedIn: 'root' })
export class AtomicService {
  // Published by Red Canary — ATT&CK Navigator layer with test counts per technique.
  private static readonly NAVIGATOR_LAYER_URL =
    'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/Attack-Navigator-Layers/art-navigator-layer.json';

  // Per-technique YAML base URL — fetch on demand
  private static readonly YAML_BASE_URL =
    'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics';

  // Live counts from the Navigator layer (techniqueID → test count)
  private directCounts = new Map<string, number>();
  // Detail index from hardcoded records (for sidebar view)
  private byAttackId = new Map<string, AtomicTest[]>();
  // Live tests fetched from GitHub YAML (per technique, cached)
  private liveTestCache = new Map<string, AtomicLiveTest[]>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  readonly total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  readonly covered$ = this.coveredSubject.asObservable();

  constructor(private http: HttpClient) {
    this.buildDetailIndex();
    this.fetchNavigatorLayer();
  }

  // ─── Public API ──────────────────────────────────────────────────────────────

  /** Returns ATT&CK test count for a technique (prefers live data over hardcoded). */
  getTestCount(attackId: string): number {
    if (this.directCounts.size > 0) {
      return this.getLiveCount(attackId);
    }
    return this.getDetailTests(attackId).length;
  }

  /** Alias used by matrix heatmap. */
  getHeatScore(attackId: string): number {
    return this.getTestCount(attackId);
  }

  /** Returns detailed test records for sidebar view (hardcoded for known techniques). */
  getTests(attackId: string): AtomicTest[] {
    return this.getDetailTests(attackId);
  }

  /** GitHub link for a technique's Atomic Red Team page. */
  getAtomicUrl(attackId: string): string {
    return `https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/${attackId}/${attackId}.md`;
  }

  /** Returns the full live counts map (techniqueID → count). */
  getLiveCounts(): ReadonlyMap<string, number> {
    return this.directCounts;
  }

  getAll(): AtomicTest[] {
    return ATOMIC_DETAIL_TESTS;
  }

  /**
   * Fetch up to `limit` real test records from Atomic Red Team GitHub YAML.
   * Returns cached results on repeat calls. Falls back to [] on network error.
   */
  fetchLiveTests(attackId: string, limit = 5): Observable<AtomicLiveTest[]> {
    if (this.liveTestCache.has(attackId)) {
      return of(this.liveTestCache.get(attackId)!.slice(0, limit));
    }

    const url = `${AtomicService.YAML_BASE_URL}/${attackId}/${attackId}.yaml`;
    return this.http.get(url, { responseType: 'text' }).pipe(
      map(yaml => {
        const tests = this.parseAtomicYaml(yaml, attackId);
        this.liveTestCache.set(attackId, tests);
        return tests.slice(0, limit);
      }),
      catchError(() => of([])),
    );
  }

  // ─── Private helpers ─────────────────────────────────────────────────────────

  /**
   * Parse Atomic Red Team YAML to extract test records.
   * Uses a simple line-based parser specific to the ART YAML format.
   */
  private parseAtomicYaml(yaml: string, attackId: string): AtomicLiveTest[] {
    const tests: AtomicLiveTest[] = [];
    // Split on top-level list items (each test starts with "- name:")
    const lines = yaml.split('\n');
    let inTests = false;
    let currentTest: Partial<AtomicLiveTest> | null = null;
    let descLines: string[] = [];
    let inDescription = false;
    let inPlatforms = false;
    let inExecutor = false;
    let executorIndent = -1;

    const pushCurrent = () => {
      if (currentTest?.name) {
        const desc = descLines.join(' ').replace(/\s+/g, ' ').trim().slice(0, 280);
        tests.push({
          name: currentTest.name,
          description: desc,
          platforms: currentTest.platforms ?? [],
          executorName: currentTest.executorName ?? 'manual',
          guid: currentTest.guid ?? '',
          attackId,
          githubUrl: `https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/${attackId}/${attackId}.md`,
        });
      }
      currentTest = null;
      descLines = [];
      inDescription = false;
      inPlatforms = false;
      inExecutor = false;
      executorIndent = -1;
    };

    for (const rawLine of lines) {
      const line = rawLine;
      const trimmed = line.trim();
      const indent = line.length - line.trimStart().length;

      // Detect start of atomic_tests section
      if (trimmed === 'atomic_tests:') { inTests = true; continue; }
      if (!inTests) continue;

      // New test item
      if (trimmed.startsWith('- name:') && indent === 0) {
        pushCurrent();
        currentTest = { name: trimmed.slice(7).trim().replace(/^['"]|['"]$/g, ''), platforms: [] };
        continue;
      }
      if (!currentTest) continue;

      // GUID
      if (trimmed.startsWith('auto_generated_guid:')) {
        currentTest.guid = trimmed.slice(20).trim().replace(/^['"]|['"]$/g, '');
        inDescription = false; inPlatforms = false; inExecutor = false;
        continue;
      }

      // Description block
      if (trimmed.startsWith('description:')) {
        inDescription = true; inPlatforms = false; inExecutor = false;
        const inline = trimmed.slice(12).trim().replace(/^\|/, '').trim();
        if (inline && inline !== '|') descLines.push(inline);
        continue;
      }

      // Platforms
      if (trimmed === 'supported_platforms:') {
        inPlatforms = true; inDescription = false; inExecutor = false;
        continue;
      }
      if (inPlatforms && trimmed.startsWith('- ')) {
        currentTest.platforms = currentTest.platforms ?? [];
        currentTest.platforms.push(trimmed.slice(2).trim().replace(/^['"]|['"]$/g, ''));
        continue;
      }
      if (inPlatforms && !trimmed.startsWith('- ')) {
        inPlatforms = false;
      }

      // Executor block
      if (trimmed === 'executor:') {
        inExecutor = true; inDescription = false; inPlatforms = false;
        executorIndent = indent;
        continue;
      }
      if (inExecutor && trimmed.startsWith('name:')) {
        currentTest.executorName = trimmed.slice(5).trim().replace(/^['"]|['"]$/g, '');
        inExecutor = false;
        continue;
      }
      if (inExecutor && (indent <= executorIndent && trimmed.length > 0 && !trimmed.startsWith('#'))) {
        inExecutor = false;
      }

      // Collect description lines
      if (inDescription) {
        if (trimmed === '' || (indent < 2 && trimmed.length > 0 && !trimmed.startsWith('#') &&
            !trimmed.startsWith('- ') && trimmed.includes(':') && !trimmed.startsWith('http'))) {
          inDescription = false;
        } else {
          descLines.push(trimmed);
        }
      }
    }
    pushCurrent();

    return tests;
  }

  private buildDetailIndex(): void {
    for (const test of ATOMIC_DETAIL_TESTS) {
      if (!this.byAttackId.has(test.attackId)) this.byAttackId.set(test.attackId, []);
      this.byAttackId.get(test.attackId)!.push(test);
    }
  }

  private fetchNavigatorLayer(): void {
    this.http.get<AtomicNavigatorLayer>(AtomicService.NAVIGATOR_LAYER_URL).subscribe({
      next: (layer) => this.ingestLayer(layer),
      error: () => {
        // Network unavailable — service falls back to hardcoded counts silently
        this.loadedSubject.next(false);
      },
    });
  }

  private ingestLayer(layer: AtomicNavigatorLayer): void {
    this.directCounts.clear();
    let totalTests = 0;
    let coveredTechs = 0;

    for (const entry of layer.techniques ?? []) {
      const id = entry.techniqueID;
      const score = entry.score ?? 0;
      if (!id || score <= 0) continue;

      this.directCounts.set(id, score);
      totalTests += score;
      coveredTechs++;
    }

    this.totalSubject.next(totalTests);
    this.coveredSubject.next(coveredTechs);
    this.loadedSubject.next(true);
  }

  /**
   * Compute test count for a technique ID from live directCounts.
   * For a parent ID (e.g. T1059): returns own count + all sub counts.
   * For a sub ID (e.g. T1059.001): returns own count only.
   */
  private getLiveCount(attackId: string): number {
    const direct = this.directCounts.get(attackId) ?? 0;
    if (attackId.includes('.')) return direct;

    // Aggregate subtechnique counts into parent total
    let sub = 0;
    const prefix = attackId + '.';
    for (const [id, count] of this.directCounts) {
      if (id.startsWith(prefix)) sub += count;
    }
    return direct + sub;
  }

  private getDetailTests(attackId: string): AtomicTest[] {
    const direct = this.byAttackId.get(attackId) ?? [];
    const parentId = attackId.includes('.') ? attackId.split('.')[0] : null;
    const fromParent = parentId ? (this.byAttackId.get(parentId) ?? []) : [];
    const prefix = attackId + '.';
    const fromSubs = attackId.includes('.')
      ? []
      : [...this.byAttackId.entries()]
          .filter(([k]) => k.startsWith(prefix))
          .flatMap(([, v]) => v);
    const seen = new Set<string>();
    const all: AtomicTest[] = [];
    for (const t of [...direct, ...fromParent, ...fromSubs]) {
      const key = t.attackId + '|' + t.name;
      if (!seen.has(key)) { seen.add(key); all.push(t); }
    }
    return all;
  }

  // ─── Invoke-AtomicRedTeam Command Generation ────────────────────────────────

  /**
   * Generate a PowerShell script to install Invoke-AtomicRedTeam and run a
   * specific technique test (or all tests for the technique).
   */
  generateInvokeCommand(attackId: string, testNumber?: number): string {
    const lines = [
      '# Install Invoke-AtomicRedTeam if needed',
      "IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)",
      'Install-AtomicRedTeam -getAtomics',
      '',
      `# Run test for ${attackId}`,
    ];
    if (testNumber !== undefined) {
      lines.push(`Invoke-AtomicTest ${attackId} -TestNumbers ${testNumber}`);
    } else {
      lines.push(`Invoke-AtomicTest ${attackId}`);
    }
    return lines.join('\n');
  }

  /** Generate a cleanup command for a technique. */
  generateCleanupCommand(attackId: string): string {
    return `Invoke-AtomicTest ${attackId} -Cleanup`;
  }

  /** Generate a batch execution script for multiple techniques. */
  generateAllTestsScript(attackIds: string[]): string {
    if (attackIds.length === 0) return '# No techniques selected';
    const lines = [
      '# Invoke-AtomicRedTeam Batch Execution Script',
      '# Install Invoke-AtomicRedTeam if needed',
      "IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)",
      'Install-AtomicRedTeam -getAtomics',
      '',
      `# Run tests for ${attackIds.length} techniques`,
    ];
    for (const id of attackIds) {
      lines.push(`Write-Host "Running tests for ${id}..." -ForegroundColor Cyan`);
      lines.push(`Invoke-AtomicTest ${id}`);
      lines.push('');
    }
    lines.push('Write-Host "All tests complete." -ForegroundColor Green');
    return lines.join('\n');
  }
}
