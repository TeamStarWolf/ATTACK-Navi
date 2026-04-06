// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';

export interface OffensiveTool {
  name: string;
  category: string;
  techniqueIds: string[];
  description: string;
  url: string;
}

const TOOLS: OffensiveTool[] = [
  // Credential Access
  { name: 'Mimikatz', category: 'Credential Dumping', techniqueIds: ['T1003.001', 'T1003.002', 'T1003.004', 'T1003.005', 'T1003.006', 'T1558.001', 'T1558.002', 'T1550.002', 'T1550.003'], description: 'Windows credential extraction', url: 'https://github.com/gentilkiwi/mimikatz' },
  { name: 'Rubeus', category: 'Kerberos', techniqueIds: ['T1558.003', 'T1558.004', 'T1558.001', 'T1550.003'], description: 'Kerberos interaction and abuse', url: 'https://github.com/GhostPack/Rubeus' },
  { name: 'Impacket', category: 'Network Protocols', techniqueIds: ['T1003.003', 'T1003.006', 'T1021.002', 'T1021.003', 'T1047', 'T1569.002'], description: 'Python network protocol implementations', url: 'https://github.com/fortra/impacket' },
  // Discovery
  { name: 'BloodHound', category: 'AD Enumeration', techniqueIds: ['T1087.002', 'T1069.002', 'T1482'], description: 'Active Directory relationship mapper', url: 'https://github.com/BloodHoundAD/BloodHound' },
  { name: 'SharpHound', category: 'AD Collection', techniqueIds: ['T1087.002', 'T1069.002', 'T1018'], description: 'BloodHound data collector', url: 'https://github.com/BloodHoundAD/SharpHound' },
  { name: 'PowerView', category: 'AD Enumeration', techniqueIds: ['T1087.002', 'T1069.002', 'T1482', 'T1018'], description: 'PowerShell AD enumeration', url: 'https://github.com/PowerShellMafia/PowerSploit' },
  { name: 'Nmap', category: 'Network Scanning', techniqueIds: ['T1046', 'T1595.001'], description: 'Network discovery and security auditing', url: 'https://github.com/nmap/nmap' },
  // Lateral Movement
  { name: 'CrackMapExec', category: 'Lateral Movement', techniqueIds: ['T1021.002', 'T1021.001', 'T1021.006', 'T1110', 'T1047'], description: 'Swiss army knife for Windows/AD', url: 'https://github.com/byt3bl33d3r/CrackMapExec' },
  { name: 'Evil-WinRM', category: 'Remote Access', techniqueIds: ['T1021.006'], description: 'WinRM shell for pentesting', url: 'https://github.com/Hackplayers/evil-winrm' },
  { name: 'PSExec', category: 'Remote Execution', techniqueIds: ['T1021.002', 'T1569.002'], description: 'Remote command execution via SMB', url: 'https://docs.microsoft.com/sysinternals/downloads/psexec' },
  // Execution
  { name: 'Ghidra', category: 'Reverse Engineering', techniqueIds: ['T1588.002'], description: 'NSA reverse engineering framework', url: 'https://github.com/NationalSecurityAgency/ghidra' },
  { name: 'ScareCrow', category: 'Payload Generation', techniqueIds: ['T1055', 'T1027', 'T1140'], description: 'Payload creation for EDR bypass', url: 'https://github.com/optiv/ScareCrow' },
  // Exploitation
  { name: 'Metasploit', category: 'Exploitation', techniqueIds: ['T1190', 'T1203', 'T1210', 'T1059'], description: 'Penetration testing framework', url: 'https://github.com/rapid7/metasploit-framework' },
  { name: 'Nuclei', category: 'Vulnerability Scanning', techniqueIds: ['T1595.002', 'T1190'], description: 'Fast vulnerability scanner', url: 'https://github.com/projectdiscovery/nuclei' },
  // C2
  { name: 'Sliver', category: 'C2 Framework', techniqueIds: ['T1071.001', 'T1071.004', 'T1573.002', 'T1055'], description: 'Open source C2 framework', url: 'https://github.com/BishopFox/sliver' },
  { name: 'Cobalt Strike', category: 'C2 Framework', techniqueIds: ['T1071.001', 'T1573', 'T1055', 'T1059.001'], description: 'Commercial adversary simulation', url: 'https://www.cobaltstrike.com/' },
  // Phishing
  { name: 'GoPhish', category: 'Phishing', techniqueIds: ['T1566.001', 'T1566.002', 'T1598'], description: 'Phishing simulation', url: 'https://github.com/gophish/gophish' },
  // Network
  { name: 'Responder', category: 'Name Poisoning', techniqueIds: ['T1557.001'], description: 'LLMNR/NBT-NS/MDNS poisoner', url: 'https://github.com/lgandx/Responder' },
  { name: 'Wireshark', category: 'Packet Analysis', techniqueIds: ['T1040'], description: 'Network protocol analyzer', url: 'https://www.wireshark.org/' },
  // Persistence
  { name: 'SharPersist', category: 'Persistence', techniqueIds: ['T1053.005', 'T1547.001', 'T1543.003'], description: 'Windows persistence toolkit', url: 'https://github.com/mandiant/SharPersist' },
  // Evasion
  { name: 'SharpWitness', category: 'Screenshot', techniqueIds: ['T1113', 'T1595.002'], description: 'Website screenshot tool', url: 'https://github.com/Relkci/SharpWitness' },
  // From followed researchers
  { name: 'GraphRunner', category: 'Cloud Attack', techniqueIds: ['T1528', 'T1098.003', 'T1078.004', 'T1114', 'T1213'], description: 'Post-exploitation for Microsoft Graph API (dafthack)', url: 'https://github.com/dafthack/GraphRunner' },
  { name: 'BloodHound Custom Queries', category: 'AD Enumeration', techniqueIds: ['T1087.002', 'T1069.002', 'T1482', 'T1078'], description: 'Custom BloodHound queries for AD attacks (dafthack)', url: 'https://github.com/dafthack/Bloodhound-Custom-Queries' },
  { name: 'HiveNightmare', category: 'Privilege Escalation', techniqueIds: ['T1003.002', 'T1068'], description: 'Read SAM/SYSTEM/SECURITY hives as non-admin (GossiTheDog)', url: 'https://github.com/GossiTheDog/HiveNightmare' },
  { name: 'SystemNightmare', category: 'Privilege Escalation', techniqueIds: ['T1068', 'T1548'], description: 'Instant SYSTEM prompt on Windows (GossiTheDog)', url: 'https://github.com/GossiTheDog/SystemNightmare' },
  { name: 'Sysmon Config', category: 'Detection', techniqueIds: ['T1059', 'T1547', 'T1003', 'T1055'], description: 'High-quality Sysmon config template (GossiTheDog)', url: 'https://github.com/GossiTheDog/sysmon-config' },
  { name: 'SharpSphere', category: 'Lateral Movement', techniqueIds: ['T1021', 'T1059'], description: '.NET tool for attacking vCenter (Relkci)', url: 'https://github.com/Relkci/SharpSphere' },
  { name: 'DPAT', category: 'Credential Audit', techniqueIds: ['T1110', 'T1078'], description: 'Domain Password Audit Tool (Relkci)', url: 'https://github.com/Relkci/DPAT' },
  { name: 'PowerMeta', category: 'Reconnaissance', techniqueIds: ['T1593', 'T1589.002', 'T1592'], description: 'Metadata extraction from public documents (Relkci)', url: 'https://github.com/Relkci/PowerMeta' },
  { name: 'Find-WSUS', category: 'Defense', techniqueIds: ['T1195.002', 'T1557'], description: 'Find WSUS configs for CVE-2025-59287 (mubix)', url: 'https://github.com/mubix/Find-WSUS' },
  { name: 'reCAPTCHA Phish', category: 'Phishing', techniqueIds: ['T1566.002', 'T1189', 'T1204.001'], description: 'Phishing with fake reCAPTCHA (JohnHammond)', url: 'https://github.com/JohnHammond/recaptcha-phish' },
  { name: 'BeaKer', category: 'Visualization', techniqueIds: ['T1040', 'T1071.001'], description: 'Elasticsearch Kibana analytics for Zeek (mon0pixel)', url: 'https://github.com/mon0pixel/BeaKer' },
  { name: 'GoSpoof', category: 'Network Spoofing', techniqueIds: ['T1557', 'T1557.001'], description: 'DNS spoofing tool (blackhillsinfosec)', url: 'https://github.com/blackhillsinfosec/GoSpoof' },
  { name: 'WindowsAuditing', category: 'Defense', techniqueIds: ['T1059', 'T1547', 'T1003', 'T1078'], description: 'Windows audit policy configuration (blackhillsinfosec)', url: 'https://github.com/blackhillsinfosec/WindowsAuditing' },
  // Well-known tools from starred repos
  { name: 'SecLists', category: 'Wordlists', techniqueIds: ['T1110', 'T1595.003', 'T1190'], description: 'Security tester companion wordlists', url: 'https://github.com/danielmiessler/SecLists' },
  { name: 'OpenSesame', category: 'Physical', techniqueIds: ['T1200'], description: 'Wireless garage door opener attack (samyk)', url: 'https://github.com/samyk/opensesame' },
  { name: 'Invoke-AtomicRedTeam', category: 'Validation', techniqueIds: ['T1059.001', 'T1204.002'], description: 'PowerShell Atomic test executor', url: 'https://github.com/redcanaryco/invoke-atomicredteam' },
  { name: 'log4j-scanner', category: 'Vulnerability Scanning', techniqueIds: ['T1190', 'T1059'], description: 'CISA Log4j vulnerability scanner', url: 'https://github.com/cisagov/log4j-scanner' },
  { name: 'Commando-VM', category: 'Offensive Platform', techniqueIds: ['T1059', 'T1588.002'], description: 'Windows offensive distribution (Mandiant)', url: 'https://github.com/mandiant/commando-vm' },
  // From starred repos — additional
  { name: 'Amass', category: 'Reconnaissance', techniqueIds: ['T1595.001', 'T1590', 'T1589'], description: 'In-depth attack surface mapping and asset discovery (OWASP)', url: 'https://github.com/owasp-amass/amass' },
  { name: 'sqlmap', category: 'Exploitation', techniqueIds: ['T1190', 'T1059'], description: 'Automatic SQL injection and database takeover', url: 'https://github.com/sqlmapproject/sqlmap' },
  { name: 'Sherlock', category: 'Reconnaissance', techniqueIds: ['T1589.001', 'T1593'], description: 'Hunt social media accounts by username', url: 'https://github.com/sherlock-project/sherlock' },
  { name: 'x64dbg', category: 'Reverse Engineering', techniqueIds: ['T1588.002', 'T1027'], description: 'Open-source Windows debugger for RE/malware analysis', url: 'https://github.com/x64dbg/x64dbg' },
  { name: 'ImHex', category: 'Reverse Engineering', techniqueIds: ['T1588.002', 'T1027'], description: 'Hex editor for reverse engineering', url: 'https://github.com/WerWolv/ImHex' },
  { name: 'MobSF', category: 'Mobile Security', techniqueIds: ['T1407', 'T1404', 'T1418'], description: 'Mobile app security testing framework (OWASP)', url: 'https://github.com/MobSF/Mobile-Security-Framework-MobSF' },
  { name: 'Vuls', category: 'Vulnerability Scanning', techniqueIds: ['T1595.002', 'T1190'], description: 'Agent-less vulnerability scanner for Linux/containers', url: 'https://github.com/future-architect/vuls' },
  { name: 'Wazuh', category: 'XDR/SIEM', techniqueIds: ['T1059', 'T1078', 'T1190'], description: 'Open source security platform (XDR + SIEM)', url: 'https://github.com/wazuh/wazuh' },
  { name: 'Strix', category: 'AI Security', techniqueIds: ['T1190', 'T1595.002'], description: 'AI-powered vulnerability finder', url: 'https://github.com/usestrix/strix' },
  { name: 'BloodHound Tools', category: 'AD Enumeration', techniqueIds: ['T1087.002', 'T1069.002', 'T1482'], description: 'Miscellaneous tools for BloodHound analysis', url: 'https://github.com/BloodHoundAD/BloodHound-Tools' },
];

@Injectable({ providedIn: 'root' })
export class OffensiveToolsService {
  private byTechnique = new Map<string, OffensiveTool[]>();

  constructor() {
    this.buildIndex();
  }

  private buildIndex(): void {
    for (const tool of TOOLS) {
      for (const tid of tool.techniqueIds) {
        const list = this.byTechnique.get(tid) ?? [];
        list.push(tool);
        this.byTechnique.set(tid, list);
      }
    }
  }

  getToolsForTechnique(attackId: string): OffensiveTool[] {
    return this.byTechnique.get(attackId) ?? [];
  }

  getAllTools(): OffensiveTool[] {
    return TOOLS;
  }

  getByCategory(cat: string): OffensiveTool[] {
    const c = cat.toLowerCase();
    return TOOLS.filter((t) => t.category.toLowerCase() === c);
  }

  getCategories(): string[] {
    return [...new Set(TOOLS.map((t) => t.category))];
  }
}
