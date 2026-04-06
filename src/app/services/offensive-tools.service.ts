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
