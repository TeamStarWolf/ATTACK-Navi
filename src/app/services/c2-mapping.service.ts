// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';

export interface C2Capability {
  framework: string;
  capability: string;
  techniqueIds: string[];
  description: string;
}

@Injectable({ providedIn: 'root' })
export class C2MappingService {
  private mappings: C2Capability[] = [
    { framework: 'Sliver', capability: 'HTTPS Listener', techniqueIds: ['T1071.001', 'T1573.002'], description: 'Encrypted C2 over HTTPS' },
    { framework: 'Sliver', capability: 'DNS Listener', techniqueIds: ['T1071.004'], description: 'C2 via DNS tunneling' },
    { framework: 'Sliver', capability: 'Process Injection', techniqueIds: ['T1055'], description: 'Inject shellcode into running process' },
    { framework: 'Sliver', capability: 'Execute Assembly', techniqueIds: ['T1059.001'], description: 'Run .NET assemblies in memory' },
    { framework: 'Sliver', capability: 'Pivoting', techniqueIds: ['T1090.001'], description: 'Route traffic through compromised hosts' },
    { framework: 'Sliver', capability: 'Screenshot', techniqueIds: ['T1113'], description: 'Capture screen contents' },
    { framework: 'Cobalt Strike', capability: 'Beacon', techniqueIds: ['T1071.001', 'T1573'], description: 'Periodic C2 check-in' },
    { framework: 'Cobalt Strike', capability: 'SMB Beacon', techniqueIds: ['T1021.002'], description: 'Lateral C2 via named pipes' },
    { framework: 'Cobalt Strike', capability: 'Mimikatz', techniqueIds: ['T1003.001'], description: 'In-memory credential dumping' },
    { framework: 'Cobalt Strike', capability: 'Jump PSExec', techniqueIds: ['T1021.002', 'T1569.002'], description: 'Lateral movement via PSExec' },
    { framework: 'Cobalt Strike', capability: 'Golden Ticket', techniqueIds: ['T1558.001'], description: 'Forge Kerberos TGT' },
    { framework: 'Cobalt Strike', capability: 'PowerShell', techniqueIds: ['T1059.001'], description: 'Execute PowerShell commands' },
    { framework: 'Metasploit', capability: 'Meterpreter', techniqueIds: ['T1059', 'T1055'], description: 'Advanced in-memory payload' },
    { framework: 'Metasploit', capability: 'Exploit Modules', techniqueIds: ['T1190', 'T1203', 'T1210'], description: 'Automated exploitation' },
    { framework: 'Metasploit', capability: 'Post Modules', techniqueIds: ['T1003', 'T1087', 'T1082'], description: 'Post-exploitation enumeration' },
    { framework: 'Metasploit', capability: 'Persistence', techniqueIds: ['T1547.001', 'T1053.005'], description: 'Establish persistent access' },
    { framework: 'Metasploit', capability: 'Pivoting', techniqueIds: ['T1090.001', 'T1572'], description: 'Network tunneling' },
  ];

  getCapabilitiesForTechnique(attackId: string): C2Capability[] {
    return this.mappings.filter(m => m.techniqueIds.some(t => attackId.startsWith(t) || t === attackId));
  }
  getFrameworks(): string[] { return [...new Set(this.mappings.map(m => m.framework))]; }
  getByFramework(name: string): C2Capability[] { return this.mappings.filter(m => m.framework === name); }
}
