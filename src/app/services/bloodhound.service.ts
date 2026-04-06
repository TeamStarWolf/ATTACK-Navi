import { Injectable } from '@angular/core';

export interface BloodHoundMapping {
  attackPath: string;
  description: string;
  techniqueIds: string[];
  tools: string[];
  mitigations: string[];
  detectionHints: string[];
}

@Injectable({ providedIn: 'root' })
export class BloodHoundService {
  private paths: BloodHoundMapping[] = [
    { attackPath: 'DCSync', description: 'Replicate directory changes to extract credentials', techniqueIds: ['T1003.006'], tools: ['Mimikatz', 'Impacket secretsdump.py'], mitigations: ['Limit Replicating Directory Changes permissions'], detectionHints: ['Event ID 4662 with DS-Replication-Get-Changes'] },
    { attackPath: 'Kerberoasting', description: 'Request TGS tickets for service accounts and crack offline', techniqueIds: ['T1558.003'], tools: ['Rubeus', 'GetUserSPNs.py'], mitigations: ['Use strong service account passwords', 'Use gMSA accounts'], detectionHints: ['Event ID 4769 with RC4 encryption'] },
    { attackPath: 'AS-REP Roasting', description: 'Request AS-REP for accounts without pre-auth', techniqueIds: ['T1558.004'], tools: ['Rubeus', 'GetNPUsers.py'], mitigations: ['Enable pre-authentication for all accounts'], detectionHints: ['Event ID 4768 without pre-auth'] },
    { attackPath: 'Pass-the-Hash', description: 'Authenticate using NTLM hash', techniqueIds: ['T1550.002'], tools: ['Mimikatz', 'CrackMapExec'], mitigations: ['Disable NTLM', 'Enable Credential Guard'], detectionHints: ['Event ID 4624 Logon Type 9'] },
    { attackPath: 'Pass-the-Ticket', description: 'Authenticate using stolen Kerberos tickets', techniqueIds: ['T1550.003'], tools: ['Mimikatz', 'Rubeus'], mitigations: ['Rotate KRBTGT password'], detectionHints: ['Event ID 4768/4769 anomalies'] },
    { attackPath: 'Golden Ticket', description: 'Forge TGT using KRBTGT hash', techniqueIds: ['T1558.001'], tools: ['Mimikatz', 'Impacket ticketer.py'], mitigations: ['Reset KRBTGT twice'], detectionHints: ['TGT with abnormal lifetime'] },
    { attackPath: 'Silver Ticket', description: 'Forge TGS for specific services', techniqueIds: ['T1558.002'], tools: ['Mimikatz'], mitigations: ['Use AES for service accounts'], detectionHints: ['TGS without corresponding TGT'] },
    { attackPath: 'LLMNR/NBT-NS Poisoning', description: 'Capture NTLMv2 hashes via name resolution', techniqueIds: ['T1557.001'], tools: ['Responder', 'Inveigh'], mitigations: ['Disable LLMNR and NetBIOS'], detectionHints: ['Unexpected LLMNR traffic'] },
    { attackPath: 'NTDS.dit Extraction', description: 'Extract AD database offline', techniqueIds: ['T1003.003'], tools: ['ntdsutil', 'Impacket secretsdump.py'], mitigations: ['Limit Domain Admin accounts'], detectionHints: ['Event ID 4661 with ntds.dit'] },
    { attackPath: 'Unconstrained Delegation', description: 'Capture TGTs from delegated hosts', techniqueIds: ['T1550.003', 'T1558'], tools: ['Rubeus', 'SpoolSample'], mitigations: ['Remove unconstrained delegation'], detectionHints: ['TGT forwarded to non-DC'] },
    { attackPath: 'Group Policy Abuse', description: 'Modify GPO for malicious scripts', techniqueIds: ['T1484.001'], tools: ['SharpGPOAbuse', 'PowerView'], mitigations: ['Restrict GPO modification rights'], detectionHints: ['Event ID 5136 on GPO'] },
    { attackPath: 'AdminSDHolder Persistence', description: 'Modify AdminSDHolder ACL', techniqueIds: ['T1098'], tools: ['PowerView'], mitigations: ['Monitor AdminSDHolder modifications'], detectionHints: ['Event ID 5136 on AdminSDHolder'] },
    { attackPath: 'SID History Injection', description: 'Add SID for cross-domain escalation', techniqueIds: ['T1134.005'], tools: ['Mimikatz', 'DSInternals'], mitigations: ['Enable SID filtering'], detectionHints: ['Event ID 4765/4766'] },
    { attackPath: 'Shadow Credentials', description: 'Add key credentials to compromise accounts', techniqueIds: ['T1556'], tools: ['Whisker', 'PyWhisker'], mitigations: ['Monitor msDS-KeyCredentialLink changes'], detectionHints: ['Event ID 5136 on msDS-KeyCredentialLink'] },
    { attackPath: 'LSASS Dump', description: 'Dump LSASS process memory for credentials', techniqueIds: ['T1003.001'], tools: ['Mimikatz', 'procdump', 'comsvcs.dll'], mitigations: ['Enable LSA Protection (RunAsPPL)', 'Credential Guard'], detectionHints: ['Event ID 4656 on lsass.exe'] },
  ];

  getPathsForTechnique(attackId: string): BloodHoundMapping[] {
    return this.paths.filter(p => p.techniqueIds.includes(attackId));
  }
  getAllPaths(): BloodHoundMapping[] { return this.paths; }
  getPathByName(name: string): BloodHoundMapping | null {
    return this.paths.find(p => p.attackPath === name) ?? null;
  }
}
