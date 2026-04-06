// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';

export interface AzureAttackPattern {
  name: string;
  description: string;
  techniqueIds: string[];
  affectedServices: string[];
  detectionQuery: string;
  mitigations: string[];
}

const AZURE_AD_ATTACKS: AzureAttackPattern[] = [
  {
    name: 'Consent Grant Attack',
    description: 'Trick user into granting app permissions to access data',
    techniqueIds: ['T1528', 'T1550.001'],
    affectedServices: ['Azure AD', 'Microsoft Graph'],
    detectionQuery: 'AuditLogs | where OperationName == "Consent to application" | where Result == "success"',
    mitigations: ['Restrict user consent', 'Require admin approval for apps'],
  },
  {
    name: 'Password Spray',
    description: 'Try common passwords across many accounts',
    techniqueIds: ['T1110.003'],
    affectedServices: ['Azure AD'],
    detectionQuery: 'SigninLogs | where ResultType == 50126 | summarize count() by IPAddress | where count_ > 10',
    mitigations: ['Enable MFA', 'Use Azure AD Password Protection'],
  },
  {
    name: 'Token Theft',
    description: 'Steal OAuth/refresh tokens for persistent access',
    techniqueIds: ['T1528', 'T1550.001'],
    affectedServices: ['Azure AD', 'Microsoft 365'],
    detectionQuery: 'AADSignInEventsBeta | where ErrorCode == 0 and RiskState == "confirmedCompromised"',
    mitigations: ['Enable CAE', 'Reduce token lifetime', 'Use Conditional Access'],
  },
  {
    name: 'Illicit Consent Grant',
    description: 'Register malicious app for persistent data access',
    techniqueIds: ['T1098.003'],
    affectedServices: ['Azure AD'],
    detectionQuery: 'AuditLogs | where OperationName has "Add app role assignment" | extend AppName = TargetResources[0].displayName',
    mitigations: ['Block user consent', 'Review app registrations regularly'],
  },
  {
    name: 'Managed Identity Abuse',
    description: 'Abuse Azure managed identities from compromised VMs',
    techniqueIds: ['T1078.004', 'T1550.001'],
    affectedServices: ['Azure VM', 'Azure Functions'],
    detectionQuery: 'AzureActivity | where Authorization.action has "Microsoft.Compute/virtualMachines/extensions/write"',
    mitigations: ['Limit managed identity permissions', 'Monitor metadata endpoint access'],
  },
  {
    name: 'Service Principal Key Credential Abuse',
    description: 'Add credentials to existing service principal',
    techniqueIds: ['T1098.001'],
    affectedServices: ['Azure AD'],
    detectionQuery: 'AuditLogs | where OperationName == "Add service principal credentials"',
    mitigations: ['Monitor credential additions', 'Use certificate-based auth'],
  },
  {
    name: 'Cross-Tenant Access Abuse',
    description: 'Exploit B2B trust for lateral movement between tenants',
    techniqueIds: ['T1199'],
    affectedServices: ['Azure AD B2B'],
    detectionQuery: 'SigninLogs | where CrossTenantAccessType != "none"',
    mitigations: ['Review cross-tenant policies', 'Limit external collaboration'],
  },
  {
    name: 'Conditional Access Bypass',
    description: 'Exploit legacy protocols or device compliance gaps',
    techniqueIds: ['T1556.006'],
    affectedServices: ['Azure AD'],
    detectionQuery: 'SigninLogs | where ClientAppUsed !in ("Browser", "Mobile Apps and Desktop clients")',
    mitigations: ['Block legacy authentication', 'Require compliant devices'],
  },
  {
    name: 'Azure Storage Account Key Theft',
    description: 'Extract storage account keys for data access',
    techniqueIds: ['T1552.005'],
    affectedServices: ['Azure Storage'],
    detectionQuery: 'AzureActivity | where OperationName == "List Storage Account Keys"',
    mitigations: ['Use Azure RBAC instead of keys', 'Rotate keys regularly'],
  },
  {
    name: 'Privileged Role Escalation',
    description: 'Escalate to Global Admin via PIM or role assignment',
    techniqueIds: ['T1078.004', 'T1548'],
    affectedServices: ['Azure AD PIM'],
    detectionQuery: 'AuditLogs | where OperationName has "Add member to role" | where TargetResources[0].displayName has "Global"',
    mitigations: ['Enable PIM', 'Require approval for role activation'],
  },
];

@Injectable({ providedIn: 'root' })
export class AzureIdentityService {
  private byTechnique = new Map<string, AzureAttackPattern[]>();

  constructor() {
    this.buildIndex();
  }

  private buildIndex(): void {
    for (const attack of AZURE_AD_ATTACKS) {
      for (const tid of attack.techniqueIds) {
        const list = this.byTechnique.get(tid) ?? [];
        list.push(attack);
        this.byTechnique.set(tid, list);
      }
    }
  }

  getAttacksForTechnique(attackId: string): AzureAttackPattern[] {
    return this.byTechnique.get(attackId) ?? [];
  }

  getAllAttacks(): AzureAttackPattern[] {
    return AZURE_AD_ATTACKS;
  }

  getByService(service: string): AzureAttackPattern[] {
    const s = service.toLowerCase();
    return AZURE_AD_ATTACKS.filter((a) =>
      a.affectedServices.some((svc) => svc.toLowerCase().includes(s)),
    );
  }
}
