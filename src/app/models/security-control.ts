export type ControlFramework = 'NIST 800-53' | 'CIS Controls v8' | 'ISO 27001' | 'Custom';
export type ControlStatus = 'implemented' | 'planned';

export interface SecurityControl {
  id: string;
  name: string;
  framework: ControlFramework;
  controlRef: string;
  description: string;
  mitigationIds: string[]; // STIX course-of-action IDs
  status: ControlStatus;
}

export interface FrameworkTemplate {
  id: string;
  name: string;
  framework: ControlFramework;
  icon: string;
  controls: {
    ref: string;
    name: string;
    mitigationAttackIds: string[]; // ATT&CK IDs like M1036
  }[];
}

export const FRAMEWORK_TEMPLATES: FrameworkTemplate[] = [
  {
    id: 'nist-800-53',
    name: 'NIST SP 800-53 Rev 5',
    framework: 'NIST 800-53',
    icon: '🏛️',
    controls: [
      { ref: 'AC-2',  name: 'Account Management',                    mitigationAttackIds: ['M1018', 'M1036', 'M1026'] },
      { ref: 'AC-3',  name: 'Access Enforcement',                     mitigationAttackIds: ['M1018', 'M1022', 'M1024'] },
      { ref: 'AC-4',  name: 'Information Flow Enforcement',           mitigationAttackIds: ['M1030', 'M1037'] },
      { ref: 'AC-6',  name: 'Least Privilege',                        mitigationAttackIds: ['M1026', 'M1018'] },
      { ref: 'AC-17', name: 'Remote Access',                          mitigationAttackIds: ['M1035', 'M1030', 'M1032'] },
      { ref: 'AU-2',  name: 'Event Logging',                          mitigationAttackIds: ['M1047'] },
      { ref: 'AU-12', name: 'Audit Record Generation',                mitigationAttackIds: ['M1047'] },
      { ref: 'CA-7',  name: 'Continuous Monitoring',                  mitigationAttackIds: ['M1047', 'M1019'] },
      { ref: 'CM-2',  name: 'Baseline Configuration',                 mitigationAttackIds: ['M1028', 'M1054'] },
      { ref: 'CM-6',  name: 'Configuration Settings',                 mitigationAttackIds: ['M1028', 'M1054'] },
      { ref: 'CM-7',  name: 'Least Functionality',                    mitigationAttackIds: ['M1042', 'M1033'] },
      { ref: 'IA-2',  name: 'Identification and Authentication',      mitigationAttackIds: ['M1032'] },
      { ref: 'IA-5',  name: 'Authenticator Management',               mitigationAttackIds: ['M1027', 'M1032'] },
      { ref: 'PM-16', name: 'Threat Awareness Program',               mitigationAttackIds: ['M1019'] },
      { ref: 'RA-5',  name: 'Vulnerability Scanning',                 mitigationAttackIds: ['M1016', 'M1051'] },
      { ref: 'SC-7',  name: 'Boundary Protection',                    mitigationAttackIds: ['M1030', 'M1031', 'M1037'] },
      { ref: 'SC-8',  name: 'Transmission Confidentiality & Integrity', mitigationAttackIds: ['M1041'] },
      { ref: 'SC-28', name: 'Protection of Info at Rest',             mitigationAttackIds: ['M1041'] },
      { ref: 'SI-2',  name: 'Flaw Remediation',                       mitigationAttackIds: ['M1051'] },
      { ref: 'SI-3',  name: 'Malicious Code Protection',              mitigationAttackIds: ['M1049', 'M1040'] },
      { ref: 'SI-7',  name: 'Software & Firmware Integrity',          mitigationAttackIds: ['M1045', 'M1046'] },
      { ref: 'SI-10', name: 'Information Input Validation',           mitigationAttackIds: ['M1013'] },
    ],
  },
  {
    id: 'cis-v8',
    name: 'CIS Controls v8',
    framework: 'CIS Controls v8',
    icon: '🛡️',
    controls: [
      { ref: 'CIS 1',  name: 'Inventory of Enterprise Assets',       mitigationAttackIds: ['M1047'] },
      { ref: 'CIS 2',  name: 'Inventory of Software Assets',         mitigationAttackIds: ['M1042', 'M1033'] },
      { ref: 'CIS 3',  name: 'Data Protection',                      mitigationAttackIds: ['M1041', 'M1022'] },
      { ref: 'CIS 4',  name: 'Secure Configuration',                 mitigationAttackIds: ['M1028', 'M1054'] },
      { ref: 'CIS 5',  name: 'Account Management',                   mitigationAttackIds: ['M1018', 'M1026', 'M1036'] },
      { ref: 'CIS 6',  name: 'Access Control Management',            mitigationAttackIds: ['M1018', 'M1022', 'M1024'] },
      { ref: 'CIS 7',  name: 'Continuous Vulnerability Management',  mitigationAttackIds: ['M1051', 'M1016'] },
      { ref: 'CIS 8',  name: 'Audit Log Management',                 mitigationAttackIds: ['M1047'] },
      { ref: 'CIS 9',  name: 'Email & Web Browser Protections',      mitigationAttackIds: ['M1021', 'M1049'] },
      { ref: 'CIS 10', name: 'Malware Defenses',                     mitigationAttackIds: ['M1049', 'M1040', 'M1045'] },
      { ref: 'CIS 11', name: 'Data Recovery',                        mitigationAttackIds: ['M1053'] },
      { ref: 'CIS 12', name: 'Network Infrastructure Management',    mitigationAttackIds: ['M1030', 'M1037'] },
      { ref: 'CIS 13', name: 'Network Monitoring & Defense',         mitigationAttackIds: ['M1031', 'M1037'] },
      { ref: 'CIS 14', name: 'Security Awareness Training',          mitigationAttackIds: ['M1017'] },
      { ref: 'CIS 16', name: 'Application Software Security',        mitigationAttackIds: ['M1048', 'M1013', 'M1045'] },
      { ref: 'CIS 17', name: 'Incident Response Management',         mitigationAttackIds: ['M1019'] },
    ],
  },
  {
    id: 'iso-27001',
    name: 'ISO/IEC 27001:2022',
    framework: 'ISO 27001',
    icon: '🌐',
    controls: [
      { ref: 'A.5.15', name: 'Access Control',                       mitigationAttackIds: ['M1018', 'M1022', 'M1026'] },
      { ref: 'A.5.16', name: 'Identity Management',                  mitigationAttackIds: ['M1018', 'M1036'] },
      { ref: 'A.5.17', name: 'Authentication Information',           mitigationAttackIds: ['M1027', 'M1032'] },
      { ref: 'A.5.23', name: 'ICT Supply Chain Security',            mitigationAttackIds: ['M1013'] },
      { ref: 'A.8.2',  name: 'Privileged Access Rights',             mitigationAttackIds: ['M1026', 'M1025'] },
      { ref: 'A.8.5',  name: 'Secure Authentication',                mitigationAttackIds: ['M1032'] },
      { ref: 'A.8.8',  name: 'Management of Technical Vulnerabilities', mitigationAttackIds: ['M1051', 'M1016'] },
      { ref: 'A.8.9',  name: 'Configuration Management',             mitigationAttackIds: ['M1028', 'M1054'] },
      { ref: 'A.8.12', name: 'Data Leakage Prevention',              mitigationAttackIds: ['M1041', 'M1030'] },
      { ref: 'A.8.15', name: 'Logging',                              mitigationAttackIds: ['M1047'] },
      { ref: 'A.8.16', name: 'Monitoring Activities',                mitigationAttackIds: ['M1047', 'M1019'] },
      { ref: 'A.8.20', name: 'Network Security',                     mitigationAttackIds: ['M1030', 'M1031', 'M1037'] },
      { ref: 'A.8.22', name: 'Segregation of Networks',              mitigationAttackIds: ['M1030'] },
      { ref: 'A.8.29', name: 'Security Testing in Dev & Acceptance', mitigationAttackIds: ['M1013'] },
    ],
  },
];
