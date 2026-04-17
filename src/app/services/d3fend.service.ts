// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, of } from 'rxjs';
import { catchError } from 'rxjs/operators';

export interface D3fendTechnique {
  id: string;          // e.g., "D3-PSA"
  name: string;        // e.g., "Process Spawn Analysis"
  definition: string;  // brief description
  url: string;
  category: 'Harden' | 'Detect' | 'Isolate' | 'Deceive' | 'Evict';
  attackIds: string[]; // ATT&CK technique IDs this counters
}

// Bundled D3FEND→ATT&CK mapping (~100 countermeasures)
const D3FEND_MAPPING: D3fendTechnique[] = [
  // --- Original 30 entries (with category added) ---
  { id: 'D3-PSA', name: 'Process Spawn Analysis', category: 'Detect', definition: 'Analyzing process spawn events to detect anomalous parent-child relationships.', url: 'https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis', attackIds: ['T1059', 'T1055', 'T1078', 'T1053'] },
  { id: 'D3-NTF', name: 'Network Traffic Filtering', category: 'Isolate', definition: 'Restricting network traffic based on policies and rules.', url: 'https://d3fend.mitre.org/technique/d3f:NetworkTrafficFiltering', attackIds: ['T1021', 'T1071', 'T1041', 'T1095', 'T1572'] },
  { id: 'D3-DNSAL', name: 'DNS Allowlisting', category: 'Harden', definition: 'Permitting only known-good DNS resolutions.', url: 'https://d3fend.mitre.org/technique/d3f:DNSAllowlisting', attackIds: ['T1568', 'T1071.004', 'T1583'] },
  { id: 'D3-NI', name: 'Network Isolation', category: 'Isolate', definition: 'Preventing or limiting lateral movement via network segmentation.', url: 'https://d3fend.mitre.org/technique/d3f:NetworkIsolation', attackIds: ['T1021', 'T1570', 'T1534'] },
  { id: 'D3-UDTA', name: 'User Data Transfer Analysis', category: 'Detect', definition: 'Monitoring and analyzing data transfers performed by users.', url: 'https://d3fend.mitre.org/technique/d3f:UserDataTransferAnalysis', attackIds: ['T1041', 'T1030', 'T1048', 'T1567'] },
  { id: 'D3-PA', name: 'Process Analysis', category: 'Detect', definition: 'Monitoring and analyzing process behavior during execution.', url: 'https://d3fend.mitre.org/technique/d3f:ProcessAnalysis', attackIds: ['T1055', 'T1059', 'T1203', 'T1106'] },
  { id: 'D3-HBPI', name: 'Homoglyph Detection', category: 'Detect', definition: 'Identifying lookalike/homoglyph characters in URLs and filenames.', url: 'https://d3fend.mitre.org/technique/d3f:HomoglyphDenial', attackIds: ['T1036', 'T1598'] },
  { id: 'D3-MAN', name: 'Mandatory Access Control', category: 'Harden', definition: 'Enforcing access based on security labels and policies.', url: 'https://d3fend.mitre.org/technique/d3f:MandatoryAccessControl', attackIds: ['T1548', 'T1068', 'T1222'] },
  { id: 'D3-UAP', name: 'User Account Permissions', category: 'Harden', definition: 'Managing and restricting user account privileges.', url: 'https://d3fend.mitre.org/technique/d3f:UserAccountPermissions', attackIds: ['T1078', 'T1548', 'T1134'] },
  { id: 'D3-PAMDA', name: 'Privileged Account Management', category: 'Harden', definition: 'Controlling the use of privileged accounts and credentials.', url: 'https://d3fend.mitre.org/technique/d3f:PrivilegedAccountManagement', attackIds: ['T1078', 'T1003', 'T1098'] },
  { id: 'D3-RCAM', name: 'Remote Command Authentication', category: 'Harden', definition: 'Authenticating and authorizing remote commands and sessions.', url: 'https://d3fend.mitre.org/technique/d3f:RemoteCommandAuthentication', attackIds: ['T1021', 'T1059', 'T1133'] },
  { id: 'D3-IOPR', name: 'Input/Output Port Restriction', category: 'Harden', definition: 'Blocking or monitoring I/O ports to prevent unauthorized device usage.', url: 'https://d3fend.mitre.org/technique/d3f:InputOutputPortRestriction', attackIds: ['T1091', 'T1052'] },
  { id: 'D3-SRA', name: 'Stack Frame Analysis', category: 'Detect', definition: 'Analyzing stack frames to detect code injection or return-oriented programming.', url: 'https://d3fend.mitre.org/technique/d3f:StackFrameAnalysis', attackIds: ['T1055', 'T1203'] },
  { id: 'D3-EAL', name: 'Executable Allowlisting', category: 'Harden', definition: 'Restricting execution to known-good executables and scripts.', url: 'https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting', attackIds: ['T1059', 'T1203', 'T1218', 'T1574'] },
  { id: 'D3-EI', name: 'Executable Integrity', category: 'Harden', definition: 'Verifying the integrity of executables using cryptographic signatures.', url: 'https://d3fend.mitre.org/technique/d3f:ExecutableCodeIntegrity', attackIds: ['T1195', 'T1553', 'T1036'] },
  { id: 'D3-BA', name: 'Behavioral Analysis', category: 'Detect', definition: 'Detecting anomalous behavior through endpoint behavioral monitoring.', url: 'https://d3fend.mitre.org/technique/d3f:BehavioralAnalysis', attackIds: ['T1059', 'T1055', 'T1071', 'T1048', 'T1041'] },
  { id: 'D3-FA', name: 'File Analysis', category: 'Detect', definition: 'Monitoring and analyzing file system operations.', url: 'https://d3fend.mitre.org/technique/d3f:FileAnalysis', attackIds: ['T1005', 'T1083', 'T1560', 'T1070.004'] },
  { id: 'D3-FR', name: 'File Removal', category: 'Evict', definition: 'Removing malicious or unauthorized files.', url: 'https://d3fend.mitre.org/technique/d3f:FileRemoval', attackIds: ['T1074', 'T1560', 'T1105'] },
  { id: 'D3-PLA', name: 'Platform Logging', category: 'Detect', definition: 'Collecting logs from operating system and platform components.', url: 'https://d3fend.mitre.org/technique/d3f:PlatformLogging', attackIds: ['T1070', 'T1562.002', 'T1562.006'] },
  { id: 'D3-CE', name: 'Credential Encryption', category: 'Harden', definition: 'Encrypting credentials stored on the endpoint.', url: 'https://d3fend.mitre.org/technique/d3f:CredentialEncryption', attackIds: ['T1003', 'T1552', 'T1555'] },
  { id: 'D3-MFA', name: 'Multi-factor Authentication', category: 'Harden', definition: 'Requiring multiple authentication factors to verify identity.', url: 'https://d3fend.mitre.org/technique/d3f:Multi-factorAuthentication', attackIds: ['T1078', 'T1556', 'T1110', 'T1621'] },
  { id: 'D3-SPP', name: 'Sender Policy Framework', category: 'Harden', definition: 'Validating sender identity to prevent email spoofing.', url: 'https://d3fend.mitre.org/technique/d3f:SenderPolicyFramework', attackIds: ['T1566', 'T1598', 'T1534'] },
  { id: 'D3-UAA', name: 'User Account Authentication', category: 'Harden', definition: 'Authenticating users with strong policies and controls.', url: 'https://d3fend.mitre.org/technique/d3f:UserAccountAuthentication', attackIds: ['T1078', 'T1110', 'T1134'] },
  { id: 'D3-CIPA', name: 'Connection Attempt Policy', category: 'Detect', definition: 'Enforcing policies on connection attempts to limit brute-force attacks.', url: 'https://d3fend.mitre.org/technique/d3f:ConnectionAttemptAnalysis', attackIds: ['T1110', 'T1021', 'T1078'] },
  { id: 'D3-PMAD', name: 'Passive Physical Link Analysis', category: 'Detect', definition: 'Monitoring physical network links for anomalous activity.', url: 'https://d3fend.mitre.org/technique/d3f:PassivePhysicalLinkAnalysis', attackIds: ['T1040', 'T1557'] },
  { id: 'D3-ANET', name: 'Authentication Network Traffic Analysis', category: 'Detect', definition: 'Analyzing network authentication traffic to detect abnormal patterns.', url: 'https://d3fend.mitre.org/technique/d3f:AuthenticationNetworkTrafficAnalysis', attackIds: ['T1078', 'T1556', 'T1110'] },
  { id: 'D3-ISVA', name: 'Inbound Session Volume Analysis', category: 'Detect', definition: 'Monitoring and limiting inbound session volumes.', url: 'https://d3fend.mitre.org/technique/d3f:InboundSessionVolumeAnalysis', attackIds: ['T1190', 'T1499'] },
  { id: 'D3-SCH', name: 'Script Execution Analysis', category: 'Detect', definition: 'Analyzing script execution contexts and behaviors.', url: 'https://d3fend.mitre.org/technique/d3f:ScriptExecutionAnalysis', attackIds: ['T1059', 'T1064', 'T1203'] },
  { id: 'D3-DNSD', name: 'DNS Denylisting', category: 'Harden', definition: 'Blocking resolution of known-malicious domains.', url: 'https://d3fend.mitre.org/technique/d3f:DNSDenylisting', attackIds: ['T1071.004', 'T1568', 'T1048'] },
  { id: 'D3-SYSM', name: 'System Call Analysis', category: 'Detect', definition: 'Monitoring system calls for anomalous behavior.', url: 'https://d3fend.mitre.org/technique/d3f:SystemCallAnalysis', attackIds: ['T1055', 'T1106', 'T1203', 'T1059'] },

  // --- New entries ---

  // Harden
  { id: 'D3-EHB', name: 'Email Hardening', category: 'Harden', definition: 'Implementing DMARC, DKIM, SPF and content filtering on email systems.', url: 'https://d3fend.mitre.org/technique/d3f:MessageHardening', attackIds: ['T1566', 'T1534', 'T1598'] },
  { id: 'D3-PH', name: 'Patch Management', category: 'Harden', definition: 'Applying security patches and updates in a timely manner.', url: 'https://d3fend.mitre.org/technique/d3f:PatchManagement', attackIds: ['T1190', 'T1203', 'T1068'] },
  { id: 'D3-MPR', name: 'Memory Protection', category: 'Harden', definition: 'Protecting process memory using DEP/NX, ASLR, and stack canaries.', url: 'https://d3fend.mitre.org/technique/d3f:MemoryBoundaryTracking', attackIds: ['T1055', 'T1203', 'T1068'] },
  { id: 'D3-ILA', name: 'Immutable Log Record', category: 'Harden', definition: 'Protecting log integrity using write-once or append-only storage.', url: 'https://d3fend.mitre.org/technique/d3f:ImmutableLogRecord', attackIds: ['T1070', 'T1562.002', 'T1562.006'] },
  { id: 'D3-SAML', name: 'Strong Authentication', category: 'Harden', definition: 'Enforcing strong authentication mechanisms including certificate-based auth.', url: 'https://d3fend.mitre.org/technique/d3f:StrongPasswordPolicy', attackIds: ['T1110', 'T1078', 'T1556'] },
  { id: 'D3-ACH', name: 'Account Credential Hardening', category: 'Harden', definition: 'Applying password policies, rotation, and protection to service accounts.', url: 'https://d3fend.mitre.org/technique/d3f:AccountCredentialHardening', attackIds: ['T1098', 'T1136', 'T1078'] },
  { id: 'D3-BI', name: 'Boot Integrity', category: 'Harden', definition: 'Ensuring boot process integrity via Secure Boot and TPM measurements.', url: 'https://d3fend.mitre.org/technique/d3f:BootRecordIntegrity', attackIds: ['T1542', 'T1547', 'T1553'] },
  { id: 'D3-FE', name: 'File Encryption', category: 'Harden', definition: 'Encrypting sensitive files and data stores to protect against unauthorized access.', url: 'https://d3fend.mitre.org/technique/d3f:FileEncryption', attackIds: ['T1005', 'T1039', 'T1025', 'T1530'] },
  { id: 'D3-CP', name: 'Credential Policy', category: 'Harden', definition: 'Enforcing password complexity, history, and expiration policies.', url: 'https://d3fend.mitre.org/technique/d3f:CredentialPolicy', attackIds: ['T1110', 'T1078', 'T1003'] },
  { id: 'D3-SAPE', name: 'Service Account Permissions', category: 'Harden', definition: 'Restricting service account privileges to the minimum required for operation.', url: 'https://d3fend.mitre.org/technique/d3f:ServiceAccountManagement', attackIds: ['T1078', 'T1098', 'T1547'] },
  { id: 'D3-CAR', name: 'Code Signing', category: 'Harden', definition: 'Requiring valid digital signatures for code execution.', url: 'https://d3fend.mitre.org/technique/d3f:CodeSigning', attackIds: ['T1036', 'T1553', 'T1218', 'T1574'] },
  { id: 'D3-RFM', name: 'Removable Media Restrictions', category: 'Harden', definition: 'Blocking or controlling use of removable media to prevent data theft and malware.', url: 'https://d3fend.mitre.org/technique/d3f:RemovableMediaRestrictions', attackIds: ['T1025', 'T1052', 'T1091'] },
  { id: 'D3-AAC', name: 'Application Access Control', category: 'Harden', definition: 'Controlling which applications can access sensitive resources and APIs.', url: 'https://d3fend.mitre.org/technique/d3f:ApplicationHardening', attackIds: ['T1059', 'T1218', 'T1197'] },
  { id: 'D3-OAH', name: 'OS Hardening', category: 'Harden', definition: 'Applying operating system security baselines and removing unnecessary features.', url: 'https://d3fend.mitre.org/technique/d3f:OperatingSystemHardening', attackIds: ['T1082', 'T1016', 'T1546', 'T1574'] },
  { id: 'D3-NFW', name: 'Network Firewall', category: 'Harden', definition: 'Controlling inbound and outbound network traffic using firewall policies.', url: 'https://d3fend.mitre.org/technique/d3f:NetworkFirewall', attackIds: ['T1021', 'T1190', 'T1095', 'T1046'] },

  // Detect
  { id: 'D3-URL', name: 'URL Analysis', category: 'Detect', definition: 'Analyzing URLs in messages and documents for malicious indicators.', url: 'https://d3fend.mitre.org/technique/d3f:URLAnalysis', attackIds: ['T1566', 'T1204', 'T1598', 'T1071.001'] },
  { id: 'D3-ATH', name: 'Attachment Analysis', category: 'Detect', definition: 'Analyzing email and message attachments for malicious content.', url: 'https://d3fend.mitre.org/technique/d3f:AttachmentAnalysis', attackIds: ['T1566', 'T1204.002'] },
  { id: 'D3-MA', name: 'Memory Analysis', category: 'Detect', definition: 'Analyzing process memory for malicious code or artifacts.', url: 'https://d3fend.mitre.org/technique/d3f:MemoryAnalysis', attackIds: ['T1055', 'T1003.001', 'T1620', 'T1027'] },
  { id: 'D3-LFA', name: 'Log File Analysis', category: 'Detect', definition: 'Analyzing log files for indicators of compromise and anomalous activity.', url: 'https://d3fend.mitre.org/technique/d3f:LogFileAnalysis', attackIds: ['T1070', 'T1562', 'T1562.002'] },
  { id: 'D3-JT', name: 'Job Analysis', category: 'Detect', definition: 'Monitoring scheduled jobs and tasks for unauthorized modifications.', url: 'https://d3fend.mitre.org/technique/d3f:JobFunctionAccessPatternAnalysis', attackIds: ['T1053', 'T1543', 'T1547'] },
  { id: 'D3-TBI', name: 'TLS Inspection', category: 'Detect', definition: 'Decrypting and inspecting TLS traffic for malicious content.', url: 'https://d3fend.mitre.org/technique/d3f:TLSInspection', attackIds: ['T1573', 'T1071', 'T1095'] },
  { id: 'D3-CHA', name: 'Certificate Analysis', category: 'Detect', definition: 'Analyzing TLS/SSL certificates for anomalies or known-bad issuers.', url: 'https://d3fend.mitre.org/technique/d3f:CertificateAnalysis', attackIds: ['T1573', 'T1583.003', 'T1553'] },
  { id: 'D3-RTA', name: 'Registry Analysis', category: 'Detect', definition: 'Monitoring Windows Registry changes for persistence or configuration modifications.', url: 'https://d3fend.mitre.org/technique/d3f:SystemInitConfigAnalysis', attackIds: ['T1112', 'T1547.001', 'T1574'] },
  { id: 'D3-FH', name: 'File Hashing', category: 'Detect', definition: 'Computing and verifying cryptographic hashes of files.', url: 'https://d3fend.mitre.org/technique/d3f:FileIntegrityMonitoring', attackIds: ['T1036', 'T1027', 'T1195'] },
  { id: 'D3-NTA', name: 'Network Traffic Analysis', category: 'Detect', definition: 'Inspecting and analyzing network traffic for anomalies and malicious patterns.', url: 'https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis', attackIds: ['T1040', 'T1095', 'T1071', 'T1557'] },
  { id: 'D3-DA', name: 'DNS Traffic Analysis', category: 'Detect', definition: 'Monitoring DNS queries and responses for signs of tunneling or malicious domains.', url: 'https://d3fend.mitre.org/technique/d3f:DNSTrafficAnalysis', attackIds: ['T1071.004', 'T1568', 'T1132'] },
  { id: 'D3-UAM', name: 'User Behavior Analysis', category: 'Detect', definition: 'Establishing behavioral baselines and detecting anomalous user activity.', url: 'https://d3fend.mitre.org/technique/d3f:UserBehaviorAnalysis', attackIds: ['T1078', 'T1087', 'T1069', 'T1098'] },
  { id: 'D3-EMAL', name: 'Email Analysis', category: 'Detect', definition: 'Inspecting email headers, content, and metadata for phishing indicators.', url: 'https://d3fend.mitre.org/technique/d3f:EmailAnalysis', attackIds: ['T1566', 'T1114', 'T1598'] },
  { id: 'D3-IAA', name: 'Inbound Traffic Analysis', category: 'Detect', definition: 'Analyzing inbound network connections for malicious payloads and exploits.', url: 'https://d3fend.mitre.org/technique/d3f:InboundTrafficFiltering', attackIds: ['T1190', 'T1133', 'T1046'] },
  { id: 'D3-DISC', name: 'Discovery Activity Analysis', category: 'Detect', definition: 'Detecting enumeration and discovery activity such as system and account queries.', url: 'https://d3fend.mitre.org/technique/d3f:DiscoveryActivityAnalysis', attackIds: ['T1082', 'T1087', 'T1069', 'T1016', 'T1046', 'T1083'] },
  { id: 'D3-EXA', name: 'Exfiltration Analysis', category: 'Detect', definition: 'Detecting data exfiltration via monitoring of outbound traffic volume and destinations.', url: 'https://d3fend.mitre.org/technique/d3f:ExfiltrationAnalysis', attackIds: ['T1041', 'T1048', 'T1567', 'T1560', 'T1020'] },
  { id: 'D3-WIA', name: 'WMI Activity Analysis', category: 'Detect', definition: 'Monitoring Windows Management Instrumentation for malicious use.', url: 'https://d3fend.mitre.org/technique/d3f:WMIActivityAnalysis', attackIds: ['T1047', 'T1546.003', 'T1059.001'] },
  { id: 'D3-PCSM', name: 'Process Code Segment Analysis', category: 'Detect', definition: 'Detecting injected or modified code segments within running processes.', url: 'https://d3fend.mitre.org/technique/d3f:ProcessCodeSegmentVerification', attackIds: ['T1055', 'T1027', 'T1059'] },
  { id: 'D3-NPA', name: 'Network Port Scan Detection', category: 'Detect', definition: 'Identifying port scanning and network enumeration activity.', url: 'https://d3fend.mitre.org/technique/d3f:NetworkPortScanDetection', attackIds: ['T1046', 'T1595', 'T1040'] },
  { id: 'D3-CAL', name: 'Cloud Audit Logging', category: 'Detect', definition: 'Enabling and monitoring audit logs in cloud environments for unauthorized actions.', url: 'https://d3fend.mitre.org/technique/d3f:CloudAuditLogging', attackIds: ['T1530', 'T1213', 'T1078', 'T1119'] },

  // Isolate
  { id: 'D3-WAF', name: 'Web Application Firewall', category: 'Isolate', definition: 'Filtering and monitoring HTTP traffic between the internet and web applications.', url: 'https://d3fend.mitre.org/technique/d3f:WebApplicationFirewall', attackIds: ['T1190', 'T1505', 'T1189'] },
  { id: 'D3-SBX', name: 'Dynamic Analysis Sandbox', category: 'Isolate', definition: 'Executing untrusted code in isolated sandbox environments.', url: 'https://d3fend.mitre.org/technique/d3f:DynamicAnalysis', attackIds: ['T1204', 'T1027', 'T1059', 'T1566'] },
  { id: 'D3-TTPD', name: 'Transfer Technique Protection', category: 'Isolate', definition: 'Restricting and monitoring file transfer mechanisms.', url: 'https://d3fend.mitre.org/technique/d3f:DataTransferSizeLimit', attackIds: ['T1048', 'T1030', 'T1567', 'T1041'] },
  { id: 'D3-OAM', name: 'Outbound Traffic Filtering', category: 'Isolate', definition: 'Filtering outbound network connections to prevent data exfiltration.', url: 'https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering', attackIds: ['T1041', 'T1048', 'T1567', 'T1071'] },
  { id: 'D3-DFAS', name: 'Database Firewall', category: 'Isolate', definition: 'Restricting and monitoring database access and queries.', url: 'https://d3fend.mitre.org/technique/d3f:DatabaseFirewall', attackIds: ['T1213', 'T1530', 'T1078'] },
  { id: 'D3-SEG', name: 'Network Segmentation', category: 'Isolate', definition: 'Dividing the network into segments to limit lateral movement and blast radius.', url: 'https://d3fend.mitre.org/technique/d3f:NetworkSegmentation', attackIds: ['T1021', 'T1570', 'T1095', 'T1046'] },
  { id: 'D3-AG', name: 'Air Gap', category: 'Isolate', definition: 'Physically isolating critical systems from untrusted networks.', url: 'https://d3fend.mitre.org/technique/d3f:AirGap', attackIds: ['T1021', 'T1091', 'T1052', 'T1197'] },
  { id: 'D3-VSEG', name: 'VLAN Isolation', category: 'Isolate', definition: 'Using VLANs to isolate network segments and restrict inter-VLAN communication.', url: 'https://d3fend.mitre.org/technique/d3f:VirtualLANIsolation', attackIds: ['T1021', 'T1046', 'T1095'] },
  { id: 'D3-QUA', name: 'Host Quarantine', category: 'Isolate', definition: 'Quarantining compromised hosts from the rest of the network.', url: 'https://d3fend.mitre.org/technique/d3f:EndpointQuarantine', attackIds: ['T1021', 'T1570', 'T1105'] },
  { id: 'D3-EDR', name: 'Endpoint Detection and Response', category: 'Isolate', definition: 'Deploying EDR solutions to monitor and isolate endpoint threats.', url: 'https://d3fend.mitre.org/technique/d3f:EndpointDetectionAndResponse', attackIds: ['T1059', 'T1055', 'T1036', 'T1027'] },
  { id: 'D3-PROXF', name: 'Proxy Filtering', category: 'Isolate', definition: 'Routing internet traffic through a proxy for content inspection and filtering.', url: 'https://d3fend.mitre.org/technique/d3f:ForwardProxy', attackIds: ['T1071', 'T1090', 'T1105', 'T1567'] },
  { id: 'D3-CNTX', name: 'Container Isolation', category: 'Isolate', definition: 'Running applications in containers to limit the impact of compromise.', url: 'https://d3fend.mitre.org/technique/d3f:ContainerIsolation', attackIds: ['T1059', 'T1055', 'T1610'] },
  { id: 'D3-PRVZ', name: 'Virtualization', category: 'Isolate', definition: 'Using virtual machines to isolate workloads and limit lateral movement.', url: 'https://d3fend.mitre.org/technique/d3f:SystemVirtualization', attackIds: ['T1021', 'T1068', 'T1055'] },

  // Deceive
  { id: 'D3-HCR', name: 'Honey Credentials', category: 'Deceive', definition: 'Deploying fake credentials that alert when accessed.', url: 'https://d3fend.mitre.org/technique/d3f:HoneyCredential', attackIds: ['T1078', 'T1003', 'T1552', 'T1110'] },
  { id: 'D3-HPN', name: 'Honeyport', category: 'Deceive', definition: 'Monitoring fake open ports to detect scanning activity.', url: 'https://d3fend.mitre.org/technique/d3f:Honeyport', attackIds: ['T1046', 'T1190'] },
  { id: 'D3-HNET', name: 'Honeynet', category: 'Deceive', definition: 'Network of decoy systems to detect and study adversary activity.', url: 'https://d3fend.mitre.org/technique/d3f:Honeynet', attackIds: ['T1046', 'T1082', 'T1021'] },
  { id: 'D3-HFD', name: 'Honey File', category: 'Deceive', definition: 'Placing fake files that alert when accessed or exfiltrated.', url: 'https://d3fend.mitre.org/technique/d3f:HoneyFile', attackIds: ['T1083', 'T1005', 'T1025', 'T1213'] },
  { id: 'D3-NDA', name: 'Network Decoy', category: 'Deceive', definition: 'Deploying decoy network services to attract and detect adversaries.', url: 'https://d3fend.mitre.org/technique/d3f:NetworkDecoy', attackIds: ['T1021', 'T1046', 'T1571'] },
  { id: 'D3-NTD', name: 'Network Traffic Decoy', category: 'Deceive', definition: 'Injecting fake traffic to confuse adversary reconnaissance and analysis.', url: 'https://d3fend.mitre.org/technique/d3f:NetworkTrafficDecoy', attackIds: ['T1040', 'T1557', 'T1046'] },
  { id: 'D3-HP', name: 'Honeypot', category: 'Deceive', definition: 'Deploying decoy systems that mimic real assets to detect intruders.', url: 'https://d3fend.mitre.org/technique/d3f:Honeypot', attackIds: ['T1046', 'T1082', 'T1083', 'T1021'] },
  { id: 'D3-HT', name: 'Honey Token', category: 'Deceive', definition: 'Embedding fake API keys or tokens that alert when used.', url: 'https://d3fend.mitre.org/technique/d3f:HoneyToken', attackIds: ['T1552', 'T1078', 'T1530'] },
  { id: 'D3-DCY', name: 'Decoy Account', category: 'Deceive', definition: 'Creating fake user or service accounts that trigger alerts on access.', url: 'https://d3fend.mitre.org/technique/d3f:DecoyUserCredential', attackIds: ['T1087', 'T1069', 'T1078', 'T1098'] },
  { id: 'D3-DNET', name: 'Decoy Network Resource', category: 'Deceive', definition: 'Deploying fake network shares or services as canaries.', url: 'https://d3fend.mitre.org/technique/d3f:DecoyNetworkResource', attackIds: ['T1039', 'T1135', 'T1213'] },
  { id: 'D3-DFND', name: 'Decoy Directory', category: 'Deceive', definition: 'Creating decoy directories and paths to detect unauthorized access.', url: 'https://d3fend.mitre.org/technique/d3f:DecoyDirectory', attackIds: ['T1083', 'T1119', 'T1074'] },

  // Evict
  { id: 'D3-PT', name: 'Process Termination', category: 'Evict', definition: 'Terminating malicious or unauthorized processes.', url: 'https://d3fend.mitre.org/technique/d3f:ProcessTermination', attackIds: ['T1055', 'T1059', 'T1203'] },
  { id: 'D3-STO', name: 'Software Update', category: 'Evict', definition: 'Updating or replacing compromised software components.', url: 'https://d3fend.mitre.org/technique/d3f:SoftwareUpdate', attackIds: ['T1195', 'T1554', 'T1574'] },
  { id: 'D3-ACR', name: 'Account Recovery', category: 'Evict', definition: 'Resetting or revoking compromised accounts and credentials.', url: 'https://d3fend.mitre.org/technique/d3f:AccountLocking', attackIds: ['T1078', 'T1098', 'T1136', 'T1110'] },
  { id: 'D3-PRS', name: 'Persistence Removal', category: 'Evict', definition: 'Identifying and removing persistence mechanisms left by adversaries.', url: 'https://d3fend.mitre.org/technique/d3f:PersistenceRemoval', attackIds: ['T1547', 'T1053', 'T1543', 'T1574'] },
  { id: 'D3-ISR', name: 'Incident System Reimaging', category: 'Evict', definition: 'Rebuilding compromised systems from trusted images.', url: 'https://d3fend.mitre.org/technique/d3f:SystemReimaging', attackIds: ['T1485', 'T1490', 'T1027'] },
  { id: 'D3-ARTF', name: 'Artifact Removal', category: 'Evict', definition: 'Removing adversary tools and artifacts from compromised systems.', url: 'https://d3fend.mitre.org/technique/d3f:ArtifactRemoval', attackIds: ['T1105', 'T1036', 'T1027'] },
  { id: 'D3-NKR', name: 'Network Session Revocation', category: 'Evict', definition: 'Terminating active network sessions associated with adversary activity.', url: 'https://d3fend.mitre.org/technique/d3f:NetworkSessionRevocation', attackIds: ['T1021', 'T1095', 'T1571'] },
  { id: 'D3-CRK', name: 'Credential Revocation', category: 'Evict', definition: 'Revoking certificates and tokens associated with compromised accounts.', url: 'https://d3fend.mitre.org/technique/d3f:CredentialRevocation', attackIds: ['T1552', 'T1078', 'T1098', 'T1556'] },
];

// D3FEND 1.4.0+ per-technique mapping endpoint. Returns SPARQL-style bindings
// with authoritative def_tactic_label (Harden/Detect/Isolate/Deceive/Evict).
const D3FEND_TECHNIQUE_API = 'https://d3fend.mitre.org/api/offensive-technique/attack/';
// JSON-LD list of every defensive technique currently in the ontology.
// Used at startup to prune bundled entries whose IDs/names were removed or
// reassigned in D3FEND 1.4.0 (e.g. D3-PRS, D3-CE).
const D3FEND_ALL_TECHNIQUES_API = 'https://d3fend.mitre.org/api/technique/all.json';

interface D3fendOntologyNode {
  '@id'?: string;
  'd3f:d3fend-id'?: string;
  'rdfs:label'?: string;
}
interface D3fendOntologyResponse {
  '@graph'?: D3fendOntologyNode[];
}

interface D3fendSparqlLiteral { value: string }
interface D3fendSparqlBinding {
  def_tactic_label?: D3fendSparqlLiteral;
  def_tech_label?: D3fendSparqlLiteral;
  def_tech_id?: D3fendSparqlLiteral;
  def_tech?: D3fendSparqlLiteral;
}
interface D3fendAttackResponse {
  off_to_def?: { results?: { bindings?: D3fendSparqlBinding[] } };
}

const VALID_CATEGORIES: ReadonlySet<D3fendTechnique['category']> =
  new Set(['Harden', 'Detect', 'Isolate', 'Deceive', 'Evict']);

// IDs that were removed from the D3FEND ontology in 1.4.0 (verified against
// api/technique/all.json on 2026-04-17). These bundled entries produce dead
// links to d3fend.mitre.org, so we filter them out at service init — before
// any network call — so offline users aren't shown broken tiles either.
const REMOVED_IN_D3FEND_1_4_0: ReadonlySet<string> = new Set([
  'D3-PAMDA', 'D3-RCAM', 'D3-FR', 'D3-UAA', 'D3-CIPA', 'D3-DNSD', 'D3-MPR',
  'D3-ILA', 'D3-SAML', 'D3-BI', 'D3-SAPE', 'D3-CAR', 'D3-RFM', 'D3-AAC',
  'D3-OAH', 'D3-NFW', 'D3-URL', 'D3-ATH', 'D3-LFA', 'D3-JT', 'D3-CHA',
  'D3-UAM', 'D3-EMAL', 'D3-DISC', 'D3-EXA', 'D3-WIA', 'D3-PCSM', 'D3-NPA',
  'D3-CAL', 'D3-WAF', 'D3-SBX', 'D3-TTPD', 'D3-DFAS', 'D3-SEG', 'D3-AG',
  'D3-VSEG', 'D3-QUA', 'D3-EDR', 'D3-PROXF', 'D3-CNTX', 'D3-PRVZ', 'D3-HCR',
  'D3-HPN', 'D3-HNET', 'D3-HFD', 'D3-NDA', 'D3-NTD', 'D3-HP', 'D3-HT',
  'D3-DCY', 'D3-DNET', 'D3-DFND', 'D3-STO', 'D3-ACR', 'D3-PRS', 'D3-ISR',
  'D3-ARTF', 'D3-NKR', 'D3-CRK',
]);

// IDs whose labels were reassigned to a different technique in 1.4.0
// (e.g. D3-CE was "Credential Encryption", is now "Credential Eviction").
// The bundled ATT&CK mappings were written for the OLD meaning, so the
// mappings no longer apply. Drop these too; live per-technique fetches
// fill in the current mappings from the D3FEND API.
const REASSIGNED_IN_D3FEND_1_4_0: ReadonlySet<string> = new Set([
  'D3-HBPI', 'D3-MAN', 'D3-IOPR', 'D3-SRA', 'D3-EI', 'D3-BA', 'D3-PLA',
  'D3-CE', 'D3-SPP', 'D3-PMAD', 'D3-ANET', 'D3-SCH', 'D3-SYSM', 'D3-EHB',
  'D3-PH', 'D3-ACH', 'D3-CP', 'D3-MA', 'D3-TBI', 'D3-RTA', 'D3-DA', 'D3-IAA',
  'D3-OAM',
]);

@Injectable({ providedIn: 'root' })
export class D3fendService {
  private byAttackId = new Map<string, D3fendTechnique[]>();
  private liveIndex = new Map<string, D3fendTechnique>();

  /** Live data keyed by ATT&CK ID (populated lazily per technique) */
  private liveMap = new Map<string, D3fendTechnique[]>();

  /** Track in-flight and completed fetches to dedupe requests. */
  private fetchStatus = new Map<string, 'pending' | 'done'>();

  /** Current D3FEND ontology ID -> label. Empty until startup fetch resolves. */
  private currentOntology = new Map<string, string>();

  /** Emits on bundled-ready and after each successful live fetch merges. */
  loaded$ = new BehaviorSubject<boolean>(true);

  constructor(private http: HttpClient) {
    // Build index from bundled data, excluding entries that are invalid in
    // D3FEND 1.4.0. This runs synchronously at startup so stale tiles never
    // render — even before the live ontology fetch resolves or when offline.
    for (const d of D3FEND_MAPPING) {
      if (REMOVED_IN_D3FEND_1_4_0.has(d.id)) continue;
      if (REASSIGNED_IN_D3FEND_1_4_0.has(d.id)) continue;
      this.liveIndex.set(d.id, d);
      for (const attackId of d.attackIds) {
        if (!this.byAttackId.has(attackId)) this.byAttackId.set(attackId, []);
        this.byAttackId.get(attackId)!.push(d);
      }
    }
    this.loadOntologyIndex();
  }

  /**
   * Fetch the current D3FEND defensive technique index and reconcile bundled
   * entries against it. Drops bundled entries whose IDs were removed from the
   * ontology (e.g. D3-PRS) and corrects labels for IDs that were reassigned
   * to a different technique (e.g. D3-CE Credential Encryption -> Eviction).
   * No-op on network failure — bundled data stays as offline fallback.
   */
  private loadOntologyIndex(): void {
    this.http.get<D3fendOntologyResponse>(D3FEND_ALL_TECHNIQUES_API)
      .pipe(catchError(() => of(null)))
      .subscribe(response => {
        const graph = response?.['@graph'];
        if (!graph?.length) return;

        for (const node of graph) {
          const id = node['d3f:d3fend-id'];
          const label = node['rdfs:label'];
          if (id && label && id.startsWith('D3-')) this.currentOntology.set(id, label);
        }
        if (!this.currentOntology.size) return;

        this.reconcileBundledData();
        this.loaded$.next(true);
      });
  }

  /** Drop bundled entries whose ID or name no longer matches current D3FEND. */
  private reconcileBundledData(): void {
    const norm = (s: string) => s.toLowerCase().replace(/[\s\-/]/g, '');
    // We drop both fully-removed IDs *and* IDs reassigned to a different
    // technique — the bundled ATT&CK mappings were written for the old name
    // and no longer apply. Live per-technique fetches fill in the current
    // mappings from d3fend.mitre.org.
    const keep = (d: D3fendTechnique): boolean => {
      const current = this.currentOntology.get(d.id);
      return !!current && norm(current) === norm(d.name);
    };

    const survivors = D3FEND_MAPPING.filter(keep);
    this.liveIndex.clear();
    this.byAttackId.clear();
    for (const d of survivors) {
      this.liveIndex.set(d.id, d);
      for (const attackId of d.attackIds) {
        if (!this.byAttackId.has(attackId)) this.byAttackId.set(attackId, []);
        this.byAttackId.get(attackId)!.push(d);
      }
    }
  }

  /**
   * Fetch live D3FEND countermeasures for a single ATT&CK technique from
   * d3fend.mitre.org (v1.4.0 ontology). Deduplicates in-flight and completed
   * requests. On success, merges results into `liveMap` and emits `loaded$`
   * so subscribers (matrix, panels) re-render.
   */
  private fetchLiveForAttackId(attackId: string): void {
    if (this.fetchStatus.has(attackId)) return;
    // D3FEND URL format uses slash for subtechniques: T1059.001 -> T1059/001
    const urlId = attackId.replace('.', '/');
    this.fetchStatus.set(attackId, 'pending');

    this.http.get<D3fendAttackResponse>(`${D3FEND_TECHNIQUE_API}${urlId}.json`)
      .pipe(catchError(() => of(null)))
      .subscribe(response => {
        this.fetchStatus.set(attackId, 'done');
        const bindings = response?.off_to_def?.results?.bindings;
        if (!bindings?.length) return;

        const collected: D3fendTechnique[] = [];
        const seen = new Set<string>();
        for (const b of bindings) {
          const defId = b.def_tech_id?.value ?? '';
          const defLabel = b.def_tech_label?.value ?? '';
          const tactic = b.def_tactic_label?.value ?? '';
          if (!defId || !defLabel) continue;
          if (seen.has(defId)) continue;
          seen.add(defId);

          const category = VALID_CATEGORIES.has(tactic as D3fendTechnique['category'])
            ? (tactic as D3fendTechnique['category'])
            : 'Detect';

          // Prefer ontology URI fragment for URL when available.
          const uri = b.def_tech?.value ?? '';
          const fragment = uri.split('#')[1] ?? defLabel.replace(/\s+/g, '');

          collected.push({
            id: defId,
            name: defLabel,
            definition: `D3FEND ${category.toLowerCase()} countermeasure that counters ${attackId}.`,
            url: `https://d3fend.mitre.org/technique/d3f:${fragment}`,
            category,
            attackIds: [attackId],
          });
          if (!this.liveIndex.has(defId)) this.liveIndex.set(defId, collected[collected.length - 1]);
        }

        if (collected.length) {
          this.liveMap.set(attackId, collected);
          this.loaded$.next(true);
        }
      });
  }

  /**
   * @param attackId e.g. "T1059" or "T1059.001"
   * @param fetchLive when true, kick off a live D3FEND API fetch (deduped).
   *   Pass false from hot paths like matrix rendering where hundreds of
   *   techniques are queried just for counts — otherwise we'd fire 200+
   *   requests at startup. Panel/detail views that actually display
   *   countermeasures should pass true.
   */
  getCountermeasures(attackId: string, fetchLive = false): D3fendTechnique[] {
    if (fetchLive) {
      this.fetchLiveForAttackId(attackId);
      if (attackId.includes('.')) this.fetchLiveForAttackId(attackId.split('.')[0]);
    }

    // Merge hardcoded + live data, deduplicated by technique ID
    const parentId = attackId.includes('.') ? attackId.split('.')[0] : null;
    const prefix = attackId + '.';

    const hardcoded = [
      ...(this.byAttackId.get(attackId) ?? []),
      ...(parentId ? (this.byAttackId.get(parentId) ?? []) : []),
      ...(!attackId.includes('.')
        ? [...this.byAttackId.entries()]
            .filter(([id]) => id.startsWith(prefix))
            .flatMap(([, values]) => values)
        : []),
    ];
    const seen = new Set(hardcoded.map(d => d.id));

    const live = [
      ...(this.liveMap.get(attackId) ?? []),
      ...(parentId ? (this.liveMap.get(parentId) ?? []) : []),
      ...(!attackId.includes('.')
        ? [...this.liveMap.entries()]
            .filter(([id]) => id.startsWith(prefix))
            .flatMap(([, values]) => values)
        : []),
    ].filter(d => !seen.has(d.id));

    return [...hardcoded, ...live];
  }

  getAllTechniques(): D3fendTechnique[] {
    return [...this.liveIndex.values()];
  }

  getAllByCategory(): Map<string, D3fendTechnique[]> {
    const map = new Map<string, D3fendTechnique[]>();
    for (const d of this.liveIndex.values()) {
      if (!map.has(d.category)) map.set(d.category, []);
      map.get(d.category)!.push(d);
    }
    return map;
  }
}
