// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { Technique } from '../models/technique';

export interface SuricataRule {
  sid: number;
  attackId: string;
  techniqueName: string;
  rule: string;
  description: string;
  severity: 'high' | 'medium' | 'low';
}

// Base SID offset for ATT&CK-generated rules
const BASE_SID = 9100000;

// Technique-specific Suricata rule templates
const RULE_TEMPLATES: Record<string, Omit<SuricataRule, 'sid' | 'attackId' | 'techniqueName'>[]> = {
  'T1071.001': [
    {
      description: 'Detects potential C2 over HTTP with unusual user-agents',
      severity: 'high',
      rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ATT&CK T1071.001 - Suspicious C2 HTTP User-Agent"; flow:established,to_server; http.user_agent; content:"curl/"; nocase; threshold:type limit,track by_src,count 5,seconds 60; classtype:trojan-activity; metadata:attack_technique T1071.001; rev:1;)`,
    },
    {
      description: 'Detects beaconing pattern — regular HTTP requests at fixed intervals',
      severity: 'medium',
      rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ATT&CK T1071.001 - HTTP Beaconing Activity"; flow:established,to_server; http.method; content:"POST"; threshold:type both,track by_src,count 10,seconds 300; classtype:command-and-control; metadata:attack_technique T1071.001; rev:1;)`,
    },
  ],
  'T1071.004': [
    {
      description: 'Detects DNS-based C2 — unusually long DNS queries',
      severity: 'high',
      rule: `alert dns any any -> any 53 (msg:"ATT&CK T1071.004 - Long DNS Query (potential C2 exfil)"; dns.query; isdataat:50,relative; pcre:"/^[a-z0-9\\-\\.]{50,}/i"; threshold:type limit,track by_src,count 3,seconds 60; classtype:command-and-control; metadata:attack_technique T1071.004; rev:1;)`,
    },
    {
      description: 'Detects DNS TXT record queries used for data exfiltration',
      severity: 'high',
      rule: `alert dns any any -> any 53 (msg:"ATT&CK T1071.004 - DNS TXT Query (exfiltration)"; dns.query; content:"|00 10|"; offset:2; depth:4; threshold:type both,track by_src,count 20,seconds 300; classtype:data-theft; metadata:attack_technique T1071.004; rev:1;)`,
    },
  ],
  'T1048.003': [
    {
      description: 'Detects data exfiltration via DNS — high volume of TXT queries',
      severity: 'high',
      rule: `alert dns $HOME_NET any -> any 53 (msg:"ATT&CK T1048.003 - DNS Data Exfiltration"; dns.query; content:"|00 10|"; offset:2; threshold:type both,track by_src,count 50,seconds 60; classtype:data-theft; metadata:attack_technique T1048.003; rev:2;)`,
    },
  ],
  'T1041': [
    {
      description: 'Detects large outbound HTTP POST (potential data exfiltration)',
      severity: 'medium',
      rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ATT&CK T1041 - Large HTTP POST Exfiltration"; flow:established,to_server; http.method; content:"POST"; http.request_body; isdataat:10000; classtype:data-theft; metadata:attack_technique T1041; rev:1;)`,
    },
  ],
  'T1190': [
    {
      description: 'Detects SQL injection attempts in HTTP requests',
      severity: 'high',
      rule: `alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ATT&CK T1190 - SQL Injection in URI"; flow:established,to_server; http.uri; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; classtype:web-application-attack; metadata:attack_technique T1190; rev:1;)`,
    },
    {
      description: 'Detects path traversal attempts against web applications',
      severity: 'high',
      rule: `alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ATT&CK T1190 - Path Traversal Attack"; flow:established,to_server; http.uri; pcre:"/(\\.\\.\\/){3,}/"; classtype:web-application-attack; metadata:attack_technique T1190; rev:1;)`,
    },
  ],
  'T1110': [
    {
      description: 'Detects brute force authentication — many failed logins from same source',
      severity: 'medium',
      rule: `alert tcp $EXTERNAL_NET any -> $HOME_NET [22,23,3389,21,25,110,143] (msg:"ATT&CK T1110 - Brute Force Login Attempt"; flow:established,to_server; threshold:type both,track by_src,count 20,seconds 60; classtype:attempted-user; metadata:attack_technique T1110; rev:1;)`,
    },
    {
      description: 'Detects SSH brute force attempts',
      severity: 'high',
      rule: `alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ATT&CK T1110 - SSH Brute Force"; flow:established,to_server; content:"SSH-"; depth:4; threshold:type both,track by_src,count 5,seconds 30; classtype:attempted-admin; metadata:attack_technique T1110; rev:1;)`,
    },
  ],
  'T1046': [
    {
      description: 'Detects network port scanning activity',
      severity: 'medium',
      rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ATT&CK T1046 - Network Port Scan Detected"; flags:S; threshold:type both,track by_src,count 500,seconds 60; classtype:network-scan; metadata:attack_technique T1046; rev:1;)`,
    },
  ],
  'T1040': [
    {
      description: 'Detects ARP spoofing — potential network sniffing setup',
      severity: 'high',
      rule: `alert arp any any -> any any (msg:"ATT&CK T1040 - ARP Spoofing Detected"; arp.opcode:2; pcre:"/^(?!ff:ff:ff:ff:ff:ff).{17}$/"; threshold:type both,track by_src,count 10,seconds 10; classtype:protocol-command-decode; metadata:attack_technique T1040; rev:1;)`,
    },
  ],
  'T1557': [
    {
      description: 'Detects LLMNR/NBT-NS poisoning — potential MitM setup',
      severity: 'high',
      rule: `alert udp any any -> 224.0.0.252 5355 (msg:"ATT&CK T1557 - LLMNR Query (potential poisoning)"; content:"|00 00 00 01|"; offset:4; depth:4; threshold:type both,track by_src,count 5,seconds 30; classtype:policy-violation; metadata:attack_technique T1557; rev:1;)`,
    },
  ],
  'T1021.001': [
    {
      description: 'Detects RDP connections from external networks',
      severity: 'medium',
      rule: `alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"ATT&CK T1021.001 - External RDP Connection"; flow:established,to_server; content:"|03 00|"; depth:2; threshold:type limit,track by_src,count 1,seconds 3600; classtype:policy-violation; metadata:attack_technique T1021.001; rev:1;)`,
    },
  ],
  'T1021.004': [
    {
      description: 'Detects SSH lateral movement — internal SSH connections',
      severity: 'medium',
      rule: `alert tcp $HOME_NET any -> $HOME_NET 22 (msg:"ATT&CK T1021.004 - Internal SSH Lateral Movement"; flow:established,to_server; content:"SSH-2.0-"; depth:8; threshold:type both,track by_src,count 10,seconds 300; classtype:policy-violation; metadata:attack_technique T1021.004; rev:1;)`,
    },
  ],
  'T1059.007': [
    {
      description: 'Detects JavaScript/WebSocket-based C2',
      severity: 'medium',
      rule: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ATT&CK T1059.007 - WebSocket C2 Channel"; flow:established,to_server; http.header; content:"Upgrade: websocket"; nocase; http.uri; pcre:"/\\.(php|aspx|jsp)$/i"; classtype:command-and-control; metadata:attack_technique T1059.007; rev:1;)`,
    },
  ],
  'T1566.001': [
    {
      description: 'Detects macro-enabled Office documents delivered over email',
      severity: 'high',
      rule: `alert smtp $EXTERNAL_NET any -> $HOME_NET 25 (msg:"ATT&CK T1566.001 - Suspicious Office Attachment in Email"; flow:established,to_server; content:"Content-Type: application/"; nocase; pcre:"/(vnd\\.ms-excel|vnd\\.openxmlformats|msword)/i"; classtype:suspicious-filename-detect; metadata:attack_technique T1566.001; rev:1;)`,
    },
  ],
  'T1595': [
    {
      description: 'Detects active reconnaissance scanning',
      severity: 'low',
      rule: `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ATT&CK T1595 - Active Scanning Detected"; flags:S; threshold:type both,track by_src,count 200,seconds 60; classtype:network-scan; metadata:attack_technique T1595; rev:1;)`,
    },
  ],
  'T1592': [
    {
      description: 'Detects web scraping for host/service information gathering',
      severity: 'low',
      rule: `alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ATT&CK T1592 - Automated Host Info Gathering"; flow:established,to_server; http.user_agent; pcre:"/(wget|curl|python-requests|nikto|masscan|nmap)/i"; threshold:type both,track by_src,count 20,seconds 60; classtype:web-application-activity; metadata:attack_technique T1592; rev:1;)`,
    },
  ],
};

// ATT&CK ID → SID number mapping
function attackIdToSid(attackId: string): number {
  let hash = 0;
  for (let i = 0; i < attackId.length; i++) {
    hash = (hash * 31 + attackId.charCodeAt(i)) >>> 0;
  }
  return BASE_SID + (hash % 99999);
}

@Injectable({ providedIn: 'root' })
export class SuricataService {

  getRules(attackId: string): SuricataRule[] {
    const templates = RULE_TEMPLATES[attackId] ?? RULE_TEMPLATES[attackId.split('.')[0]] ?? [];
    return templates.map((t, i) => ({
      sid: attackIdToSid(attackId) + i,
      attackId,
      techniqueName: '',
      ...t,
    }));
  }

  hasRules(attackId: string): boolean {
    return (
      attackId in RULE_TEMPLATES ||
      attackId.split('.')[0] in RULE_TEMPLATES
    );
  }

  generateRulesForTechnique(tech: Technique): SuricataRule[] {
    const templates = RULE_TEMPLATES[tech.attackId] ?? RULE_TEMPLATES[tech.attackId.split('.')[0]] ?? [];
    if (templates.length > 0) {
      return templates.map((t, i) => ({
        sid: attackIdToSid(tech.attackId) + i,
        attackId: tech.attackId,
        techniqueName: tech.name,
        ...t,
      }));
    }
    // Generic fallback for network-capable techniques
    if (
      tech.platforms?.some(p => ['Network', 'Linux', 'Windows', 'macOS'].includes(p)) &&
      ['command-and-control', 'exfiltration', 'lateral-movement', 'initial-access', 'reconnaissance'].some(
        t => tech.tacticShortnames.includes(t)
      )
    ) {
      return [{
        sid: attackIdToSid(tech.attackId),
        attackId: tech.attackId,
        techniqueName: tech.name,
        description: `Generic network detection for ${tech.attackId} - ${tech.name}`,
        severity: 'low',
        rule: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ATT&CK ${tech.attackId} - ${tech.name}"; flow:established; threshold:type limit,track by_src,count 1,seconds 3600; classtype:policy-violation; metadata:attack_technique ${tech.attackId}; rev:1;)`,
      }];
    }
    return [];
  }

  generateRulesForTechniques(techniques: Technique[]): string {
    const header = [
      `# Suricata IDS Rules — MITRE ATT&CK`,
      `# Generated: ${new Date().toISOString().slice(0, 10)}`,
      `# Techniques: ${techniques.length}`,
      `# Source: ATT&CK Navi`,
      `#`,
      `# Classification metadata:`,
      `#   classtype:trojan-activity   = malware C2`,
      `#   classtype:data-theft        = data exfiltration`,
      `#   classtype:attempted-admin   = privilege escalation attempt`,
      `#   classtype:policy-violation  = policy/lateral movement`,
      ``,
    ].join('\n');

    const rules: string[] = [];
    for (const tech of techniques) {
      const techRules = this.generateRulesForTechnique(tech);
      if (techRules.length > 0) {
        rules.push(`# ${tech.attackId} — ${tech.name}`);
        for (const r of techRules) {
          rules.push(`# ${r.description}`);
          rules.push(r.rule);
        }
        rules.push('');
      }
    }

    return header + (rules.length ? rules.join('\n') : '# No Suricata rules available for selected techniques\n');
  }

  exportRules(techniques: Technique[]): void {
    const content = this.generateRulesForTechniques(techniques);
    const filename = `suricata-attack-rules-${new Date().toISOString().split('T')[0]}.rules`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: filename });
    a.click();
    URL.revokeObjectURL(url);
  }

  /** Returns all supported ATT&CK technique IDs */
  getSupportedTechniqueIds(): string[] {
    return Object.keys(RULE_TEMPLATES);
  }

  getRuleCount(): number {
    return Object.values(RULE_TEMPLATES).reduce((sum, arr) => sum + arr.length, 0);
  }
}
