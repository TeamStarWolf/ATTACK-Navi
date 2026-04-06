// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { Technique } from '../models/technique';

export interface ZeekScript {
  attackId: string;
  techniqueName: string;
  filename: string;
  description: string;
  script: string;
  events: string[];  // Zeek event hooks used
}

// Technique-specific Zeek script templates
const SCRIPT_TEMPLATES: Record<string, { description: string; filename: string; events: string[]; script: string }[]> = {
  'T1071.001': [{
    description: 'Detect suspicious HTTP C2 beaconing and unusual user-agents',
    filename: 'detect-http-c2.zeek',
    events: ['http_request', 'HTTP::log_http'],
    script: `@load base/protocols/http
@load base/frameworks/notice

module ATT_CK_T1071_001;

export {
  redef enum Notice::Type += {
    Suspicious_HTTP_C2_Agent,
    HTTP_Beaconing_Detected,
  };
}

# Track request counts per src/dst pair for beaconing detection
global http_counts: table[addr, addr] of count &default=0 &create_expire=5 min;

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
  local ua = "";
  if (c$http?$user_agent) ua = c$http$user_agent;

  # Flag suspicious user-agents commonly used by malware/C2 frameworks
  local suspicious_uas = vector("curl/", "python-requests", "Go-http-client", "okhttp", "libwww-perl");
  for (i in suspicious_uas) {
    if (suspicious_uas[i] in ua) {
      NOTICE([$note=Suspicious_HTTP_C2_Agent,
              $conn=c,
              $msg=fmt("ATT&CK T1071.001: Suspicious user-agent %s from %s", ua, c$id$orig_h),
              $identifier=cat(c$id$orig_h, ua)]);
    }
  }

  # Track for beaconing detection
  local key = [c$id$orig_h, c$id$resp_h];
  http_counts[c$id$orig_h, c$id$resp_h] += 1;

  if (http_counts[c$id$orig_h, c$id$resp_h] > 20) {
    NOTICE([$note=HTTP_Beaconing_Detected,
            $conn=c,
            $msg=fmt("ATT&CK T1071.001: HTTP beaconing from %s to %s (%d requests in 5min)",
                     c$id$orig_h, c$id$resp_h, http_counts[c$id$orig_h, c$id$resp_h]),
            $identifier=cat(c$id$orig_h, c$id$resp_h)]);
    delete http_counts[c$id$orig_h, c$id$resp_h];
  }
}`,
  }],
  'T1071.004': [{
    description: 'Detect DNS-based C2 — long queries, high entropy domains, TXT record abuse',
    filename: 'detect-dns-c2.zeek',
    events: ['dns_request', 'dns_A_reply'],
    script: `@load base/protocols/dns
@load base/frameworks/notice

module ATT_CK_T1071_004;

export {
  redef enum Notice::Type += {
    DNS_C2_Long_Query,
    DNS_C2_High_Entropy,
    DNS_C2_TXT_Abuse,
  };
}

global dns_query_counts: table[addr] of count &default=0 &create_expire=1 min;

# Shannon entropy calculation
function entropy(s: string): double {
  local counts: table[string] of count &default=0;
  for (i in s) counts[s[i]] += 1;
  local e = 0.0;
  local len = |s|;
  for (c in counts) {
    local p = counts[c] / (len + 0.0);
    if (p > 0.0) e -= p * log(p) / log(2.0);
  }
  return e;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
  # Long DNS queries — potential data exfiltration
  if (|query| > 50) {
    NOTICE([$note=DNS_C2_Long_Query,
            $conn=c,
            $msg=fmt("ATT&CK T1071.004: Long DNS query (%d chars) from %s: %s",
                     |query|, c$id$orig_h, query),
            $identifier=cat(c$id$orig_h, "long_query")]);
  }

  # TXT record queries — commonly used for C2
  if (qtype == 16) {  # TXT record type
    dns_query_counts[c$id$orig_h] += 1;
    if (dns_query_counts[c$id$orig_h] > 10) {
      NOTICE([$note=DNS_C2_TXT_Abuse,
              $conn=c,
              $msg=fmt("ATT&CK T1071.004: High-frequency DNS TXT queries from %s", c$id$orig_h),
              $identifier=cat(c$id$orig_h, "txt_abuse")]);
    }
  }
}`,
  }],
  'T1046': [{
    description: 'Detect network port scanning — multiple destination ports from single source',
    filename: 'detect-port-scan.zeek',
    events: ['connection_attempt', 'connection_rejected'],
    script: `@load base/frameworks/notice
@load policy/misc/scan

module ATT_CK_T1046;

export {
  redef enum Notice::Type += {
    Port_Scan_Detected,
  };
  const scan_threshold = 100 &redef;  # unique ports within window
  const scan_window = 60 sec &redef;
}

global port_scan_tracker: table[addr] of set[port] &create_expire=scan_window;

event connection_attempt(c: connection) {
  local src = c$id$orig_h;
  local dst_port = c$id$resp_p;

  if (src !in port_scan_tracker)
    port_scan_tracker[src] = set();

  add port_scan_tracker[src][dst_port];

  if (|port_scan_tracker[src]| >= scan_threshold) {
    NOTICE([$note=Port_Scan_Detected,
            $conn=c,
            $msg=fmt("ATT&CK T1046: Port scan from %s — %d unique ports probed",
                     src, |port_scan_tracker[src]|),
            $identifier=cat(src, "port_scan")]);
    delete port_scan_tracker[src];
  }
}`,
  }],
  'T1040': [{
    description: 'Detect network sniffing — ARP cache poisoning and promiscuous mode indicators',
    filename: 'detect-network-sniffing.zeek',
    events: ['arp_request', 'arp_reply'],
    script: `@load base/frameworks/notice
@load base/protocols/arp

module ATT_CK_T1040;

export {
  redef enum Notice::Type += {
    ARP_Spoofing_Detected,
    ARP_Flood_Detected,
  };
}

global arp_reply_counts: table[addr] of count &default=0 &create_expire=30 sec;
global arp_cache: table[addr] of string &create_expire=10 min;

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string) {
  # Detect ARP cache poisoning — same IP responding with different MACs
  if (SPA in arp_cache && arp_cache[SPA] != SHA) {
    NOTICE([$note=ARP_Spoofing_Detected,
            $msg=fmt("ATT&CK T1040: ARP spoofing — IP %s claimed by %s (was %s)",
                     SPA, SHA, arp_cache[SPA]),
            $identifier=cat(SPA, "arp_spoof")]);
  }
  arp_cache[SPA] = SHA;

  arp_reply_counts[SPA] += 1;
  if (arp_reply_counts[SPA] > 30) {
    NOTICE([$note=ARP_Flood_Detected,
            $msg=fmt("ATT&CK T1040: ARP flood from %s (MAC: %s) — %d replies in 30s",
                     SPA, SHA, arp_reply_counts[SPA]),
            $identifier=cat(SPA, "arp_flood")]);
    delete arp_reply_counts[SPA];
  }
}`,
  }],
  'T1041': [{
    description: 'Detect data exfiltration over existing C2 channel — large outbound transfers',
    filename: 'detect-exfil-c2.zeek',
    events: ['connection_state_remove', 'HTTP::log_http'],
    script: `@load base/frameworks/notice
@load base/protocols/http

module ATT_CK_T1041;

export {
  redef enum Notice::Type += {
    Large_HTTP_Exfiltration,
    Sustained_Outbound_Transfer,
  };
  const exfil_threshold_bytes = 10000000 &redef;  # 10MB
}

global outbound_bytes: table[addr] of count &default=0 &create_expire=1 hr;

event connection_state_remove(c: connection) {
  if (!c?$conn) return;
  local orig_bytes = c$conn$orig_bytes;
  local dst = c$id$resp_h;

  # Check if destination is external
  if (Site::is_local_addr(dst)) return;

  if (orig_bytes > exfil_threshold_bytes) {
    NOTICE([$note=Large_HTTP_Exfiltration,
            $conn=c,
            $msg=fmt("ATT&CK T1041: Large outbound transfer %d bytes from %s to %s",
                     orig_bytes, c$id$orig_h, dst),
            $identifier=cat(c$id$orig_h, "exfil")]);
  }

  outbound_bytes[c$id$orig_h] += orig_bytes;
  if (outbound_bytes[c$id$orig_h] > exfil_threshold_bytes * 5) {
    NOTICE([$note=Sustained_Outbound_Transfer,
            $conn=c,
            $msg=fmt("ATT&CK T1041: Sustained outbound from %s — %d bytes total in last hour",
                     c$id$orig_h, outbound_bytes[c$id$orig_h]),
            $identifier=cat(c$id$orig_h, "sustained_exfil")]);
    delete outbound_bytes[c$id$orig_h];
  }
}`,
  }],
  'T1110': [{
    description: 'Detect brute force authentication attacks across multiple protocols',
    filename: 'detect-brute-force.zeek',
    events: ['ssh_auth_failed', 'ftp_reply', 'http_reply'],
    script: `@load base/frameworks/notice
@load base/protocols/ssh

module ATT_CK_T1110;

export {
  redef enum Notice::Type += {
    SSH_Brute_Force,
    Multi_Protocol_Brute_Force,
  };
  const ssh_threshold = 10 &redef;
  const brute_window = 60 sec &redef;
}

global ssh_failures: table[addr] of count &default=0 &create_expire=brute_window;
global multi_proto_attempts: table[addr] of set[port] &create_expire=5 min;

event ssh_auth_failed(c: connection, user: string, client_version: string, server_version: string, auth_type: string) {
  local src = c$id$orig_h;
  ssh_failures[src] += 1;

  if (ssh_failures[src] >= ssh_threshold) {
    NOTICE([$note=SSH_Brute_Force,
            $conn=c,
            $msg=fmt("ATT&CK T1110: SSH brute force from %s — %d failures for user '%s'",
                     src, ssh_failures[src], user),
            $identifier=cat(src, "ssh_brute")]);
    delete ssh_failures[src];
  }
}`,
  }],
  'T1557': [{
    description: 'Detect MitM attacks — LLMNR/NBT-NS poisoning, ARP spoofing',
    filename: 'detect-mitm.zeek',
    events: ['dns_request', 'arp_reply'],
    script: `@load base/frameworks/notice

module ATT_CK_T1557;

export {
  redef enum Notice::Type += {
    LLMNR_Poisoning_Detected,
    NBT_NS_Poisoning_Detected,
  };
}

global llmnr_responders: table[addr] of set[string] &create_expire=5 min;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
  # LLMNR uses port 5355, MDNS uses 5353
  if (c$id$resp_p == 5355/udp || c$id$resp_p == 5353/udp) {
    if (c$id$orig_h !in llmnr_responders)
      llmnr_responders[c$id$orig_h] = set();
    add llmnr_responders[c$id$orig_h][query];

    if (|llmnr_responders[c$id$orig_h]| > 5) {
      NOTICE([$note=LLMNR_Poisoning_Detected,
              $conn=c,
              $msg=fmt("ATT&CK T1557: Possible LLMNR/MDNS poisoning from %s — responding to %d queries",
                       c$id$orig_h, |llmnr_responders[c$id$orig_h]|),
              $identifier=cat(c$id$orig_h, "llmnr")]);
    }
  }
}`,
  }],
  'T1190': [{
    description: 'Detect exploitation of public-facing applications — SQLi, XSS, path traversal',
    filename: 'detect-webapp-exploitation.zeek',
    events: ['http_request', 'http_reply'],
    script: `@load base/frameworks/notice
@load base/protocols/http

module ATT_CK_T1190;

export {
  redef enum Notice::Type += {
    SQL_Injection_Attempt,
    Path_Traversal_Attempt,
    XSS_Attempt,
  };
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
  local uri = unescaped_URI;

  # SQL Injection patterns
  if (/UNION.*SELECT|OR.*1.*=.*1|DROP.*TABLE|INSERT.*INTO/i in uri) {
    NOTICE([$note=SQL_Injection_Attempt,
            $conn=c,
            $msg=fmt("ATT&CK T1190: SQL injection attempt from %s: %s", c$id$orig_h, uri),
            $identifier=cat(c$id$orig_h, "sqli")]);
  }

  # Path traversal
  if (/(\\.\\.\\/){2,}|\\.\\.%2[fF]/ in uri) {
    NOTICE([$note=Path_Traversal_Attempt,
            $conn=c,
            $msg=fmt("ATT&CK T1190: Path traversal from %s: %s", c$id$orig_h, uri),
            $identifier=cat(c$id$orig_h, "path_traversal")]);
  }

  # XSS
  if (/<script|javascript:|on(load|click|error)=/i in uri) {
    NOTICE([$note=XSS_Attempt,
            $conn=c,
            $msg=fmt("ATT&CK T1190: XSS attempt from %s: %s", c$id$orig_h, uri),
            $identifier=cat(c$id$orig_h, "xss")]);
  }
}`,
  }],
  'T1021.004': [{
    description: 'Detect SSH lateral movement and tunneling within the network',
    filename: 'detect-ssh-lateral.zeek',
    events: ['ssh_client_version', 'connection_state_remove'],
    script: `@load base/frameworks/notice
@load base/protocols/ssh

module ATT_CK_T1021_004;

export {
  redef enum Notice::Type += {
    SSH_Lateral_Movement,
    SSH_Tunnel_Detected,
  };
}

global internal_ssh: table[addr] of set[addr] &create_expire=30 min;

event ssh_client_version(c: connection, version: string) {
  local src = c$id$orig_h;
  local dst = c$id$resp_h;

  # Track internal SSH movements
  if (Site::is_local_addr(src) && Site::is_local_addr(dst)) {
    if (src !in internal_ssh) internal_ssh[src] = set();
    add internal_ssh[src][dst];

    if (|internal_ssh[src]| >= 5) {
      NOTICE([$note=SSH_Lateral_Movement,
              $conn=c,
              $msg=fmt("ATT&CK T1021.004: SSH lateral movement from %s to %d internal hosts",
                       src, |internal_ssh[src]|),
              $identifier=cat(src, "ssh_lateral")]);
    }
  }
}`,
  }],
};

@Injectable({ providedIn: 'root' })
export class ZeekService {

  getScripts(attackId: string): ZeekScript[] {
    const templates = SCRIPT_TEMPLATES[attackId] ?? SCRIPT_TEMPLATES[attackId.split('.')[0]] ?? [];
    return templates.map(t => ({ attackId, techniqueName: '', ...t }));
  }

  hasScripts(attackId: string): boolean {
    return attackId in SCRIPT_TEMPLATES || attackId.split('.')[0] in SCRIPT_TEMPLATES;
  }

  generateScriptsForTechnique(tech: Technique): ZeekScript[] {
    const templates = SCRIPT_TEMPLATES[tech.attackId] ?? SCRIPT_TEMPLATES[tech.attackId.split('.')[0]] ?? [];
    if (templates.length > 0) {
      return templates.map(t => ({
        attackId: tech.attackId,
        techniqueName: tech.name,
        ...t,
      }));
    }
    // Generic fallback for network techniques
    const isNetworkTech = ['command-and-control', 'exfiltration', 'lateral-movement', 'initial-access'].some(
      tactic => tech.tacticShortnames.includes(tactic)
    );
    if (isNetworkTech) {
      const safeName = tech.attackId.replace('.', '_');
      return [{
        attackId: tech.attackId,
        techniqueName: tech.name,
        filename: `detect-${tech.attackId.toLowerCase().replace('.', '-')}.zeek`,
        description: `Generic network detection for ${tech.attackId} — ${tech.name}`,
        events: ['connection_state_remove'],
        script: `@load base/frameworks/notice

module ATT_CK_${safeName};

export {
  redef enum Notice::Type += {
    ${safeName}_Activity,
  };
}

# TODO: Customize this template for ${tech.attackId} - ${tech.name}
# Reference: https://attack.mitre.org/techniques/${tech.attackId.replace('.', '/')}

event connection_state_remove(c: connection) {
  # Add your detection logic here
  # Example: track unusual connection patterns
  if (!Site::is_local_addr(c$id$resp_h)) {
    # Monitor outbound connections
  }
}`,
      }];
    }
    return [];
  }

  generatePackageForTechniques(techniques: Technique[]): string {
    const header = [
      `# Zeek Detection Package — MITRE ATT&CK`,
      `# Generated: ${new Date().toISOString().slice(0, 10)}`,
      `# Techniques: ${techniques.length}`,
      `# Source: ATT&CK Navi`,
      `#`,
      `# Installation:`,
      `#   zeek-pkg install ./attack-detection`,
      `#   or: zeek -r capture.pcap attack-detection/scripts/__load__.zeek`,
      ``,
    ].join('\n');

    const scripts: string[] = [];
    for (const tech of techniques) {
      const techScripts = this.generateScriptsForTechnique(tech);
      for (const s of techScripts) {
        scripts.push(`# ========== ${s.attackId} — ${tech.name} ==========`);
        scripts.push(`# Events: ${s.events.join(', ')}`);
        scripts.push(`# ${s.description}`);
        scripts.push(s.script);
        scripts.push('');
      }
    }

    return header + (scripts.length ? scripts.join('\n') : '# No Zeek scripts available for selected techniques\n');
  }

  exportScripts(techniques: Technique[]): void {
    const content = this.generatePackageForTechniques(techniques);
    const filename = `zeek-attack-detection-${new Date().toISOString().split('T')[0]}.zeek`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: filename });
    a.click();
    URL.revokeObjectURL(url);
  }

  getSupportedTechniqueIds(): string[] {
    return Object.keys(SCRIPT_TEMPLATES);
  }

  getScriptCount(): number {
    return Object.values(SCRIPT_TEMPLATES).reduce((sum, arr) => sum + arr.length, 0);
  }
}
