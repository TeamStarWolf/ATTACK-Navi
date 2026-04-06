// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { Technique } from '../models/technique';

export interface YaraPattern {
  attackId: string;
  strings: string[];       // YARA string patterns
  conditions: string[];    // condition fragments
  meta: Record<string, string>;
}

export interface YaraRule {
  ruleName: string;
  attackId: string;
  techniqueName: string;
  tags: string[];
  meta: Record<string, string>;
  strings: string[];
  condition: string;
  yaml: string;
}

// ATT&CK technique → YARA detection patterns
const YARA_PATTERNS: YaraPattern[] = [
  { attackId: 'T1059.001', strings: ['$ps1 = "powershell" nocase wide ascii', '$enc = "-EncodedCommand" nocase', '$nop = "-NonInteractive" nocase', '$bypass = "-ExecutionPolicy Bypass" nocase', '$iex = "IEX" nocase', '$webclient = "New-Object Net.WebClient" nocase', '$download = "DownloadString" nocase'], conditions: ['2 of ($ps1, $enc, $nop, $bypass) or ($iex and $webclient) or ($download and $webclient)'], meta: { description: 'Detects suspicious PowerShell execution patterns', reference: 'https://attack.mitre.org/techniques/T1059/001/' } },
  { attackId: 'T1059.003', strings: ['$cmd = "cmd.exe" nocase wide ascii', '$c = "/c " nocase', '$k = "/k " nocase', '$hidden = "/q" nocase', '$pipe = "2>&1" ascii', '$env = "%COMSPEC%" nocase'], conditions: ['$cmd and ($c or $k) and ($hidden or $pipe or $env)'], meta: { description: 'Detects suspicious cmd.exe execution', reference: 'https://attack.mitre.org/techniques/T1059/003/' } },
  { attackId: 'T1059.005', strings: ['$vbs1 = "WScript.Shell" nocase', '$vbs2 = "CreateObject" nocase', '$vbs3 = "Shell.Application" nocase', '$vbs4 = ".Run(" nocase', '$vbs5 = "GetObject(" nocase', '$vbs6 = "Execute(" nocase'], conditions: ['2 of them'], meta: { description: 'Detects VBScript/VBA malicious patterns', reference: 'https://attack.mitre.org/techniques/T1059/005/' } },
  { attackId: 'T1055', strings: ['$virt = "VirtualAllocEx" ascii', '$write = "WriteProcessMemory" ascii', '$thread = "CreateRemoteThread" ascii', '$inject = "NtCreateThreadEx" ascii', '$map = "MapViewOfFile" ascii', '$hollow = "NtUnmapViewOfSection" ascii', '$queueapc = "QueueUserAPC" ascii'], conditions: ['2 of them'], meta: { description: 'Detects process injection API patterns', reference: 'https://attack.mitre.org/techniques/T1055/' } },
  { attackId: 'T1003.001', strings: ['$mimi1 = "sekurlsa::logonpasswords" nocase', '$mimi2 = "privilege::debug" nocase', '$mimi3 = "lsadump::dcsync" nocase', '$mimi4 = "mimikatz" nocase', '$procdump = "MiniDumpWriteDump" ascii', '$lsass = "lsass.exe" nocase wide'], conditions: ['($mimi1 or $mimi2 or $mimi3 or $mimi4) or ($procdump and $lsass)'], meta: { description: 'Detects credential dumping from LSASS', reference: 'https://attack.mitre.org/techniques/T1003/001/' } },
  { attackId: 'T1027', strings: ['$b64_1 = "TVqQAAMAAAAEAAA" ascii', '$b64_2 = "JABjAG0AZAAgAC" ascii', '$xor = "XOR" nocase ascii', '$compress = "System.IO.Compression" nocase', '$deflate = "DeflateStream" nocase', '$b64decode = "FromBase64String" nocase', '$chr_arr = "char[]" ascii'], conditions: ['2 of them'], meta: { description: 'Detects binary/script obfuscation techniques', reference: 'https://attack.mitre.org/techniques/T1027/' } },
  { attackId: 'T1218.010', strings: ['$reg1 = "regsvr32" nocase wide ascii', '$scrobj = "scrobj.dll" nocase', '$sct1 = ".sct" nocase', '$http = "http" nocase', '$comsvcs = "comsvcs.dll" nocase'], conditions: ['$reg1 and ($scrobj or $sct1 or $http)'], meta: { description: 'Detects Regsvr32 proxy execution / Squiblydoo', reference: 'https://attack.mitre.org/techniques/T1218/010/' } },
  { attackId: 'T1218.011', strings: ['$rdll1 = "rundll32" nocase wide ascii', '$js = "javascript:" nocase', '$shell = "shell32.dll" nocase', '$control = "control_rundll" nocase', '$url = "url.dll,FileProtocolHandler" nocase'], conditions: ['$rdll1 and ($js or $shell or $control or $url)'], meta: { description: 'Detects suspicious Rundll32 execution', reference: 'https://attack.mitre.org/techniques/T1218/011/' } },
  { attackId: 'T1218.005', strings: ['$mshta1 = "mshta" nocase wide ascii', '$vbs = ".vbs" nocase', '$hta = ".hta" nocase', '$js2 = ".js" nocase', '$http2 = "http://" nocase', '$https = "https://" nocase'], conditions: ['$mshta1 and ($vbs or $hta or $js2 or $http2 or $https)'], meta: { description: 'Detects MSHTA proxy execution', reference: 'https://attack.mitre.org/techniques/T1218/005/' } },
  { attackId: 'T1547.001', strings: ['$run1 = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase wide', '$run2 = "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase', '$run3 = "HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase', '$startup = "\\\\Startup\\\\" nocase wide'], conditions: ['any of them'], meta: { description: 'Detects Run key or Startup folder persistence', reference: 'https://attack.mitre.org/techniques/T1547/001/' } },
  { attackId: 'T1070.001', strings: ['$wevt = "wevtutil" nocase wide ascii', '$clear = "cl " nocase', '$clearlog = "clear-eventlog" nocase', '$remove = "Remove-EventLog" nocase', '$fsutil = "fsutil usn deletejournal" nocase'], conditions: ['any of them'], meta: { description: 'Detects Windows event log clearing', reference: 'https://attack.mitre.org/techniques/T1070/001/' } },
  { attackId: 'T1562.001', strings: ['$av1 = "Set-MpPreference" nocase', '$av2 = "DisableRealtimeMonitoring" nocase', '$av3 = "DisableAntiSpyware" nocase', '$sc1 = "sc stop" nocase wide ascii', '$sc2 = "WinDefend" nocase', '$tamper = "TamperProtection" nocase'], conditions: ['($av1 and ($av2 or $av3)) or ($sc1 and $sc2) or $tamper'], meta: { description: 'Detects Windows Defender tampering', reference: 'https://attack.mitre.org/techniques/T1562/001/' } },
  { attackId: 'T1490', strings: ['$bcd1 = "bcdedit" nocase wide ascii', '$bcd2 = "recoveryenabled No" nocase', '$shadow1 = "vssadmin delete shadows" nocase', '$shadow2 = "wmic shadowcopy delete" nocase', '$shadow3 = "Get-WmiObject Win32_ShadowCopy" nocase', '$wbadmin = "wbadmin delete catalog" nocase'], conditions: ['any of them'], meta: { description: 'Detects ransomware backup/recovery deletion patterns', reference: 'https://attack.mitre.org/techniques/T1490/' } },
  { attackId: 'T1566.001', strings: ['$macro1 = "AutoOpen" ascii', '$macro2 = "Document_Open" ascii', '$macro3 = "Auto_Open" ascii', '$shell1 = "Shell(" ascii', '$shell2 = "WScript.Shell" ascii', '$download2 = "URLDownloadToFile" ascii', '$createobj = "CreateObject" ascii'], conditions: ['($macro1 or $macro2 or $macro3) and ($shell1 or $shell2 or $download2 or $createobj)'], meta: { description: 'Detects malicious Office macro patterns', reference: 'https://attack.mitre.org/techniques/T1566/001/' } },
  { attackId: 'T1053.005', strings: ['$scht1 = "schtasks" nocase wide ascii', '$create = "/create" nocase', '$sc2 = "/sc" nocase', '$tr = "/tr" nocase', '$xml = "SchTasks.exe" nocase', '$onstart = "ONSTART" nocase', '$system_sched = "\\\\Windows\\\\System32\\\\Tasks\\\\" nocase wide'], conditions: ['($scht1 and $create and ($sc2 or $tr)) or $system_sched'], meta: { description: 'Detects scheduled task creation for persistence', reference: 'https://attack.mitre.org/techniques/T1053/005/' } },
  { attackId: 'T1105', strings: ['$cert = "certutil" nocase wide ascii', '$decode = "-decode" nocase', '$urlcache = "-urlcache" nocase', '$bitsadmin = "bitsadmin" nocase wide', '$transfer = "/transfer" nocase', '$bits2 = "Start-BitsTransfer" nocase'], conditions: ['($cert and ($decode or $urlcache)) or ($bitsadmin and $transfer) or $bits2'], meta: { description: 'Detects file download via built-in tools (certutil, BITS)', reference: 'https://attack.mitre.org/techniques/T1105/' } },
  { attackId: 'T1112', strings: ['$reg_add = "reg add" nocase wide ascii', '$reg_del = "reg delete" nocase wide', '$regedit = "regedit /s" nocase', '$regkey1 = "HKLM\\\\SYSTEM\\\\CurrentControlSet" nocase wide', '$regkey2 = "HKCU\\\\Software" nocase wide', '$regkey3 = "DisableAntiSpyware" nocase'], conditions: ['($reg_add or $reg_del or $regedit) or ($regkey1 and $regkey3) or ($regkey2 and $regkey3)'], meta: { description: 'Detects registry modification for defense evasion', reference: 'https://attack.mitre.org/techniques/T1112/' } },
  { attackId: 'T1078', strings: ['$runas = "runas" nocase wide ascii', '$token = "CreateProcessWithTokenW" ascii', '$impersonate = "ImpersonateLoggedOnUser" ascii', '$luid = "LogonUserW" ascii', '$whoami = "whoami /all" nocase', '$net_use = "net use" nocase wide'], conditions: ['any of ($token, $impersonate, $luid) or ($runas and $net_use)'], meta: { description: 'Detects account/token manipulation patterns', reference: 'https://attack.mitre.org/techniques/T1078/' } },
  { attackId: 'T1136.001', strings: ['$netuser1 = "net user" nocase wide ascii', '$netuser2 = "net localgroup" nocase wide', '$netuser3 = "administrators" nocase wide', '$add = "/add" nocase', '$new_localuser = "New-LocalUser" nocase', '$add_member = "Add-LocalGroupMember" nocase'], conditions: ['($netuser1 and $add) or ($netuser2 and $add) or $new_localuser or $add_member'], meta: { description: 'Detects local account creation', reference: 'https://attack.mitre.org/techniques/T1136/001/' } },
  { attackId: 'T1574.001', strings: ['$dll_hijack1 = { 4D 5A 90 00 03 00 00 00 }', '$dll_hijack2 = "DllMain" ascii', '$search1 = "LoadLibrary" ascii', '$search2 = "GetProcAddress" ascii', '$safemode = "SafeDllSearchMode" nocase', '$pathmod = "PATH=" nocase wide'], conditions: ['($dll_hijack1 and $dll_hijack2 and $search1 and $search2) or $safemode'], meta: { description: 'Detects DLL search order hijacking', reference: 'https://attack.mitre.org/techniques/T1574/001/' } },
  { attackId: 'T1048.003', strings: ['$dns_txt = "Resolve-DnsName" nocase', '$dns2 = "nslookup" nocase wide ascii', '$txt = " TXT " ascii', '$exfil1 = "dnscat" nocase', '$iodine = "iodine" nocase', '$dns3 = "dns2tcp" nocase'], conditions: ['any of them'], meta: { description: 'Detects DNS-based data exfiltration', reference: 'https://attack.mitre.org/techniques/T1048/003/' } },
  { attackId: 'T1041', strings: ['$upload1 = "Invoke-WebRequest" nocase', '$upload2 = "WebClient" nocase', '$method = "UploadString" nocase', '$method2 = "UploadData" nocase', '$post = "-Method POST" nocase', '$curl_post = "curl.*-d" ascii'], conditions: ['($upload1 or $upload2) and ($method or $method2 or $post) or $curl_post'], meta: { description: 'Detects data exfiltration over C2 channel', reference: 'https://attack.mitre.org/techniques/T1041/' } },
];

@Injectable({ providedIn: 'root' })
export class YaraService {
  private patternMap = new Map<string, YaraPattern>();

  constructor() {
    for (const p of YARA_PATTERNS) {
      this.patternMap.set(p.attackId, p);
      // Also map parent if subtechnique
      const parent = p.attackId.includes('.') ? p.attackId.split('.')[0] : null;
      if (parent && !this.patternMap.has(parent)) {
        this.patternMap.set(parent, p);
      }
    }
  }

  getPattern(attackId: string): YaraPattern | null {
    return this.patternMap.get(attackId) ?? this.patternMap.get(attackId.split('.')[0]) ?? null;
  }

  hasPattern(attackId: string): boolean {
    return this.getPattern(attackId) !== null;
  }

  generateRule(tech: Technique): YaraRule | null {
    const p = this.getPattern(tech.attackId);
    if (!p) return null;

    const ruleName = 'ATT_CK_' + tech.attackId.replace('.', '_') + '_' + tech.name.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 30);
    const tags = ['ATT_CK', tech.attackId.replace('.', '_'), ...tech.tacticShortnames.map(t => t.replace(/-/g, '_'))];
    const meta: Record<string, string> = {
      technique: tech.attackId,
      technique_name: tech.name,
      ...p.meta,
      author: 'ATT&CK Navi',
      date: new Date().toISOString().split('T')[0],
    };

    const yamlLines: string[] = [
      `rule ${ruleName} : ${tags.join(' ')} {`,
      `  meta:`,
      ...Object.entries(meta).map(([k, v]) => `    ${k} = "${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`),
      `  strings:`,
      ...p.strings.map(s => `    ${s}`),
      `  condition:`,
      `    ${p.conditions[0]}`,
      `}`,
    ];

    return { ruleName, attackId: tech.attackId, techniqueName: tech.name, tags, meta, strings: p.strings, condition: p.conditions[0], yaml: yamlLines.join('\n') };
  }

  generateRules(techniques: Technique[]): YaraRule[] {
    return techniques.map(t => this.generateRule(t)).filter((r): r is YaraRule => r !== null);
  }

  exportRules(rules: YaraRule[]): void {
    const header = `/*\n * YARA rules generated by ATT&CK Navi\n * Generated: ${new Date().toISOString()}\n * Techniques: ${rules.length}\n */\n\n`;
    const content = header + rules.map(r => r.yaml).join('\n\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `attack_yara_rules_${new Date().toISOString().split('T')[0]}.yar`;
    a.click();
    URL.revokeObjectURL(url);
  }

  getAllPatterns(): YaraPattern[] { return YARA_PATTERNS; }
}
