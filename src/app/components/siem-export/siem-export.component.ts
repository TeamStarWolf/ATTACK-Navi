import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { CARService, CarAnalytic } from '../../services/car.service';
import { SuricataService, SuricataRule } from '../../services/suricata.service';
import { ZeekService, ZeekScript } from '../../services/zeek.service';
import { Technique } from '../../models/technique';

export type SiemPlatform = 'splunk' | 'sentinel' | 'elastic' | 'suricata' | 'zeek';
export type SiemExportMode = 'all' | 'by-technique' | 'by-tactic';

interface AnalyticEntry {
  analytic: CarAnalytic;
  included: boolean;
}

@Component({
  selector: 'app-siem-export',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './siem-export.component.html',
  styleUrl: './siem-export.component.scss',
})
export class SiemExportComponent implements OnInit, OnDestroy {
  open = false;
  activePlatform: SiemPlatform = 'splunk';
  exportMode: SiemExportMode = 'all';
  selectedTechniqueId = '';
  selectedTactic = '';
  techniques: Technique[] = [];
  analyticsEntries: AnalyticEntry[] = [];
  generatedContent = '';
  copied = false;
  filterText = '';
  listExpanded = false;

  // Suricata + Zeek state
  suricataRuleCount = 0;
  zeekScriptCount = 0;

  private subs = new Subscription();
  private allAnalytics: CarAnalytic[] = [];
  private tactics: string[] = [];

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private carService: CARService,
    private suricataService: SuricataService,
    private zeekService: ZeekService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(panel => {
        this.open = panel === 'siem';
        if (this.open) {
          this.loadData();
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  loadData(): void {
    this.allAnalytics = this.carService.getAll();
    this.analyticsEntries = this.allAnalytics.map(a => ({ analytic: a, included: true }));

    const domain = (this.dataService as any)['domainSubject']?.value;
    if (domain) {
      this.techniques = domain.techniques;
      const tacticSet = new Set<string>();
      for (const t of this.techniques) {
        for (const ts of t.tacticShortnames) tacticSet.add(ts);
      }
      this.tactics = [...tacticSet].sort();
    }

    this.generateExport();
    this.cdr.markForCheck();
  }

  get filteredAnalytics(): CarAnalytic[] {
    let analytics = this.analyticsEntries
      .filter(e => e.included)
      .map(e => e.analytic);

    if (this.exportMode === 'by-technique' && this.selectedTechniqueId) {
      analytics = analytics.filter(a =>
        a.attackIds.some(id =>
          id === this.selectedTechniqueId ||
          id.startsWith(this.selectedTechniqueId + '.') ||
          (this.selectedTechniqueId.includes('.') && id === this.selectedTechniqueId.split('.')[0])
        )
      );
    } else if (this.exportMode === 'by-tactic' && this.selectedTactic) {
      const techIdsInTactic = new Set(
        this.techniques
          .filter(t => t.tacticShortnames.includes(this.selectedTactic))
          .map(t => t.attackId)
      );
      analytics = analytics.filter(a =>
        a.attackIds.some(id => techIdsInTactic.has(id) || techIdsInTactic.has(id.split('.')[0]))
      );
    }

    if (this.filterText.trim()) {
      const q = this.filterText.toLowerCase();
      analytics = analytics.filter(a =>
        a.name.toLowerCase().includes(q) ||
        a.id.toLowerCase().includes(q) ||
        a.attackIds.some(id => id.toLowerCase().includes(q))
      );
    }

    return analytics;
  }

  get analyticsCount(): number {
    return this.filteredAnalytics.length;
  }

  get techniqueCount(): number {
    const ids = new Set<string>();
    for (const a of this.filteredAnalytics) {
      for (const id of a.attackIds) ids.add(id.split('.')[0]);
    }
    return ids.size;
  }

  get listAnalytics(): AnalyticEntry[] {
    const filtered = new Set(this.filteredAnalytics.map(a => a.id));
    return this.analyticsEntries.filter(e => filtered.has(e.analytic.id) || !e.included);
  }

  get fileExtension(): string {
    if (this.activePlatform === 'splunk') return 'spl';
    if (this.activePlatform === 'sentinel') return 'kql';
    if (this.activePlatform === 'suricata') return 'rules';
    if (this.activePlatform === 'zeek') return 'zeek';
    return 'eql';
  }

  get lineCount(): number {
    return this.generatedContent ? this.generatedContent.split('\n').length : 0;
  }

  generateExport(): void {
    // Suricata and Zeek are technique-driven, not analytics-driven
    if (this.activePlatform === 'suricata') {
      this.generatedContent = this.buildSuricataExport();
      this.suricataRuleCount = this.suricataService.getRuleCount();
      this.cdr.markForCheck();
      return;
    }
    if (this.activePlatform === 'zeek') {
      this.generatedContent = this.buildZeekExport();
      this.zeekScriptCount = this.zeekService.getScriptCount();
      this.cdr.markForCheck();
      return;
    }

    const analytics = this.filteredAnalytics;
    if (analytics.length === 0) {
      this.generatedContent = this.activePlatform === 'splunk'
        ? '| * No CAR analytics matched the current filter *'
        : '// No CAR analytics matched the current filter';
      this.cdr.markForCheck();
      return;
    }

    switch (this.activePlatform) {
      case 'splunk':
        this.generatedContent = this.buildSplunkExport(analytics);
        break;
      case 'sentinel':
        this.generatedContent = this.buildSentinelExport(analytics);
        break;
      case 'elastic':
        this.generatedContent = this.buildElasticExport(analytics);
        break;
    }
    this.cdr.markForCheck();
  }

  buildSuricataExport(): string {
    const techs = this.getFilteredTechniques();
    return this.suricataService.generateRulesForTechniques(techs);
  }

  buildZeekExport(): string {
    const techs = this.getFilteredTechniques();
    return this.zeekService.generatePackageForTechniques(techs);
  }

  private getFilteredTechniques(): Technique[] {
    let techs = this.techniques;
    if (this.exportMode === 'by-technique' && this.selectedTechniqueId) {
      techs = techs.filter(t => t.attackId === this.selectedTechniqueId || t.attackId.startsWith(this.selectedTechniqueId + '.'));
    } else if (this.exportMode === 'by-tactic' && this.selectedTactic) {
      techs = techs.filter(t => t.tacticShortnames.includes(this.selectedTactic));
    }
    return techs;
  }

  get isSuricataOrZeek(): boolean {
    return this.activePlatform === 'suricata' || this.activePlatform === 'zeek';
  }

  buildSplunkExport(analytics: CarAnalytic[]): string {
    const lines: string[] = [
      '| =====================================================================',
      '| MITRE ATT&CK CAR Analytics — Splunk SPL Detection Queries',
      `| Generated: ${new Date().toISOString().slice(0, 10)}`,
      `| Analytics: ${analytics.length}  |  Platform: Splunk SPL`,
      '| Source: MITRE Cyber Analytics Repository (car.mitre.org)',
      '| =====================================================================',
      '',
    ];

    for (const analytic of analytics) {
      const techIds = analytic.attackIds.join(', ');
      lines.push(
        `| ===== ${analytic.id}: ${analytic.name} =====`,
        `| ATT&CK: ${techIds}`,
        `| Description: ${analytic.description}`,
        `| Platforms: ${analytic.platforms.join(', ')}`,
        `| Reference: ${analytic.url}`,
      );

      lines.push(this.getSplunkQuery(analytic));
      lines.push('');
    }

    return lines.join('\n');
  }

  buildSentinelExport(analytics: CarAnalytic[]): string {
    const lines: string[] = [
      '// =====================================================================',
      '// MITRE ATT&CK CAR Analytics — Microsoft Sentinel KQL Detection Queries',
      `// Generated: ${new Date().toISOString().slice(0, 10)}`,
      `// Analytics: ${analytics.length}  |  Platform: Microsoft Sentinel KQL`,
      '// Source: MITRE Cyber Analytics Repository (car.mitre.org)',
      '// =====================================================================',
      '',
    ];

    for (const analytic of analytics) {
      const techIds = analytic.attackIds.join(', ');
      lines.push(
        `// ===== ${analytic.id}: ${analytic.name} =====`,
        `// ATT&CK: ${techIds}`,
        `// Description: ${analytic.description}`,
        `// Platforms: ${analytic.platforms.join(', ')}`,
        `// Reference: ${analytic.url}`,
      );

      lines.push(this.getSentinelQuery(analytic));
      lines.push('');
    }

    return lines.join('\n');
  }

  buildElasticExport(analytics: CarAnalytic[]): string {
    const lines: string[] = [
      '// =====================================================================',
      '// MITRE ATT&CK CAR Analytics — Elastic EQL Detection Queries',
      `// Generated: ${new Date().toISOString().slice(0, 10)}`,
      `// Analytics: ${analytics.length}  |  Platform: Elastic EQL`,
      '// Source: MITRE Cyber Analytics Repository (car.mitre.org)',
      '// =====================================================================',
      '',
    ];

    for (const analytic of analytics) {
      const techIds = analytic.attackIds.join(', ');
      lines.push(
        `// ===== ${analytic.id}: ${analytic.name} =====`,
        `// ATT&CK: ${techIds}`,
        `// Description: ${analytic.description}`,
        `// Platforms: ${analytic.platforms.join(', ')}`,
        `// Reference: ${analytic.url}`,
      );

      lines.push(this.getElasticQuery(analytic));
      lines.push('');
    }

    return lines.join('\n');
  }

  private getSplunkQuery(analytic: CarAnalytic): string {
    const techId = analytic.attackIds[0] ?? '';

    // Command & Scripting Interpreter
    if (techId.startsWith('T1059.001') || analytic.name.toLowerCase().includes('powershell')) {
      return [
        `index=* (sourcetype=WinEventLog:Security OR sourcetype=XmlWinEventLog:Microsoft-Windows-PowerShell/Operational) (EventCode=4688 OR EventCode=4104)`,
        `| eval CommandLine=coalesce(CommandLine, ScriptBlockText)`,
        `| search CommandLine IN ("*-enc*", "*-nop*", "*iex*", "*Invoke-Expression*", "*DownloadString*", "*bypass*")`,
        `| stats count by _time, Computer, User, CommandLine, ParentProcessName`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="execution"`,
        `| sort -_time`,
      ].join('\n');
    }
    if (techId.startsWith('T1059')) {
      return [
        `index=* sourcetype=WinEventLog:Security EventCode=4688`,
        `| search (NewProcessName="*cmd.exe" OR NewProcessName="*powershell.exe" OR NewProcessName="*wscript.exe" OR NewProcessName="*cscript.exe")`,
        `| eval suspicious=if(match(CommandLine, "-enc|-nop|/c .{200,}|iex |DownloadString"), 1, 0)`,
        `| where suspicious=1`,
        `| stats count by Computer, SubjectUserName, NewProcessName, CommandLine`,
        `| eval technique="${techId}", analytic="${analytic.id}"`,
      ].join('\n');
    }

    // Process Injection
    if (techId.startsWith('T1055')) {
      return [
        `index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=8`,
        `| rename TargetImage as target_process, SourceImage as source_process`,
        `| where NOT match(source_process, "(?i)(antivirus|defender|splunk|sysmon)")`,
        `| stats count by _time, Computer, source_process, target_process, StartModule`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="defense-evasion"`,
        `| sort -_time`,
      ].join('\n');
    }

    // Scheduled Task
    if (techId.startsWith('T1053')) {
      return [
        `index=* sourcetype=WinEventLog:Security (EventCode=4698 OR EventCode=4702 OR EventCode=4699)`,
        `| rename TaskName as task_name, SubjectUserName as user`,
        `| search NOT (user="SYSTEM" AND task_name IN ("\\Microsoft\\Windows\\*"))`,
        `| stats count by _time, Computer, user, task_name, TaskContent`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="persistence"`,
        `| sort -_time`,
      ].join('\n');
    }

    // Remote Desktop / Remote Services
    if (techId.startsWith('T1021.001') || analytic.name.toLowerCase().includes('rdp')) {
      return [
        `index=* sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=10`,
        `| stats count by _time, Computer, Account_Name, Workstation_Name, src_ip`,
        `| where count > 3`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="lateral-movement"`,
        `| sort -count`,
      ].join('\n');
    }
    if (techId.startsWith('T1021')) {
      return [
        `index=* sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625) (Logon_Type=3 OR Logon_Type=10)`,
        `| stats count as total_attempts, dc(src_ip) as unique_sources by Computer, Account_Name`,
        `| where total_attempts > 5 OR unique_sources > 3`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="lateral-movement"`,
        `| sort -total_attempts`,
      ].join('\n');
    }

    // Credential Access - LSASS
    if (techId.startsWith('T1003')) {
      return [
        `index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10`,
        `| search TargetImage="*lsass.exe"`,
        `| where NOT match(SourceImage, "(?i)(AV|antivirus|defender|MsMpEng|sysmon|csrss)")`,
        `| stats count by _time, Computer, SourceImage, TargetImage, GrantedAccess`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="credential-access"`,
        `| sort -_time`,
      ].join('\n');
    }

    // UAC Bypass
    if (techId.startsWith('T1548')) {
      return [
        `index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1`,
        `| search IntegrityLevel="High" NOT (User="*\\Administrator" OR User="*\\SYSTEM")`,
        `| where NOT match(CommandLine, "(?i)(msiexec|installer|setup|update)")`,
        `| stats count by _time, Computer, User, Image, CommandLine, ParentImage`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="privilege-escalation"`,
        `| sort -_time`,
      ].join('\n');
    }

    // Port Scanning
    if (techId.startsWith('T1046')) {
      return [
        `index=* sourcetype=network_traffic OR sourcetype=firewall`,
        `| bin _time span=1m`,
        `| stats dc(dest_port) as unique_ports, count as connections by _time, src_ip`,
        `| where unique_ports > 20 AND connections > 100`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="discovery"`,
        `| sort -unique_ports`,
      ].join('\n');
    }

    // WMI
    if (techId.startsWith('T1047')) {
      return [
        `index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1`,
        `| search ParentImage="*WmiPrvSE.exe"`,
        `| where NOT (User="NT AUTHORITY\\SYSTEM" OR User="NT AUTHORITY\\LOCAL SERVICE")`,
        `| stats count by _time, Computer, User, Image, CommandLine`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="execution"`,
        `| sort -_time`,
      ].join('\n');
    }

    // DLL Hijacking / Registry
    if (techId.startsWith('T1574') || techId.startsWith('T1112')) {
      return [
        `index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=13`,
        `| search TargetObject IN ("*SafeDllSearchMode*", "*AppCertDlls*", "*AppInit_DLLs*")`,
        `| stats count by _time, Computer, User, TargetObject, Details`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="defense-evasion"`,
        `| sort -_time`,
      ].join('\n');
    }

    // BITS Jobs
    if (techId.startsWith('T1197')) {
      return [
        `index=* sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*bitsadmin.exe"`,
        `| search CommandLine IN ("*/transfer*", "*/addfile*", "*/SetNotifyCmdLine*")`,
        `| stats count by _time, Computer, SubjectUserName, CommandLine`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="defense-evasion"`,
        `| sort -_time`,
      ].join('\n');
    }

    // Inhibit System Recovery (ransomware)
    if (techId.startsWith('T1490')) {
      return [
        `index=* sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*bcdedit.exe"`,
        `| search CommandLine IN ("*recoveryenabled*", "*bootstatuspolicy*")`,
        `| stats count by _time, Computer, SubjectUserName, CommandLine`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="impact"`,
        `| sort -_time`,
      ].join('\n');
    }

    // Valid Accounts / Brute Force
    if (techId.startsWith('T1078') || techId.startsWith('T1110')) {
      return [
        `index=* sourcetype=WinEventLog:Security EventCode=4625`,
        `| bin _time span=5m`,
        `| stats count as failures, dc(Computer) as targets by _time, Account_Name, src_ip`,
        `| where failures > 10`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="initial-access"`,
        `| sort -failures`,
      ].join('\n');
    }

    // Webshell
    if (techId.startsWith('T1505')) {
      return [
        `index=* sourcetype=WinEventLog:Security EventCode=4688`,
        `| search ParentProcessName IN ("*httpd*", "*nginx*", "*w3wp.exe*", "*tomcat*", "*apache*")`,
        `| search NewProcessName IN ("*cmd.exe*", "*powershell.exe*", "*wscript.exe*", "*cscript.exe*")`,
        `| stats count by _time, Computer, SubjectUserName, ParentProcessName, NewProcessName, CommandLine`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="persistence"`,
        `| sort -_time`,
      ].join('\n');
    }

    // Ingress Tool Transfer
    if (techId.startsWith('T1105')) {
      return [
        `index=* sourcetype=WinEventLog:Security EventCode=4688`,
        `| search NewProcessName IN ("*scp.exe*", "*sftp.exe*", "*robocopy.exe*", "*bitsadmin.exe*", "*certutil.exe*", "*curl.exe*", "*wget.exe*")`,
        `| stats count by _time, Computer, SubjectUserName, NewProcessName, CommandLine`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="command-and-control"`,
        `| sort -_time`,
      ].join('\n');
    }

    // Exploit Public-Facing Application
    if (techId.startsWith('T1190')) {
      return [
        `index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1`,
        `| search ParentImage IN ("*java*", "*javaw*", "*jboss*", "*tomcat*")`,
        `| search Image IN ("*cmd.exe*", "*powershell.exe*", "*bash*", "*sh*")`,
        `| stats count by _time, Computer, User, Image, ParentImage, CommandLine`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="initial-access"`,
        `| sort -_time`,
      ].join('\n');
    }

    // Defense Evasion (obfuscation, disabling defenses)
    if (techId.startsWith('T1562') || techId.startsWith('T1027')) {
      return [
        `index=* sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*powershell.exe"`,
        `| search CommandLine IN ("*Set-MpPreference*", "*Disable-WindowsOptionalFeature*", "*netsh advfirewall*", "*sc stop*", "*MpCmdRun*")`,
        `| stats count by _time, Computer, SubjectUserName, CommandLine`,
        `| eval technique="${techId}", analytic="${analytic.id}", tactic="defense-evasion"`,
        `| sort -_time`,
      ].join('\n');
    }

    // Default generic query
    return [
      `index=* sourcetype=WinEventLog:Security`,
      `| eval analytic="${analytic.id}", technique="${techId}"`,
      `| search ${analytic.pseudocode ? '| * Reference pseudocode: ' + analytic.pseudocode.replace(/\n/g, ' ') : ''}`,
      `| stats count by _time, Computer, SubjectUserName, EventCode`,
      `| sort -_time`,
    ].join('\n');
  }

  private getSentinelQuery(analytic: CarAnalytic): string {
    const techId = analytic.attackIds[0] ?? '';

    if (techId.startsWith('T1059.001') || analytic.name.toLowerCase().includes('powershell')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `SecurityEvent`,
        `| where TimeGenerated > ago(1d)`,
        `| where EventID in (4688, 4104)`,
        `| extend CmdLine = coalesce(CommandLine, tostring(EventData))`,
        `| where CmdLine matches regex @"(?i)(-enc|-nop|iex |Invoke-Expression|DownloadString|bypass)"`,
        `| project TimeGenerated, Computer, Account, CmdLine, ParentProcessName`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "Execution"`,
        `| order by TimeGenerated desc`,
      ].join('\n');
    }
    if (techId.startsWith('T1059')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `SecurityEvent`,
        `| where EventID == 4688`,
        `| where NewProcessName endswith "cmd.exe" or NewProcessName endswith "powershell.exe"`,
        `      or NewProcessName endswith "wscript.exe" or NewProcessName endswith "cscript.exe"`,
        `| where strlen(CommandLine) > 200 or CommandLine matches regex @"(?i)(-enc|iex |base64)"`,
        `| summarize Count=count() by Computer, Account, NewProcessName, bin(TimeGenerated, 5m)`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}"`,
      ].join('\n');
    }

    if (techId.startsWith('T1055')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `Event`,
        `| where Source == "Microsoft-Windows-Sysmon" and EventID == 8`,
        `| extend TargetImage = extract(@"TargetImage: ([^\\n]+)", 1, RenderedDescription)`,
        `| extend SourceImage = extract(@"SourceImage: ([^\\n]+)", 1, RenderedDescription)`,
        `| where TargetImage !contains "antivirus" and TargetImage !contains "defender"`,
        `| summarize Count=count() by Computer, SourceImage, TargetImage, bin(TimeGenerated, 1h)`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "DefenseEvasion"`,
      ].join('\n');
    }

    if (techId.startsWith('T1053')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `SecurityEvent`,
        `| where EventID in (4698, 4702, 4699)`,
        `| where AccountName != "SYSTEM"`,
        `| where TaskName !startswith @"\\Microsoft\\Windows\\"`,
        `| project TimeGenerated, Computer, AccountName, TaskName, EventData`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "Persistence"`,
        `| order by TimeGenerated desc`,
      ].join('\n');
    }

    if (techId.startsWith('T1021.001') || analytic.name.toLowerCase().includes('rdp')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `SecurityEvent`,
        `| where EventID == 4624 and LogonType == 10`,
        `| summarize Count=count() by Computer, AccountName, WorkstationName, IpAddress`,
        `| where Count > 3`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "LateralMovement"`,
        `| order by Count desc`,
      ].join('\n');
    }
    if (techId.startsWith('T1021')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `SecurityEvent`,
        `| where EventID in (4624, 4625) and LogonType in (3, 10)`,
        `| summarize Attempts=count(), Sources=dcount(IpAddress) by Computer, AccountName, bin(TimeGenerated, 5m)`,
        `| where Attempts > 5 or Sources > 3`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "LateralMovement"`,
      ].join('\n');
    }

    if (techId.startsWith('T1003')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `Event`,
        `| where Source == "Microsoft-Windows-Sysmon" and EventID == 10`,
        `| extend TargetImage = extract(@"TargetImage: ([^\\n]+)", 1, RenderedDescription)`,
        `| extend SourceImage = extract(@"SourceImage: ([^\\n]+)", 1, RenderedDescription)`,
        `| where TargetImage contains "lsass.exe"`,
        `| where SourceImage !contains "MsMpEng" and SourceImage !contains "csrss"`,
        `| project TimeGenerated, Computer, SourceImage, TargetImage`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "CredentialAccess"`,
      ].join('\n');
    }

    if (techId.startsWith('T1548')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `Event`,
        `| where Source == "Microsoft-Windows-Sysmon" and EventID == 1`,
        `| extend IntegrityLevel = extract(@"IntegrityLevel: ([^\\n]+)", 1, RenderedDescription)`,
        `| extend User = extract(@"User: ([^\\n]+)", 1, RenderedDescription)`,
        `| where IntegrityLevel == "High" and User !contains "Administrator" and User !contains "SYSTEM"`,
        `| summarize Count=count() by Computer, User, IntegrityLevel, bin(TimeGenerated, 1h)`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "PrivilegeEscalation"`,
      ].join('\n');
    }

    if (techId.startsWith('T1046')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `CommonSecurityLog`,
        `| where TimeGenerated > ago(1h)`,
        `| summarize UniqueDestPorts=dcount(DestinationPort), Connections=count() by SourceIP, bin(TimeGenerated, 1m)`,
        `| where UniqueDestPorts > 20 and Connections > 100`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "Discovery"`,
        `| order by UniqueDestPorts desc`,
      ].join('\n');
    }

    if (techId.startsWith('T1047')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `Event`,
        `| where Source == "Microsoft-Windows-Sysmon" and EventID == 1`,
        `| extend ParentImage = extract(@"ParentImage: ([^\\n]+)", 1, RenderedDescription)`,
        `| extend User = extract(@"User: ([^\\n]+)", 1, RenderedDescription)`,
        `| where ParentImage contains "WmiPrvSE.exe"`,
        `| where User !contains "SYSTEM" and User !contains "LOCAL SERVICE"`,
        `| project TimeGenerated, Computer, User, ParentImage`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "Execution"`,
      ].join('\n');
    }

    if (techId.startsWith('T1574') || techId.startsWith('T1112')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `Event`,
        `| where Source == "Microsoft-Windows-Sysmon" and EventID == 13`,
        `| extend TargetObject = extract(@"TargetObject: ([^\\n]+)", 1, RenderedDescription)`,
        `| where TargetObject contains "SafeDllSearchMode" or TargetObject contains "AppInit_DLLs"`,
        `         or TargetObject contains "AppCertDlls"`,
        `| project TimeGenerated, Computer, TargetObject`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "DefenseEvasion"`,
      ].join('\n');
    }

    if (techId.startsWith('T1197')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `SecurityEvent`,
        `| where EventID == 4688 and NewProcessName endswith "bitsadmin.exe"`,
        `| where CommandLine contains "/transfer" or CommandLine contains "/SetNotifyCmdLine"`,
        `| project TimeGenerated, Computer, Account, CommandLine`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "DefenseEvasion"`,
      ].join('\n');
    }

    if (techId.startsWith('T1490')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `SecurityEvent`,
        `| where EventID == 4688 and NewProcessName endswith "bcdedit.exe"`,
        `| where CommandLine contains "recoveryenabled" or CommandLine contains "bootstatuspolicy"`,
        `| project TimeGenerated, Computer, Account, CommandLine`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "Impact"`,
      ].join('\n');
    }

    if (techId.startsWith('T1078') || techId.startsWith('T1110')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `SecurityEvent`,
        `| where EventID == 4625`,
        `| summarize Failures=count() by AccountName, IpAddress, bin(TimeGenerated, 5m)`,
        `| where Failures > 10`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "InitialAccess"`,
        `| order by Failures desc`,
      ].join('\n');
    }

    if (techId.startsWith('T1505')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `SecurityEvent`,
        `| where EventID == 4688`,
        `| where ParentProcessName has_any ("httpd", "nginx", "w3wp", "tomcat", "apache")`,
        `| where NewProcessName has_any ("cmd.exe", "powershell.exe", "wscript.exe")`,
        `| project TimeGenerated, Computer, Account, ParentProcessName, NewProcessName, CommandLine`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "Persistence"`,
      ].join('\n');
    }

    if (techId.startsWith('T1105')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `SecurityEvent`,
        `| where EventID == 4688`,
        `| where NewProcessName has_any ("scp.exe", "sftp.exe", "certutil.exe", "curl.exe", "wget.exe", "bitsadmin.exe")`,
        `| project TimeGenerated, Computer, Account, NewProcessName, CommandLine`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "CommandAndControl"`,
      ].join('\n');
    }

    if (techId.startsWith('T1190')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `Event`,
        `| where Source == "Microsoft-Windows-Sysmon" and EventID == 1`,
        `| extend ParentImage = extract(@"ParentImage: ([^\\n]+)", 1, RenderedDescription)`,
        `| extend Image = extract(@"Image: ([^\\n]+)", 1, RenderedDescription)`,
        `| where ParentImage contains "java" or ParentImage contains "jboss"`,
        `| where Image has_any ("cmd.exe", "powershell.exe", "bash", "sh")`,
        `| project TimeGenerated, Computer, ParentImage, Image`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "InitialAccess"`,
      ].join('\n');
    }

    if (techId.startsWith('T1562') || techId.startsWith('T1027')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `SecurityEvent`,
        `| where EventID == 4688 and NewProcessName endswith "powershell.exe"`,
        `| where CommandLine contains "Set-MpPreference" or CommandLine contains "netsh advfirewall"`,
        `         or CommandLine contains "Disable-WindowsOptionalFeature"`,
        `| project TimeGenerated, Computer, Account, CommandLine`,
        `| extend TechniqueId = "${techId}", Analytic = "${analytic.id}", Tactic = "DefenseEvasion"`,
      ].join('\n');
    }

    // Default
    return [
      `// ${analytic.id} — ${analytic.name}`,
      `SecurityEvent`,
      `| where TimeGenerated > ago(1d)`,
      `| extend Analytic = "${analytic.id}", TechniqueId = "${techId}"`,
      `| summarize Count=count() by Computer, Account, EventID`,
      `| order by Count desc`,
    ].join('\n');
  }

  private getElasticQuery(analytic: CarAnalytic): string {
    const techId = analytic.attackIds[0] ?? '';

    if (techId.startsWith('T1059.001') || analytic.name.toLowerCase().includes('powershell')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `process where event.type == "start"`,
        `  and process.name : ("powershell.exe", "pwsh.exe")`,
        `  and (`,
        `    process.command_line : ("*-enc*", "*-nop*", "*iex *", "*Invoke-Expression*", "*DownloadString*")`,
        `    or length(process.command_line) > 500`,
        `  )`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} | Tactic: Execution */`,
      ].join('\n');
    }
    if (techId.startsWith('T1059')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `process where event.type == "start"`,
        `  and process.name : ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")`,
        `  and (`,
        `    process.command_line : ("*-enc*", "*base64*")`,
        `    or length(process.command_line) > 1000`,
        `  )`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} */`,
      ].join('\n');
    }

    if (techId.startsWith('T1055')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `sequence with maxspan=30s`,
        `  [process where event.type == "start" and process.name != null]`,
        `  [process where event.type == "start" and`,
        `   process.parent.name : ("explorer.exe", "svchost.exe") and`,
        `   process.name : ("cmd.exe", "powershell.exe", "rundll32.exe")]`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} | Tactic: DefenseEvasion */`,
      ].join('\n');
    }

    if (techId.startsWith('T1053')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `process where event.type == "start"`,
        `  and process.name : "schtasks.exe"`,
        `  and process.command_line : ("*/create*", "*/change*")`,
        `  and not process.parent.name : "svchost.exe"`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} | Tactic: Persistence */`,
      ].join('\n');
    }

    if (techId.startsWith('T1021')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `sequence with maxspan=1h`,
        `  [authentication where event.outcome == "failure"] with runs=5`,
        `  [authentication where event.outcome == "success"]`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} | Tactic: LateralMovement */`,
      ].join('\n');
    }

    if (techId.startsWith('T1003')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `process where event.type == "start"`,
        `  and process.pe.original_file_name : ("procdump.exe", "taskmgr.exe", "werfault.exe")`,
        `  and process.command_line : ("*lsass*", "*pid*")`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} | Tactic: CredentialAccess */`,
      ].join('\n');
    }

    if (techId.startsWith('T1548')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `process where event.type == "start"`,
        `  and process.token.integrity_level_name == "high"`,
        `  and not user.name : ("Administrator", "SYSTEM")`,
        `  and not process.executable : ("*installer*", "*setup*", "*msiexec*")`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} | Tactic: PrivilegeEscalation */`,
      ].join('\n');
    }

    if (techId.startsWith('T1046')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `network where event.type == "connection_attempted"`,
        `  and destination.port > 1024`,
        `  and not process.name : ("chrome.exe", "firefox.exe", "msedge.exe")`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} | Tactic: Discovery */`,
      ].join('\n');
    }

    if (techId.startsWith('T1047')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `process where event.type == "start"`,
        `  and process.parent.name : "WmiPrvSE.exe"`,
        `  and not user.name : ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} | Tactic: Execution */`,
      ].join('\n');
    }

    if (techId.startsWith('T1197')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `process where event.type == "start"`,
        `  and process.name : "bitsadmin.exe"`,
        `  and process.command_line : ("*/transfer*", "*/AddFile*", "*/SetNotifyCmdLine*")`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} | Tactic: DefenseEvasion */`,
      ].join('\n');
    }

    if (techId.startsWith('T1490')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `process where event.type == "start"`,
        `  and process.name : "bcdedit.exe"`,
        `  and process.command_line : ("*recoveryenabled*", "*bootstatuspolicy*")`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} | Tactic: Impact */`,
      ].join('\n');
    }

    if (techId.startsWith('T1078') || techId.startsWith('T1110')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `sequence by source.ip with maxspan=5m`,
        `  [authentication where event.outcome == "failure"] with runs=10`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} | Tactic: InitialAccess */`,
      ].join('\n');
    }

    if (techId.startsWith('T1505')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `process where event.type == "start"`,
        `  and process.parent.name : ("httpd", "nginx", "w3wp.exe", "tomcat", "apache")`,
        `  and process.name : ("cmd.exe", "powershell.exe", "bash", "sh")`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} | Tactic: Persistence */`,
      ].join('\n');
    }

    if (techId.startsWith('T1190')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `sequence with maxspan=1h`,
        `  [process where event.type == "start" and process.name : ("java", "javaw") ]`,
        `  [process where event.type == "start" and process.name : ("cmd.exe", "bash", "sh", "powershell.exe")]`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} | Tactic: InitialAccess */`,
      ].join('\n');
    }

    if (techId.startsWith('T1562') || techId.startsWith('T1027')) {
      return [
        `// ${analytic.id} — ${analytic.name}`,
        `process where event.type == "start"`,
        `  and process.name : "powershell.exe"`,
        `  and process.command_line : ("*Set-MpPreference*", "*netsh advfirewall*", "*Disable-WindowsOptionalFeature*")`,
        `/* TechniqueId: ${techId} | Analytic: ${analytic.id} | Tactic: DefenseEvasion */`,
      ].join('\n');
    }

    // Default EQL
    return [
      `// ${analytic.id} — ${analytic.name}`,
      `process where event.type == "start"`,
      `  and process.name != null`,
      `/* TechniqueId: ${techId} | Analytic: ${analytic.id} */`,
      `/* Pseudocode: ${analytic.pseudocode ?? 'N/A'} */`,
    ].join('\n');
  }

  copyToClipboard(): void {
    navigator.clipboard.writeText(this.generatedContent).then(() => {
      this.copied = true;
      this.cdr.markForCheck();
      setTimeout(() => {
        this.copied = false;
        this.cdr.markForCheck();
      }, 2000);
    });
  }

  downloadFile(): void {
    const ext = this.fileExtension;
    const mimeType = ext === 'kql' ? 'text/plain' : 'text/plain';
    const date = new Date().toISOString().slice(0, 10);
    const filename = `car-analytics-${this.activePlatform}-${date}.${ext}`;
    const blob = new Blob([this.generatedContent], { type: mimeType });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  onPlatformChange(platform: SiemPlatform): void {
    this.activePlatform = platform;
    this.generateExport();
  }

  onModeChange(): void {
    this.generateExport();
  }

  onFilterChange(): void {
    this.generateExport();
  }

  onEntryToggle(): void {
    this.generateExport();
  }

  get tacticOptions(): string[] {
    return this.tactics;
  }

  get techniqueOptions(): Technique[] {
    return this.techniques.filter(t => !t.isSubtechnique).slice(0, 300);
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }
}
