import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { of } from 'rxjs';

export interface CarAnalytic {
  id: string;           // e.g., "CAR-2014-04-003"
  name: string;
  description: string;
  url: string;
  platforms: string[];
  attackIds: string[];  // ATT&CK technique IDs
  pseudocode?: string;  // Detection pseudocode/logic
}

const CAR_ANALYTICS: CarAnalytic[] = [
  { id: 'CAR-2013-02-003', name: 'Processes Spawning cmd.exe', description: 'Detects command prompt spawned from unusual parent processes.', url: 'https://car.mitre.org/analytics/CAR-2013-02-003/', platforms: ['Windows'], attackIds: ['T1059.003'], pseudocode: 'process WHERE parent_exe NOT IN whitelist AND child_exe = "cmd.exe"' },
  { id: 'CAR-2013-05-002', name: 'Scheduled Task Creation', description: 'Detects creation of scheduled tasks, which can be used for persistence.', url: 'https://car.mitre.org/analytics/CAR-2013-05-002/', platforms: ['Windows'], attackIds: ['T1053.005'], pseudocode: 'process WHERE exe = "schtasks.exe" AND command_line CONTAINS "/create"' },
  { id: 'CAR-2013-09-005', name: 'Service Outlier Executables', description: 'Detects services running executables not previously seen in the environment.', url: 'https://car.mitre.org/analytics/CAR-2013-09-005/', platforms: ['Windows'], attackIds: ['T1543.003'] },
  { id: 'CAR-2013-10-001', name: 'User Login Activity', description: 'Monitors login patterns to detect suspicious authentication events.', url: 'https://car.mitre.org/analytics/CAR-2013-10-001/', platforms: ['Windows', 'Linux', 'macOS'], attackIds: ['T1078', 'T1110'], pseudocode: 'auth_event WHERE (failed_attempts > 5 OR unusual_time OR new_source)' },
  { id: 'CAR-2014-03-005', name: 'Remotely Launched Executables via Services', description: 'Detects remote service creation used for lateral movement.', url: 'https://car.mitre.org/analytics/CAR-2014-03-005/', platforms: ['Windows'], attackIds: ['T1021', 'T1543'], pseudocode: 'service_creation WHERE initiating_host != local_host' },
  { id: 'CAR-2014-04-003', name: 'PowerShell Execution', description: 'Detects PowerShell script execution, particularly encoded or suspicious commands.', url: 'https://car.mitre.org/analytics/CAR-2014-04-003/', platforms: ['Windows'], attackIds: ['T1059.001'], pseudocode: 'process WHERE exe = "powershell.exe" AND (command_line CONTAINS "-enc" OR command_line CONTAINS "-nop" OR command_line CONTAINS "iex")' },
  { id: 'CAR-2014-05-001', name: 'RDP Login from Localhost', description: 'Detects RDP logins originating from localhost, indicating local RDP tunneling.', url: 'https://car.mitre.org/analytics/CAR-2014-05-001/', platforms: ['Windows'], attackIds: ['T1021.001'], pseudocode: 'auth_event WHERE logon_type = "RemoteInteractive" AND source_ip = "127.0.0.1"' },
  { id: 'CAR-2014-11-002', name: 'Remote File Copy', description: 'Detects file copy activity involving remote systems.', url: 'https://car.mitre.org/analytics/CAR-2014-11-002/', platforms: ['Windows', 'Linux'], attackIds: ['T1105'], pseudocode: 'network_connection WHERE (exe IN ["scp","sftp","robocopy","xcopy"]) AND remote_host != null' },
  { id: 'CAR-2014-12-001', name: 'Remotely Launched Executables via WMI', description: 'Detects remote process execution through Windows Management Instrumentation.', url: 'https://car.mitre.org/analytics/CAR-2014-12-001/', platforms: ['Windows'], attackIds: ['T1047'], pseudocode: 'process WHERE parent_exe = "WmiPrvSE.exe" AND user != "SYSTEM"' },
  { id: 'CAR-2019-04-001', name: 'UAC Bypass', description: 'Detects User Account Control bypass techniques.', url: 'https://car.mitre.org/analytics/CAR-2019-04-001/', platforms: ['Windows'], attackIds: ['T1548.002'], pseudocode: 'process WHERE integrity_level = "high" AND NOT prompt_shown AND user NOT IN admins' },
  { id: 'CAR-2019-07-002', name: 'Lsass Access from Non-System Account', description: 'Detects attempts to access LSASS memory for credential dumping.', url: 'https://car.mitre.org/analytics/CAR-2019-07-002/', platforms: ['Windows'], attackIds: ['T1003.001'], pseudocode: 'process_access WHERE target_exe = "lsass.exe" AND source_user NOT IN ["SYSTEM","LOCAL SERVICE"]' },
  { id: 'CAR-2020-05-001', name: 'MiniDump of LSASS', description: 'Detects tools creating memory dumps of the LSASS process.', url: 'https://car.mitre.org/analytics/CAR-2020-05-001/', platforms: ['Windows'], attackIds: ['T1003.001'], pseudocode: 'file_create WHERE file_path CONTAINS "lsass" AND extension = ".dmp"' },
  { id: 'CAR-2020-09-001', name: 'Scheduled Task - File Access', description: 'Detects suspicious file access patterns associated with scheduled task abuse.', url: 'https://car.mitre.org/analytics/CAR-2020-09-001/', platforms: ['Windows'], attackIds: ['T1053.005'], pseudocode: 'file_access WHERE path = "%SystemRoot%\\System32\\Tasks\\" AND process_name NOT IN ["svchost.exe"]' },
  { id: 'CAR-2021-01-001', name: 'Port Scanning Activity', description: 'Identifies hosts conducting network port scans.', url: 'https://car.mitre.org/analytics/CAR-2021-01-001/', platforms: ['Windows', 'Linux', 'macOS'], attackIds: ['T1046'], pseudocode: 'network_connection WHERE connections_per_minute > 100 AND distinct_dest_ports > 20' },
  { id: 'CAR-2021-01-002', name: 'Unusually Long Command Line Strings', description: 'Detects excessively long command lines which may indicate obfuscation.', url: 'https://car.mitre.org/analytics/CAR-2021-01-002/', platforms: ['Windows'], attackIds: ['T1059', 'T1027'], pseudocode: 'process WHERE length(command_line) > 1000' },
  { id: 'CAR-2021-02-001', name: 'Webshell-Indicative Process Tree', description: 'Detects web server processes spawning command shells, indicating webshell activity.', url: 'https://car.mitre.org/analytics/CAR-2021-02-001/', platforms: ['Windows', 'Linux'], attackIds: ['T1505.003'], pseudocode: 'process WHERE parent_exe IN ["httpd","nginx","w3wp.exe","tomcat"] AND child_exe IN ["cmd.exe","bash","sh","powershell.exe"]' },
  { id: 'CAR-2021-05-001', name: 'BITSAdmin Download File', description: 'Detects use of BITSAdmin to download files, commonly used for C2 staging.', url: 'https://car.mitre.org/analytics/CAR-2021-05-001/', platforms: ['Windows'], attackIds: ['T1197'], pseudocode: 'process WHERE exe = "bitsadmin.exe" AND command_line CONTAINS "/transfer"' },
  { id: 'CAR-2021-05-003', name: 'BCDEdit Failure Recovery Modification', description: 'Detects modification of boot recovery settings used in ransomware attacks.', url: 'https://car.mitre.org/analytics/CAR-2021-05-003/', platforms: ['Windows'], attackIds: ['T1490'], pseudocode: 'process WHERE exe = "bcdedit.exe" AND command_line CONTAINS "recoveryenabled No"' },
  { id: 'CAR-2021-11-001', name: 'Registry Edit with Creation of SafeDllSearchMode', description: 'Detects DLL search order hijacking via registry modification.', url: 'https://car.mitre.org/analytics/CAR-2021-11-001/', platforms: ['Windows'], attackIds: ['T1574.001', 'T1112'], pseudocode: 'registry_modification WHERE key CONTAINS "SafeDllSearchMode" AND value = 0' },
  { id: 'CAR-2022-03-001', name: 'BITS Job Persistence', description: 'Detects BITS jobs configured for persistence or command execution.', url: 'https://car.mitre.org/analytics/CAR-2022-03-001/', platforms: ['Windows'], attackIds: ['T1197', 'T1547'], pseudocode: 'bits_job WHERE notify_cmd_line != null OR job_type = "UPLOAD" AND remote_url CONTAINS "cmd"' },
  { id: 'CAR-2022-06-001', name: 'Shell Spawned by Java Utility', description: 'Detects shell processes spawned by Java utilities, often associated with exploitation.', url: 'https://car.mitre.org/analytics/CAR-2022-06-001/', platforms: ['Windows', 'Linux'], attackIds: ['T1190', 'T1059'], pseudocode: 'process WHERE parent_exe CONTAINS "java" AND child_exe IN ["cmd.exe","bash","sh","powershell.exe"]' },
  { id: 'CAR-2023-01-001', name: 'Defense Evasion Activity via PowerShell', description: 'Detects PowerShell commands commonly used to bypass defenses.', url: 'https://car.mitre.org/analytics/CAR-2023-01-001/', platforms: ['Windows'], attackIds: ['T1562', 'T1059.001'], pseudocode: 'process WHERE exe = "powershell.exe" AND command_line MATCHES (Set-MpPreference|Disable-WindowsOptionalFeature|netsh advfirewall)' },
];

@Injectable({ providedIn: 'root' })
export class CARService {
  // Live navigator layer from MITRE CAR GitHub — 122 technique/subtechnique mappings
  private static readonly NAVIGATOR_URL =
    'https://raw.githubusercontent.com/mitre-attack/car/master/docs/car_attack/car_attack.json';

  private byAttackId = new Map<string, CarAnalytic[]>();
  // Live counts from GitHub navigator layer: techniqueId → count of CAR analytics
  private liveCountMap = new Map<string, number>();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  /** Total CAR analytics in the live dataset. */
  total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  /** Number of unique ATT&CK techniques covered by CAR. */
  covered$ = this.coveredSubject.asObservable();

  constructor(private http: HttpClient) {
    // Index hardcoded analytics synchronously (always available)
    for (const analytic of CAR_ANALYTICS) {
      for (const id of analytic.attackIds) {
        if (!this.byAttackId.has(id)) this.byAttackId.set(id, []);
        this.byAttackId.get(id)!.push(analytic);
      }
    }
    // Fetch live navigator layer for accurate coverage counts
    this.loadLive();
  }

  private loadLive(): void {
    this.http.get<any>(CARService.NAVIGATOR_URL).pipe(
      catchError(() => of(null)),
    ).subscribe(data => {
      if (data?.techniques) {
        this.parseLiveLayer(data.techniques);
      }
      this.loadedSubject.next(true);
    });
  }

  private parseLiveLayer(techniques: any[]): void {
    for (const t of techniques) {
      const id: string = t.techniqueID ?? '';
      if (!id) continue;
      this.liveCountMap.set(id, (this.liveCountMap.get(id) ?? 0) + 1);
    }
    const totalUnique = new Set(techniques.map(t => t.techniqueID).filter(Boolean)).size;
    this.totalSubject.next(techniques.length);
    this.coveredSubject.next(totalUnique);
  }

  getAnalytics(attackId: string): CarAnalytic[] {
    const direct = this.byAttackId.get(attackId) ?? [];
    const parentId = attackId.includes('.') ? attackId.split('.')[0] : null;
    const parent = parentId ? (this.byAttackId.get(parentId) ?? []) : [];
    return [...direct, ...parent.filter(p => !direct.some(d => d.id === p.id))];
  }

  /**
   * Returns the best available count for a technique — prefers live navigator layer
   * count (more comprehensive), falls back to hardcoded analytics count.
   */
  getLiveCount(attackId: string): number {
    const liveCount = this.liveCountMap.get(attackId) ?? 0;
    const hardcodedCount = this.getAnalytics(attackId).length;
    return Math.max(liveCount, hardcodedCount);
  }

  /** Whether the live layer has data for this technique (beyond hardcoded). */
  hasLiveCoverage(attackId: string): boolean {
    return this.liveCountMap.has(attackId);
  }

  getAll(): CarAnalytic[] { return CAR_ANALYTICS; }
}
