// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { DataService } from './data.service';
import { AtomicService } from './atomic.service';
import { SigmaService } from './sigma.service';
import { ElasticService } from './elastic.service';
import { SplunkContentService } from './splunk-content.service';
import { Domain } from '../models/domain';
import { Technique } from '../models/technique';

export interface EmulationStep {
  order: number;
  phase: string;
  techniqueId: string;
  techniqueName: string;
  objective: string;
  atomicTestId: string | null;
  invokeCommand: string;
  expectedDetection: string;
  expectedLogSource: string;
  prerequisites: string[];
  successCriteria: string;
}

export interface EmulationPlan {
  id: string;
  name: string;
  actorName: string;
  actorId: string;
  description: string;
  steps: EmulationStep[];
  createdAt: string;
  totalSteps: number;
}

// Canonical MITRE ATT&CK kill chain phase order
const TACTIC_ORDER: string[] = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
];

const TACTIC_DISPLAY: Record<string, string> = {
  'reconnaissance': 'Reconnaissance',
  'resource-development': 'Resource Development',
  'initial-access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access',
  'discovery': 'Discovery',
  'lateral-movement': 'Lateral Movement',
  'collection': 'Collection',
  'command-and-control': 'Command and Control',
  'exfiltration': 'Exfiltration',
  'impact': 'Impact',
};

// Map tactic shortnames to objective templates
const OBJECTIVE_TEMPLATES: Record<string, string> = {
  'reconnaissance': 'Gather information about target via',
  'resource-development': 'Establish infrastructure or acquire tools for',
  'initial-access': 'Gain initial foothold via',
  'execution': 'Execute malicious code using',
  'persistence': 'Establish persistence via',
  'privilege-escalation': 'Escalate privileges using',
  'defense-evasion': 'Evade defenses via',
  'credential-access': 'Harvest credentials via',
  'discovery': 'Discover environment details using',
  'lateral-movement': 'Move laterally via',
  'collection': 'Collect target data using',
  'command-and-control': 'Establish C2 channel via',
  'exfiltration': 'Exfiltrate data via',
  'impact': 'Achieve impact objective using',
};

// Map tactic to success criteria templates
const SUCCESS_CRITERIA: Record<string, string> = {
  'reconnaissance': 'Target information gathered and validated',
  'resource-development': 'Infrastructure and tooling operational',
  'initial-access': 'Initial shell or access obtained on target',
  'execution': 'Payload executed successfully on target host',
  'persistence': 'Persistence mechanism survives reboot verification',
  'privilege-escalation': 'Elevated privileges confirmed (SYSTEM/root/admin)',
  'defense-evasion': 'Security tooling bypassed — no alerts generated',
  'credential-access': 'Valid credentials extracted and verified',
  'discovery': 'Network/system enumeration data collected',
  'lateral-movement': 'Access established on additional host(s)',
  'collection': 'Target data staged for exfiltration',
  'command-and-control': 'Stable C2 callback confirmed',
  'exfiltration': 'Data transfer to external destination confirmed',
  'impact': 'Target impact achieved (disruption/destruction/encryption)',
};

// Map data sources to log source names
const DATASOURCE_LOG_MAP: Record<string, string> = {
  'Process': 'Windows Security Event Log 4688 / Sysmon Event 1',
  'Process Creation': 'Sysmon Event 1 / Windows Security 4688',
  'Process Termination': 'Sysmon Event 5',
  'Network Traffic': 'Zeek/Suricata logs / Firewall logs',
  'Network Connection': 'Sysmon Event 3 / Firewall logs',
  'File': 'Sysmon Events 11,23 / Windows Security 4663',
  'File Creation': 'Sysmon Event 11',
  'File Modification': 'Sysmon Event 2',
  'File Deletion': 'Sysmon Event 23',
  'Windows Registry': 'Sysmon Events 12,13,14',
  'Registry Key Creation': 'Sysmon Event 12',
  'Registry Key Modification': 'Sysmon Event 13',
  'Command': 'PowerShell ScriptBlock Logging 4104',
  'Script': 'PowerShell ScriptBlock Logging 4104',
  'Module': 'Sysmon Event 7 (Image Load)',
  'Service': 'Windows System Event Log 7045',
  'Scheduled Job': 'Windows Security 4698 / Task Scheduler',
  'Authentication': 'Windows Security 4624/4625',
  'Logon Session': 'Windows Security 4624/4634',
  'DNS': 'Sysmon Event 22 / DNS Server logs',
  'Firewall': 'Windows Firewall / Perimeter firewall logs',
  'WMI': 'Sysmon Events 19,20,21 / WMI Trace',
  'Driver': 'Sysmon Event 6 (Driver Load)',
  'Web': 'Web proxy / IIS / Apache access logs',
  'Email': 'Exchange / O365 Message Trace',
  'Cloud': 'CloudTrail / Azure Activity / GCP Audit',
  'Container': 'Docker daemon / Kubernetes audit logs',
};

const STORAGE_KEY = 'mitre-nav-emulation-plans';

@Injectable({ providedIn: 'root' })
export class EmulationPlanService {
  constructor(
    private dataService: DataService,
    private atomicService: AtomicService,
    private sigmaService: SigmaService,
    private elasticService: ElasticService,
    private splunkService: SplunkContentService,
  ) {}

  /**
   * Build an ordered emulation plan for a threat actor.
   * Steps are ordered by kill chain phase (reconnaissance -> impact).
   */
  generatePlan(actorId: string, domain: Domain): EmulationPlan {
    const group = domain.groups.find(g => g.id === actorId);
    if (!group) {
      return {
        id: this.generateId(),
        name: 'Unknown Actor Plan',
        actorName: 'Unknown',
        actorId,
        description: 'Actor not found in current domain data.',
        steps: [],
        createdAt: new Date().toISOString(),
        totalSteps: 0,
      };
    }

    // 1. Get all techniques used by this actor
    const techniques = domain.techniquesByGroup?.get(actorId) ?? [];

    // 2. Sort by kill chain phase order
    const sortedTechniques = this.sortByKillChain(techniques);

    // 3. Generate steps
    const steps: EmulationStep[] = [];
    const previousPhases: string[] = [];

    for (let i = 0; i < sortedTechniques.length; i++) {
      const tech = sortedTechniques[i];
      const tactic = this.getPrimaryTactic(tech);
      const phase = TACTIC_DISPLAY[tactic] || tactic;

      // Track phase transitions for prerequisites
      if (!previousPhases.includes(phase)) {
        previousPhases.push(phase);
      }

      const step = this.buildStep(i + 1, tech, tactic, phase, previousPhases, domain);
      steps.push(step);
    }

    return {
      id: this.generateId(),
      name: `${group.name} Emulation Plan`,
      actorName: group.name,
      actorId: group.attackId,
      description: `Adversary emulation plan simulating ${group.name} (${group.attackId}) TTPs across ${steps.length} steps. ` +
        `This plan covers ${new Set(steps.map(s => s.phase)).size} kill chain phases.`,
      steps,
      createdAt: new Date().toISOString(),
      totalSteps: steps.length,
    };
  }

  /** Generate a Markdown document from an emulation plan. */
  exportMarkdown(plan: EmulationPlan): string {
    const lines: string[] = [];
    lines.push(`# Adversary Emulation Plan: ${plan.actorName}`);
    lines.push('');
    lines.push(`**Actor:** ${plan.actorName} (${plan.actorId})`);
    lines.push(`**Created:** ${new Date(plan.createdAt).toLocaleDateString()}`);
    lines.push(`**Total Steps:** ${plan.totalSteps}`);
    lines.push('');
    lines.push(`## Description`);
    lines.push('');
    lines.push(plan.description);
    lines.push('');
    lines.push('---');
    lines.push('');

    let currentPhase = '';
    for (const step of plan.steps) {
      if (step.phase !== currentPhase) {
        currentPhase = step.phase;
        lines.push(`## Phase: ${currentPhase}`);
        lines.push('');
      }

      lines.push(`### Step ${step.order}: ${step.techniqueName} (${step.techniqueId})`);
      lines.push('');
      lines.push(`**Objective:** ${step.objective}`);
      lines.push('');

      if (step.prerequisites.length > 0) {
        lines.push('**Prerequisites:**');
        for (const pre of step.prerequisites) {
          lines.push(`- ${pre}`);
        }
        lines.push('');
      }

      lines.push('**Invoke Command:**');
      lines.push('```powershell');
      lines.push(step.invokeCommand);
      lines.push('```');
      lines.push('');

      lines.push(`**Expected Detection:** ${step.expectedDetection}`);
      lines.push('');
      lines.push(`**Log Source:** ${step.expectedLogSource}`);
      lines.push('');
      lines.push(`**Success Criteria:** ${step.successCriteria}`);
      lines.push('');
      lines.push('---');
      lines.push('');
    }

    return lines.join('\n');
  }

  /**
   * Export a MITRE Caldera adversary profile as a downloadable YAML file.
   * Groups steps by tactic phase number (initial-access=1, execution=2, etc.).
   */
  exportCalderaProfile(plan: EmulationPlan): void {
    const phaseMap: Record<string, number> = {
      'reconnaissance': 1,
      'resource-development': 1,
      'initial-access': 1,
      'execution': 2,
      'persistence': 3,
      'privilege-escalation': 4,
      'defense-evasion': 5,
      'credential-access': 6,
      'discovery': 7,
      'lateral-movement': 8,
      'collection': 9,
      'command-and-control': 10,
      'exfiltration': 11,
      'impact': 12,
    };

    // Group steps by phase number
    const phases = new Map<number, EmulationStep[]>();
    for (const step of plan.steps) {
      // Derive tactic shortname from phase display name
      const tacticKey = Object.entries(TACTIC_DISPLAY).find(
        ([, display]) => display === step.phase,
      )?.[0] ?? 'execution';
      const phaseNum = phaseMap[tacticKey] ?? 2;
      if (!phases.has(phaseNum)) phases.set(phaseNum, []);
      phases.get(phaseNum)!.push(step);
    }

    // Build YAML
    const lines: string[] = [];
    lines.push('---');
    lines.push(`name: "${plan.actorName} Emulation - ATTACK-Navi"`);
    lines.push(`description: "Auto-generated adversary profile from ATTACK-Navi emulation plan"`);
    lines.push('phases:');

    const sortedPhases = [...phases.keys()].sort((a, b) => a - b);
    for (const phaseNum of sortedPhases) {
      lines.push(`  ${phaseNum}:`);
      for (const step of phases.get(phaseNum)!) {
        lines.push(`    - technique:`);
        lines.push(`        attack_id: "${step.techniqueId}"`);
        lines.push(`        name: "${step.techniqueName}"`);
      }
    }

    const yaml = lines.join('\n') + '\n';
    const filename = `caldera-${plan.actorId || 'profile'}-${new Date().toISOString().split('T')[0]}.yml`;
    const blob = new Blob([yaml], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: filename });
    a.click();
    URL.revokeObjectURL(url);
  }

  /** Save a plan to localStorage. */
  savePlan(plan: EmulationPlan): void {
    const plans = this.getSavedPlans();
    const idx = plans.findIndex(p => p.id === plan.id);
    if (idx >= 0) {
      plans[idx] = plan;
    } else {
      plans.push(plan);
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(plans));
  }

  /** Get all saved plans from localStorage. */
  getSavedPlans(): EmulationPlan[] {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch {
      return [];
    }
  }

  /** Delete a saved plan by id. */
  deletePlan(id: string): void {
    const plans = this.getSavedPlans().filter(p => p.id !== id);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(plans));
  }

  // ── Private helpers ─────────────────────────────────────────────────────

  private sortByKillChain(techniques: Technique[]): Technique[] {
    return [...techniques].sort((a, b) => {
      const tacticA = this.getPrimaryTactic(a);
      const tacticB = this.getPrimaryTactic(b);
      const orderA = TACTIC_ORDER.indexOf(tacticA);
      const orderB = TACTIC_ORDER.indexOf(tacticB);
      const idxA = orderA >= 0 ? orderA : 999;
      const idxB = orderB >= 0 ? orderB : 999;
      if (idxA !== idxB) return idxA - idxB;
      return a.attackId.localeCompare(b.attackId);
    });
  }

  private getPrimaryTactic(tech: Technique): string {
    if (!tech.tacticShortnames || tech.tacticShortnames.length === 0) return 'unknown';
    // Return the earliest tactic in kill chain order
    let earliest = tech.tacticShortnames[0];
    let earliestIdx = TACTIC_ORDER.indexOf(earliest);
    if (earliestIdx < 0) earliestIdx = 999;

    for (const tactic of tech.tacticShortnames) {
      const idx = TACTIC_ORDER.indexOf(tactic);
      if (idx >= 0 && idx < earliestIdx) {
        earliest = tactic;
        earliestIdx = idx;
      }
    }
    return earliest;
  }

  private buildStep(
    order: number,
    tech: Technique,
    tactic: string,
    phase: string,
    previousPhases: string[],
    domain: Domain,
  ): EmulationStep {
    const objective = this.generateObjective(tech, tactic);
    const invokeCommand = this.atomicService.generateInvokeCommand(tech.attackId);
    const expectedDetection = this.getExpectedDetection(tech);
    const expectedLogSource = this.getExpectedLogSource(tech);
    const prerequisites = this.inferPrerequisites(tech, tactic, previousPhases, order);
    const successCriteria = SUCCESS_CRITERIA[tactic] || 'Technique execution verified';

    // Find an atomic test ID if available
    const tests = this.atomicService.getTests(tech.attackId);
    const atomicTestId = tests.length > 0 ? tests[0].url : null;

    return {
      order,
      phase,
      techniqueId: tech.attackId,
      techniqueName: tech.name,
      objective,
      atomicTestId,
      invokeCommand,
      expectedDetection,
      expectedLogSource,
      prerequisites,
      successCriteria,
    };
  }

  private generateObjective(tech: Technique, tactic: string): string {
    const template = OBJECTIVE_TEMPLATES[tactic] || 'Execute';
    return `${template} ${tech.name} (${tech.attackId})`;
  }

  private getExpectedDetection(tech: Technique): string {
    const parts: string[] = [];

    const sigmaCount = this.sigmaService.getRuleCount(tech.attackId);
    if (sigmaCount > 0) {
      parts.push(`Sigma: ${sigmaCount} rule${sigmaCount !== 1 ? 's' : ''} for ${tech.attackId}`);
    }

    const elasticCount = this.elasticService.getRuleCount(tech.attackId);
    if (elasticCount > 0) {
      parts.push(`Elastic: ${elasticCount} detection rule${elasticCount !== 1 ? 's' : ''}`);
    }

    const splunkCount = this.splunkService.getRuleCount(tech.attackId);
    if (splunkCount > 0) {
      parts.push(`Splunk: ${splunkCount} detection${splunkCount !== 1 ? 's' : ''}`);
    }

    if (parts.length === 0) {
      return 'No pre-built detection rules found — custom detection required';
    }
    return parts.join(' | ');
  }

  private getExpectedLogSource(tech: Technique): string {
    if (!tech.dataSources || tech.dataSources.length === 0) {
      return 'Not specified — manual log source identification required';
    }

    const logSources = new Set<string>();
    for (const ds of tech.dataSources) {
      // Data sources can be "Category: Component" format
      const parts = ds.split(':').map(s => s.trim());
      for (const part of parts) {
        const mapped = DATASOURCE_LOG_MAP[part];
        if (mapped) {
          logSources.add(mapped);
        }
      }
    }

    if (logSources.size === 0) {
      // Fall back to raw data source names
      return tech.dataSources.slice(0, 3).join(', ');
    }
    return [...logSources].slice(0, 3).join(' | ');
  }

  private inferPrerequisites(
    tech: Technique,
    tactic: string,
    previousPhases: string[],
    order: number,
  ): string[] {
    const prereqs: string[] = [];

    if (order === 1) {
      prereqs.push('Target scope and rules of engagement defined');
      prereqs.push('Testing infrastructure prepared');
      return prereqs;
    }

    // Phase-based prerequisites
    const tacticIdx = TACTIC_ORDER.indexOf(tactic);
    if (tacticIdx > 0) {
      const prevPhase = TACTIC_DISPLAY[TACTIC_ORDER[tacticIdx - 1]];
      if (prevPhase && previousPhases.includes(prevPhase)) {
        prereqs.push(`${prevPhase} phase completed`);
      }
    }

    // Technique-specific prerequisites
    if (tactic === 'execution' || tactic === 'persistence') {
      prereqs.push('Initial access obtained');
    }
    if (tactic === 'lateral-movement') {
      prereqs.push('Valid credentials harvested');
      prereqs.push('Target hosts identified via discovery');
    }
    if (tactic === 'exfiltration') {
      prereqs.push('Target data collected and staged');
      prereqs.push('C2 channel established');
    }
    if (tactic === 'privilege-escalation') {
      prereqs.push('Initial code execution achieved');
    }
    if (tactic === 'credential-access') {
      prereqs.push('Code execution on target host');
    }

    if (tech.systemRequirements && tech.systemRequirements.length > 0) {
      prereqs.push(...tech.systemRequirements.slice(0, 2));
    }
    if (tech.permissionsRequired && tech.permissionsRequired.length > 0) {
      prereqs.push(`${tech.permissionsRequired.join('/')} permissions required`);
    }

    return prereqs.length > 0 ? prereqs : ['Previous step completed successfully'];
  }

  private generateId(): string {
    return 'ep-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
  }
}
