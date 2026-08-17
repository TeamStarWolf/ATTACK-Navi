// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Subscription, combineLatest } from 'rxjs';
import { DataService } from '../../services/data.service';
import { AssetInventoryService } from '../../services/asset-inventory.service';
import { CveService } from '../../services/cve.service';
import { Cve2CapecService } from '../../services/cve2capec.service';
import { ImplementationService } from '../../services/implementation.service';
import { ValidationService } from '../../services/validation.service';
import { TimelineService } from '../../services/timeline.service';

interface CtemStage {
  n: number;
  name: string;
  question: string;
  metrics: { label: string; value: string | number }[];
  links: { label: string; route: string[] }[];
  /** Ranked drill-down rows (e.g. top KEV-exposed techniques). */
  list?: { heading: string; rows: { primary: string; secondary: string; route: string[]; params?: Record<string, string> }[] };
  /** Status distribution chips (e.g. validation outcomes). */
  chips?: { label: string; count: number; cls: string }[];
}

/**
 * CTEM board: the app's REAL data organized along Gartner's five Continuous
 * Threat Exposure Management stages. The stage mapping itself is curated
 * editorial framing (labeled in the header); every number on the board comes
 * live from the same services that power the rest of the app — nothing here
 * is invented.
 */
@Component({
  selector: 'app-ctem-page',
  standalone: true,
  imports: [RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './ctem-page.component.html',
  styleUrl: './ctem-page.component.scss',
})
export class CtemPageComponent implements OnInit, OnDestroy {
  stages: CtemStage[] = [];
  private subs = new Subscription();

  constructor(
    private dataService: DataService,
    private assetService: AssetInventoryService,
    private cveService: CveService,
    private cve2capecService: Cve2CapecService,
    private implService: ImplementationService,
    private validationService: ValidationService,
    private timelineService: TimelineService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    // KEV loads lazily; without this the Discovery/Prioritization numbers sit
    // at 0 until the user happens to visit a KEV-loading page first.
    this.cveService.loadKev();
    this.subs.add(
      combineLatest([
        this.dataService.domain$,
        this.assetService.assets$,
        this.cveService.kevTechScores$,
        this.cve2capecService.covered$,
        this.validationService.runs$,
        this.timelineService.snapshots$,
      ]).subscribe(([domain, assets, kevTechScores, cveCovered, runs, snapshots]) => {
        const parents = (domain?.techniques ?? []).filter(t => !t.isSubtechnique);
        const platforms = new Set((domain?.techniques ?? []).flatMap(t => t.platforms)).size;
        const uncovered = parents.filter(t => t.mitigationCount === 0).length;
        const statusMap = this.implService.getStatusMap();
        const counts = { implemented: 0, 'in-progress': 0, planned: 0, 'not-started': 0 } as Record<string, number>;
        for (const s of statusMap.values()) counts[s] = (counts[s] ?? 0) + 1;
        const lastRun = runs.length ? new Date(Math.max(...runs.map(r => +new Date(r.runDate ?? 0)))) : null;
        const lastSnap = snapshots.length ? snapshots[snapshots.length - 1] : null;

        // Top techniques by CISA KEV exposure, resolved against the loaded domain.
        const byAttackId = new Map((domain?.techniques ?? []).map(t => [t.attackId, t]));
        const topKev = [...kevTechScores.entries()]
          .filter(([id]) => byAttackId.has(id))
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .map(([id, score]) => ({
            primary: `${id} ${byAttackId.get(id)!.name}`,
            secondary: `${score} KEV CVE${score === 1 ? '' : 's'}`,
            route: ['/matrix'],
            params: { tech: id },
          }));

        // Validation outcome distribution across recorded runs.
        const valCounts = new Map<string, number>();
        for (const r of runs) valCounts.set(r.status, (valCounts.get(r.status) ?? 0) + 1);
        const valChips = [
          { label: 'passed', cls: 'chip-pass' },
          { label: 'partial', cls: 'chip-warn' },
          { label: 'failed', cls: 'chip-fail' },
          { label: 'no-telemetry', cls: 'chip-mute' },
        ].filter(c => (valCounts.get(c.label) ?? 0) > 0)
          .map(c => ({ ...c, count: valCounts.get(c.label)! }));

        // Coverage trend: latest snapshot vs the one before it.
        const prevSnap = snapshots.length >= 2 ? snapshots[snapshots.length - 2] : null;
        const trend = lastSnap && prevSnap
          ? `${prevSnap.coveragePct}% → ${lastSnap.coveragePct}%`
          : lastSnap ? `${lastSnap.coveragePct}% (first snapshot)` : '—';

        // F3 domain: native-vs-shared split. The T-prefix rule is CTID's own
        // isAttack flag (verified 1:1 against their published matrix data).
        const isF3 = this.dataService.getCurrentAttackDomain() === 'f3';
        const f3Shared = isF3 ? (domain?.techniques ?? []).filter(t => t.attackId.startsWith('T')).length : 0;
        const f3Native = isF3 ? (domain?.techniques ?? []).length - f3Shared : 0;

        this.stages = [
          {
            n: 1, name: 'Scoping',
            question: 'What attack surface are we managing?',
            metrics: [
              { label: 'Active domain', value: domain?.name ?? '—' },
              { label: 'Techniques in scope', value: parents.length },
              { label: 'Platforms represented', value: platforms },
              { label: 'Assets inventoried', value: assets.length },
              ...(isF3 ? [{ label: 'Fraud-native · shared with ATT&CK', value: `${f3Native} · ${f3Shared}` }] : []),
            ],
            links: [
              { label: 'Asset inventory', route: ['/coverage', 'assets'] },
              { label: 'Matrix scope filters', route: ['/matrix'] },
            ],
          },
          {
            n: 2, name: 'Discovery',
            question: 'Which exposures actually exist?',
            metrics: [
              { label: 'Techniques with KEV exposure', value: kevTechScores.size },
              { label: 'Techniques with CVE kill chains', value: cveCovered },
              { label: 'Asset-specific exposures', value: this.assetService.getExposureDetails(assets).length },
            ],
            links: [
              { label: 'CVE explorer', route: ['/exposure', 'cve'] },
              { label: 'Kill chains', route: ['/exposure', 'kill-chain'] },
            ],
          },
          {
            n: 3, name: 'Prioritization',
            question: 'What matters most, right now?',
            metrics: [
              { label: 'Uncovered techniques (0 mitigations)', value: uncovered },
              { label: 'Mitigations not started', value: counts['not-started'] },
              { label: 'Mitigations in progress', value: counts['in-progress'] },
            ],
            list: topKev.length
              ? { heading: 'Top KEV-exposed techniques (CISA)', rows: topKev }
              : undefined,
            links: [
              { label: 'Priority ranking', route: ['/exposure', 'priority'] },
              { label: 'Gap analysis', route: ['/exposure', 'gap-analysis'] },
            ],
          },
          {
            n: 4, name: 'Validation',
            question: 'Do our defenses actually work?',
            metrics: [
              { label: 'Validation runs recorded', value: runs.length },
              { label: 'Last validation', value: lastRun ? lastRun.toLocaleDateString() : 'never' },
            ],
            chips: valChips.length ? valChips : undefined,
            links: [
              { label: 'Detection validation', route: ['/detect', 'validation'] },
              { label: 'Purple team planner', route: ['/detect', 'purple-team'] },
            ],
          },
          {
            n: 5, name: 'Mobilization',
            question: 'Is remediation actually moving?',
            metrics: [
              { label: 'Mitigations implemented', value: counts['implemented'] },
              { label: 'Planned next', value: counts['planned'] },
              { label: 'Coverage snapshots', value: snapshots.length },
              { label: 'Last snapshot', value: lastSnap ? lastSnap.label : 'none yet' },
              { label: 'Coverage trend', value: trend },
            ],
            links: [
              { label: 'Remediation roadmap', route: ['/library', 'roadmap'] },
              { label: 'Coverage timeline', route: ['/coverage', 'timeline'] },
            ],
          },
        ];
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }
}
