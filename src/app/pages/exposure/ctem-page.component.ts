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

        this.stages = [
          {
            n: 1, name: 'Scoping',
            question: 'What attack surface are we managing?',
            metrics: [
              { label: 'Active domain', value: domain?.name ?? '—' },
              { label: 'Techniques in scope', value: parents.length },
              { label: 'Platforms represented', value: platforms },
              { label: 'Assets inventoried', value: assets.length },
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
