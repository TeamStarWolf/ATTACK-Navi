// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  Component,
  DestroyRef,
  OnInit,
  inject,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { DataService } from '../../services/data.service';
import { Domain } from '../../models/domain';
import { StatsBarComponent } from '../../components/stats-bar/stats-bar.component';
import { DataHealthComponent } from '../../components/data-health/data-health.component';

/**
 * Integration Health workspace: the at-a-glance coverage stats and the
 * data-source integration-health strip, relocated here from the matrix's
 * context bar so the matrix stays focused on the grid and its legend.
 */
@Component({
  selector: 'app-status-page',
  standalone: true,
  imports: [CommonModule, StatsBarComponent, DataHealthComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './status-page.component.html',
  styleUrl: './status-page.component.scss',
})
export class StatusPageComponent implements OnInit {
  private readonly destroyRef = inject(DestroyRef);
  private readonly dataService = inject(DataService);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly router = inject(Router);

  domain: Domain | null = null;
  loading = true;

  ngOnInit(): void {
    this.dataService.domain$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((d) => {
      this.domain = d;
      this.cdr.markForCheck();
    });
    this.dataService.loading$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((l) => {
      this.loading = l;
      this.cdr.markForCheck();
    });
  }

  /** Clicking a tactic in the stats bar takes the user to the matrix grid. */
  onTacticClick(_shortname: string): void {
    this.router.navigate(['/matrix'], { queryParamsHandling: 'preserve' });
  }
}
