import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { ChangelogService, AttackRelease } from '../../services/changelog.service';

@Component({
  selector: 'app-changelog-panel',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './changelog-panel.component.html',
  styleUrl: './changelog-panel.component.scss',
})
export class ChangelogPanelComponent implements OnInit, OnDestroy {
  visible = false;
  releases: AttackRelease[] = [];
  loaded = false;
  expandedRelease: string | null = null;

  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private changelogService: ChangelogService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'changelog';
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.changelogService.releases$.subscribe(releases => {
        this.releases = releases;
        this.cdr.markForCheck();
      }),
    );

    this.subs.add(
      this.changelogService.loaded$.subscribe(loaded => {
        this.loaded = loaded;
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  toggleRelease(tag: string): void {
    this.expandedRelease = this.expandedRelease === tag ? null : tag;
    this.cdr.markForCheck();
  }

  formatDate(isoDate: string): string {
    if (!isoDate) return '';
    try {
      return new Date(isoDate).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
      });
    } catch {
      return isoDate;
    }
  }

  truncatedBody(body: string): string {
    if (!body) return '';
    return body.length > 2000 ? body.slice(0, 2000) + '\n\n[truncated...]' : body;
  }
}
