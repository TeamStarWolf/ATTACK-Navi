// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  Input,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  inject,
  OnChanges,
  OnInit,
  OnDestroy,
  SimpleChanges,
} from '@angular/core';

import { Subscription } from 'rxjs';
import { LibraryService, LibraryAsset } from '../../services/library.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { DrawerRowComponent, DrawerSectionComponent, type DrawerBadgeTone } from '../drawer-primitives';

/**
 * Shows Library assets (tools / channels / X accounts) related to a given
 * ATT&CK technique. Drop this into the technique sidebar (or any panel that
 * has a selected technique) to surface the bidirectional Workbench ↔ Library
 * mapping the user requested.
 */
@Component({
  selector: 'app-library-cross-ref',
  standalone: true,
  imports: [DrawerSectionComponent, DrawerRowComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <app-drawer-section class="lcr" heading="From the Library" [collapsible]="false">
      @if (assets.length > 0) {
        <button sbTrailing class="sb-action lcr-open-library" (click)="openLibrary()" title="Open the Library Index">
          Open Library →
        </button>
      }

      @if (assets.length === 0) {
        <p class="sb-empty lcr-empty">
          No starred tools, channels, or accounts mapped to this technique yet.
          @if (attackId) { <span>({{ attackId }})</span> }
        </p>
      } @else {
        <p class="sb-text lcr-meta">
          {{ assets.length }} matching {{ assets.length === 1 ? 'asset' : 'assets' }}
          (curated by <a class="sb-link" href="https://x.com/WolfenLabs" target="_blank" rel="noreferrer">&#64;WolfenLabs</a>)
        </p>
        <div class="sb-list sb-list--scroll lcr-list">
          @for (a of assets; track a.id) {
            <app-drawer-row kind="detail" class="lcr-item" [attr.data-type]="a.type"
                            [name]="a.title" nameClass="lcr-link lcr-title" [nameHref]="a.url" rel="noopener noreferrer"
                            [description]="a.description">
              <span sbBadge class="sb-badge lcr-type-badge" [attr.data-type]="a.type" [attr.data-tone]="typeTone(a.type)">{{ shortType(a.type) }}</span>
            </app-drawer-row>
          }
        </div>
      }
    </app-drawer-section>
  `,
  styles: [`
    :host { display: block; }
    /* The card, header, rows and badges come from the drawer primitives; only the
       two-line clamp of an asset's description is this list's own. */
    .lcr-item .sb-desc {
      display: -webkit-box;
      -webkit-line-clamp: 2;
      line-clamp: 2;
      -webkit-box-orient: vertical;
      overflow: hidden;
    }
  `],
})
export class LibraryCrossRefComponent implements OnInit, OnChanges, OnDestroy {
  @Input() attackId = '';
  @Input() techniqueName = '';
  @Input() tacticSlugs: string[] = [];

  private library = inject(LibraryService);
  private panelNav = inject(PanelNavService);
  private cdr = inject(ChangeDetectorRef);
  private sub?: Subscription;

  assets: LibraryAsset[] = [];

  ngOnInit(): void {
    // React when the library data finishes loading (race-safe).
    this.sub = this.library.library$.subscribe(() => {
      this.recompute();
      this.cdr.markForCheck();
    });
  }

  ngOnChanges(_changes: SimpleChanges): void {
    this.recompute();
  }

  ngOnDestroy(): void {
    this.sub?.unsubscribe();
  }

  private recompute(): void {
    if (!this.attackId && !this.techniqueName) {
      this.assets = [];
      return;
    }
    this.assets = this.library.getAssetsForTechnique(
      this.attackId,
      this.techniqueName,
      this.tacticSlugs,
    );
  }

  openLibrary(): void {
    this.panelNav.open('library');
  }

  typeTone(t: string): DrawerBadgeTone {
    if (t === 'channel') return 'danger';
    if (t === 'x-account') return 'purple';
    return 'accent';
  }

  shortType(t: string): string {
    if (t === 'x-account') return '@X';
    if (t === 'channel') return 'YT';
    if (t === 'tool') return 'GH';
    return t.slice(0, 2).toUpperCase();
  }
}
