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
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { LibraryService, LibraryAsset } from '../../services/library.service';
import { ViewModeService } from '../../services/view-mode.service';

/**
 * Shows Library assets (tools / channels / X accounts) related to a given
 * ATT&CK technique. Drop this into the technique sidebar (or any panel that
 * has a selected technique) to surface the bidirectional Workbench ↔ Library
 * mapping the user requested.
 */
@Component({
  selector: 'app-library-cross-ref',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="lcr">
      <header class="lcr-head">
        <h4>From the Library</h4>
        @if (assets.length > 0) {
          <button class="lcr-open-library" (click)="openLibrary()" title="Open the Library Index">
            Open Library →
          </button>
        }
      </header>

      @if (assets.length === 0) {
        <p class="lcr-empty">
          No starred tools, channels, or accounts mapped to this technique yet.
          @if (attackId) { <span>({{ attackId }})</span> }
        </p>
      } @else {
        <p class="lcr-meta">
          {{ assets.length }} matching {{ assets.length === 1 ? 'asset' : 'assets' }}
          (curated by <a href="https://x.com/WolfenLabs" target="_blank" rel="noreferrer">&#64;WolfenLabs</a>)
        </p>
        <ul class="lcr-list">
          @for (a of assets; track a.id) {
            <li class="lcr-item" [attr.data-type]="a.type">
              <a [href]="a.url" target="_blank" rel="noopener noreferrer" class="lcr-link">
                <span class="lcr-type-badge" [attr.data-type]="a.type">{{ shortType(a.type) }}</span>
                <span class="lcr-title">{{ a.title }}</span>
              </a>
              @if (a.description) {
                <p class="lcr-desc">{{ a.description }}</p>
              }
            </li>
          }
        </ul>
      }
    </section>
  `,
  styles: [`
    .lcr {
      margin: 12px 0;
      padding: 10px 12px;
      background: rgba(78, 161, 255, 0.04);
      border: 1px solid rgba(78, 161, 255, 0.18);
      border-radius: 6px;
    }
    .lcr-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin: 0 0 8px;
    }
    .lcr-head h4 {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: var(--accent, #4ea1ff);
      margin: 0;
      font-weight: 700;
    }
    .lcr-open-library {
      background: transparent;
      border: 1px solid var(--border-subtle, #2a2f3d);
      color: var(--text-muted, #8b93a7);
      padding: 3px 9px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 11px;
    }
    .lcr-open-library:hover {
      color: var(--accent, #4ea1ff);
      border-color: var(--accent, #4ea1ff);
    }
    .lcr-meta {
      font-size: 11px;
      color: var(--text-muted, #8b93a7);
      margin: 0 0 8px;
    }
    .lcr-empty {
      font-size: 12px;
      color: var(--text-muted, #8b93a7);
      margin: 4px 0 0;
      font-style: italic;
    }
    .lcr-list {
      list-style: none;
      padding: 0;
      margin: 0;
      display: flex;
      flex-direction: column;
      gap: 5px;
      max-height: 260px;
      overflow-y: auto;
    }
    .lcr-item {
      padding: 5px 8px;
      border-radius: 4px;
    }
    .lcr-item:hover {
      background: rgba(255, 255, 255, 0.03);
    }
    .lcr-link {
      display: flex;
      align-items: center;
      gap: 7px;
      text-decoration: none;
      color: var(--text-main, #e6e8ee);
      font-size: 12.5px;
    }
    .lcr-link:hover .lcr-title {
      color: var(--accent, #4ea1ff);
    }
    .lcr-title {
      flex: 1;
      font-weight: 500;
      word-break: break-word;
    }
    .lcr-type-badge {
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      padding: 1px 5px;
      border-radius: 3px;
      flex-shrink: 0;
    }
    .lcr-type-badge[data-type="tool"]      { background: rgba(78,161,255,0.18); color: #4ea1ff; }
    .lcr-type-badge[data-type="channel"]   { background: rgba(239,68,68,0.18); color: #ef4444; }
    .lcr-type-badge[data-type="x-account"] { background: rgba(167,139,250,0.18); color: #a78bfa; }
    .lcr-desc {
      font-size: 11px;
      color: var(--text-muted, #8b93a7);
      margin: 2px 0 0 50px;
      line-height: 1.35;
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
  private viewMode = inject(ViewModeService);
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
    this.viewMode.set('library');
  }

  shortType(t: string): string {
    if (t === 'x-account') return '@X';
    if (t === 'channel') return 'YT';
    if (t === 'tool') return 'GH';
    return t.slice(0, 2).toUpperCase();
  }
}
