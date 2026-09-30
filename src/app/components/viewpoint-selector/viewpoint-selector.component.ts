// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  Component,
  ElementRef,
  HostListener,
  OnDestroy,
  OnInit,
  QueryList,
  ViewChildren,
  inject,
} from '@angular/core';

import { Subscription } from 'rxjs';
import { IconComponent } from '../../shared/icons/icon.component';
import { Viewpoint, ViewpointId, ViewpointService } from '../../services/viewpoint.service';

/**
 * Compact role/viewpoint switcher for the top of the nav rail. Mirrors the
 * heatmap lens menu's open/close + keyboard behaviour so it feels native:
 * a trigger shows the current viewpoint (icon + short label); it opens a
 * `role="menu"` popover listing every viewpoint (icon + label + tagline), and
 * selecting one delegates to `ViewpointService.setViewpoint`.
 */
@Component({
  selector: 'app-viewpoint-selector',
  standalone: true,
  imports: [IconComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './viewpoint-selector.component.html',
  styleUrl: './viewpoint-selector.component.scss',
})
export class ViewpointSelectorComponent implements OnInit, OnDestroy {
  private readonly viewpointService = inject(ViewpointService);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly cdr = inject(ChangeDetectorRef);

  readonly viewpoints: Viewpoint[] = this.viewpointService.viewpoints;
  current: Viewpoint = this.viewpointService.current;
  open = false;

  @ViewChildren('optionBtn') private optionBtns?: QueryList<ElementRef<HTMLButtonElement>>;

  private sub?: Subscription;

  ngOnInit(): void {
    this.sub = this.viewpointService.viewpoint$.subscribe((vp) => {
      this.current = vp;
      this.cdr.markForCheck();
    });
  }

  ngOnDestroy(): void {
    this.sub?.unsubscribe();
  }

  toggle(): void {
    this.open = !this.open;
    this.cdr.markForCheck();
    if (this.open) this.focusActiveOption();
  }

  close(returnFocus = false): void {
    if (!this.open) return;
    this.open = false;
    this.cdr.markForCheck();
    if (returnFocus) this.focusTrigger();
  }

  select(id: ViewpointId): void {
    this.viewpointService.setViewpoint(id);
    this.close(true);
  }

  isActive(id: ViewpointId): boolean {
    return this.current.id === id;
  }

  /** Arrow / Home / End roving focus within the open menu. */
  onMenuKeydown(event: KeyboardEvent): void {
    const btns = this.optionBtns?.toArray() ?? [];
    if (!btns.length) return;
    const active = document.activeElement;
    let idx = btns.findIndex((b) => b.nativeElement === active);
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        idx = idx < 0 ? 0 : (idx + 1) % btns.length;
        btns[idx].nativeElement.focus();
        break;
      case 'ArrowUp':
        event.preventDefault();
        idx = idx < 0 ? btns.length - 1 : (idx - 1 + btns.length) % btns.length;
        btns[idx].nativeElement.focus();
        break;
      case 'Home':
        event.preventDefault();
        btns[0].nativeElement.focus();
        break;
      case 'End':
        event.preventDefault();
        btns[btns.length - 1].nativeElement.focus();
        break;
    }
  }

  @HostListener('document:keydown.escape')
  onEscape(): void {
    this.close(true);
  }

  @HostListener('document:click', ['$event'])
  onDocumentClick(event: MouseEvent): void {
    if (this.open && !this.host.nativeElement.contains(event.target as Node)) {
      this.close();
    }
  }

  private focusActiveOption(): void {
    // Menu renders on the next CD pass; focus the active option once it exists.
    setTimeout(() => {
      const btns = this.optionBtns?.toArray() ?? [];
      const activeIdx = Math.max(0, this.viewpoints.findIndex((v) => v.id === this.current.id));
      btns[activeIdx]?.nativeElement.focus();
    });
  }

  private focusTrigger(): void {
    this.host.nativeElement.querySelector<HTMLButtonElement>('.vp-trigger')?.focus();
  }
}
