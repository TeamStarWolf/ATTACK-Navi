// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, Component, ElementRef, Input, OnDestroy, inject, signal } from '@angular/core';
import { DrawerWidthService } from '../../services/drawer-width.service';

/**
 * Vertical resize handle on the technique drawer's inner (left) edge. The host
 * element is the separator: focusable, with its value in px. Pointer drag
 * changes the width live (pointer capture, no text selection while dragging)
 * and persists it on release; double-click resets to the default; the keyboard
 * map lives in drawerWidthForKey. Hidden at 768 px and below, where the drawer
 * takes the full width.
 */
@Component({
  selector: 'app-drawer-resize-handle',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: '',
  styleUrl: './drawer-resize-handle.component.scss',
  host: {
    role: 'separator',
    tabindex: '0',
    'aria-orientation': 'vertical',
    'aria-label': 'Resize technique panel',
    title: 'Drag to resize, double-click to reset',
    '[attr.aria-controls]': 'controls || null',
    '[attr.aria-valuenow]': 'drawer.width()',
    '[attr.aria-valuemin]': 'drawer.min',
    '[attr.aria-valuemax]': 'drawer.max()',
    '[attr.aria-valuetext]': 'drawer.width() + " px"',
    '[class.dragging]': 'dragging()',
    '(pointerdown)': 'onPointerDown($event)',
    '(pointermove)': 'onPointerMove($event)',
    '(pointerup)': 'onPointerUp($event)',
    '(pointercancel)': 'onPointerUp($event)',
    '(lostpointercapture)': 'endDrag()',
    '(dblclick)': 'onDoubleClick($event)',
    '(keydown)': 'onKeydown($event)',
  },
})
export class DrawerResizeHandleComponent implements OnDestroy {
  protected readonly drawer = inject(DrawerWidthService);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);

  /** Id of the panel this handle resizes (aria-controls). */
  @Input() controls = '';

  readonly dragging = signal(false);

  private pointerId: number | null = null;
  private startX = 0;
  private startWidth = 0;
  private savedUserSelect = '';
  private savedCursor = '';

  onPointerDown(event: PointerEvent): void {
    if (event.button !== 0) return;
    // No text selection and no native drag while resizing.
    event.preventDefault();
    const el = this.host.nativeElement;
    el.focus({ preventScroll: true });
    try {
      el.setPointerCapture(event.pointerId);
    } catch {
      /* synthetic events have no active pointer; the drag still tracks moves on the handle */
    }
    this.pointerId = event.pointerId;
    this.startX = event.clientX;
    this.startWidth = this.drawer.width();
    this.dragging.set(true);
    this.lockPage(true);
  }

  onPointerMove(event: PointerEvent): void {
    if (this.pointerId === null || event.pointerId !== this.pointerId) return;
    // The handle is on the drawer's LEFT edge: moving the pointer left widens it.
    this.drawer.preview(this.startWidth + (this.startX - event.clientX));
  }

  onPointerUp(event: PointerEvent): void {
    if (this.pointerId === null || event.pointerId !== this.pointerId) return;
    const el = this.host.nativeElement;
    try {
      if (el.hasPointerCapture(event.pointerId)) el.releasePointerCapture(event.pointerId);
    } catch {
      /* capture already gone */
    }
    this.endDrag();
  }

  /** Finish a drag (pointer up, cancel or lost capture): persist the width once. */
  endDrag(): void {
    if (this.pointerId === null) return;
    this.pointerId = null;
    this.dragging.set(false);
    this.lockPage(false);
    this.drawer.commit();
  }

  onDoubleClick(event: MouseEvent): void {
    event.preventDefault();
    this.drawer.reset();
  }

  /**
   * A key the separator uses stays inside it: no default action and no bubbling
   * to document-level shortcuts (the matrix moves its focused cell on the arrow
   * keys). Keys it does not use, Escape included, bubble on as usual.
   */
  onKeydown(event: KeyboardEvent): void {
    if (event.altKey || event.ctrlKey || event.metaKey) return;
    if (!this.drawer.handleKey(event.key, event.shiftKey)) return;
    event.preventDefault();
    event.stopPropagation();
  }

  ngOnDestroy(): void {
    if (this.pointerId !== null) {
      this.pointerId = null;
      this.lockPage(false);
      this.drawer.commit();
    }
  }

  /** While dragging, the whole page shows the resize cursor and selects no text. */
  private lockPage(lock: boolean): void {
    const style = document.body.style;
    if (lock) {
      this.savedUserSelect = style.userSelect;
      this.savedCursor = style.cursor;
      style.userSelect = 'none';
      style.cursor = 'col-resize';
    } else {
      style.userSelect = this.savedUserSelect;
      style.cursor = this.savedCursor;
    }
  }
}
