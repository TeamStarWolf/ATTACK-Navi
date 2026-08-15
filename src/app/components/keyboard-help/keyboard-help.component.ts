// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, ChangeDetectionStrategy, ChangeDetectorRef, OnInit, OnDestroy, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { HelpOverlayService } from '../../services/help-overlay.service';
import { SHORTCUTS, ShortcutDef } from '../../models/shortcuts';

interface ShortcutGroup {
  title: string;
  shortcuts: ShortcutDef[];
}

/**
 * Keyboard shortcuts overlay. Renders from models/shortcuts.ts — the same
 * list HotkeysService implements — so the help can't drift from behavior.
 * Open/close state lives in HelpOverlayService ('?' key, nav-rail Help
 * button, and the palette's "Keyboard shortcuts" command all route there).
 */
@Component({
  selector: 'app-keyboard-help',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './keyboard-help.component.html',
  styleUrl: './keyboard-help.component.scss',
})
export class KeyboardHelpComponent implements OnInit, OnDestroy {
  visible = false;

  readonly groups: ShortcutGroup[] = ['Global', 'Quick navigation', 'Matrix'].map(title => ({
    title,
    shortcuts: SHORTCUTS.filter(s => s.group === title),
  }));

  private helpOverlay = inject(HelpOverlayService);
  private cdr = inject(ChangeDetectorRef);
  private sub?: Subscription;

  ngOnInit(): void {
    this.sub = this.helpOverlay.open$.subscribe(open => {
      this.visible = open;
      this.cdr.markForCheck();
    });
  }

  ngOnDestroy(): void {
    this.sub?.unsubscribe();
  }

  toggle(): void {
    this.helpOverlay.toggle();
  }

  close(): void {
    this.helpOverlay.close();
  }
}
