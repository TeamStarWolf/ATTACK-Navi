// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, HostListener, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';

interface ShortcutGroup {
  title: string;
  shortcuts: Array<{ keys: string[]; description: string }>;
}

@Component({
  selector: 'app-keyboard-help',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './keyboard-help.component.html',
  styleUrl: './keyboard-help.component.scss',
})
export class KeyboardHelpComponent {
  visible = false;

  readonly groups: ShortcutGroup[] = [
    {
      title: 'Navigation',
      shortcuts: [
        { keys: ['?'], description: 'Open / close this help panel' },
        { keys: ['d'], description: 'Open dashboard' },
        { keys: ['t'], description: 'Open timeline' },
        { keys: ['w'], description: 'Open watchlist' },
        { keys: ['r'], description: 'Open risk matrix' },
        { keys: ['c'], description: 'Clear all filters' },
        { keys: ['/'], description: 'Focus technique search' },
        { keys: ['Ctrl', 'F'], description: 'Focus technique search (global)' },
        { keys: ['Ctrl', 'K'], description: 'Open search panel' },
        { keys: ['Ctrl', 'E'], description: 'Expand all subtechniques' },
        { keys: ['Esc'], description: 'Close active panel / close sidebar' },
        { keys: ['Tab'], description: 'Move focus between technique cells' },
        { keys: ['Enter', 'Space'], description: 'Open technique detail in sidebar' },
      ],
    },
    {
      title: 'Matrix Keyboard Navigation',
      shortcuts: [
        { keys: ['↑', '↓'], description: 'Move selection up / down within a tactic column' },
        { keys: ['←', '→'], description: 'Move selection left / right between tactic columns' },
        { keys: ['Enter'], description: 'Open sidebar for the focused technique' },
        { keys: ['Esc'], description: 'Clear focused cell and close sidebar' },
        { keys: ['/'], description: 'Jump to search box' },
      ],
    },
    {
      title: 'Matrix View',
      shortcuts: [
        { keys: ['🎨', 'Coverage'], description: 'Cycle heatmap: Coverage → Exposure → Status' },
        { keys: ['↕ Risk'], description: 'Sort by least-mitigated techniques first' },
        { keys: ['👁 Uncovered'], description: 'Dim techniques with zero mitigations' },
        { keys: ['⚠ Gaps'], description: 'Show all uncovered techniques list' },
      ],
    },
    {
      title: 'Filtering',
      shortcuts: [
        { keys: ['Technique search'], description: 'Type to highlight matching techniques' },
        { keys: ['Mitigation filter'], description: 'Multi-select: each pick adds to active filters' },
        { keys: ['Platform select'], description: 'Show only techniques for a specific platform' },
        { keys: ['Status filter'], description: 'Dim techniques by implementation status' },
        { keys: ['✕ Clear'], description: 'Reset all active filters' },
      ],
    },
    {
      title: 'Team Panels',
      shortcuts: [
        { keys: ['👥 Threats'], description: 'Overlay APT group technique usage on matrix' },
        { keys: ['📊 Priority'], description: 'Ranked mitigations + implementation status' },
        { keys: ['🔮 What-If'], description: 'Simulate coverage gain from new mitigations' },
        { keys: ['📋 Report'], description: 'Full coverage report with documentation' },
      ],
    },
    {
      title: 'Documentation',
      shortcuts: [
        { keys: ['Sidebar → 📝'], description: 'Add analyst notes to any technique' },
        { keys: ['Sidebar → Add documentation'], description: 'Document security controls, owner, due date, evidence URL per mitigation' },
        { keys: ['Sidebar → Status chips'], description: 'Set implementation status per mitigation' },
      ],
    },
    {
      title: 'Export & State',
      shortcuts: [
        { keys: ['⬇ CSV'], description: 'Export technique-mitigation coverage as CSV' },
        { keys: ['⬇ Tactics'], description: 'Export per-tactic coverage summary' },
        { keys: ['⬇ Plan'], description: 'Export implementation plan with all documentation' },
        { keys: ['⬇ State'], description: 'Export implementation status + docs as JSON' },
        { keys: ['⬆ Import'], description: 'Import previously exported state JSON' },
      ],
    },
  ];

  constructor(private cdr: ChangeDetectorRef) {}

  @HostListener('document:keydown', ['$event'])
  onKeydown(e: KeyboardEvent): void {
    const tag = (e.target as HTMLElement)?.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
    if (e.key === '?') {
      e.preventDefault();
      this.visible = !this.visible;
      this.cdr.markForCheck();
    }
    if (e.key === 'Escape' && this.visible) {
      this.visible = false;
      this.cdr.markForCheck();
    }
  }

  toggle(): void {
    this.visible = !this.visible;
    this.cdr.markForCheck();
  }

  close(): void {
    this.visible = false;
    this.cdr.markForCheck();
  }
}
