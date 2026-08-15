// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

export interface ShortcutDef {
  /** Display keys, e.g. ['Ctrl', 'K']. */
  keys: string[];
  description: string;
  group: 'Global' | 'Quick navigation' | 'Matrix';
}

/**
 * Single source of truth for keyboard shortcuts. HotkeysService implements
 * the behavior; the keyboard-help overlay renders this list, so the two
 * can't drift apart.
 */
export const SHORTCUTS: readonly ShortcutDef[] = [
  // Global (modifier combos work even while typing in an input)
  { keys: ['Ctrl', 'K'], description: 'Open the command palette (search or jump anywhere)', group: 'Global' },
  { keys: ['Ctrl', 'Shift', 'F'], description: 'Toggle the command palette', group: 'Global' },
  { keys: ['Ctrl', 'F'], description: 'Focus the matrix technique search', group: 'Global' },
  { keys: ['Ctrl', 'E'], description: 'Expand all subtechniques', group: 'Global' },
  { keys: ['?'], description: 'Open / close this help panel', group: 'Global' },
  { keys: ['Esc'], description: 'Close palette or help; otherwise deselect technique', group: 'Global' },

  // Quick navigation (single keys, ignored while typing)
  { keys: ['m'], description: 'Go to the Matrix', group: 'Quick navigation' },
  { keys: ['d'], description: 'Toggle the Dashboard', group: 'Quick navigation' },
  { keys: ['t'], description: 'Toggle the coverage Timeline', group: 'Quick navigation' },
  { keys: ['w'], description: 'Toggle the Watchlist', group: 'Quick navigation' },
  { keys: ['r'], description: 'Toggle the Risk matrix', group: 'Quick navigation' },
  { keys: ['c'], description: 'Clear all filters', group: 'Quick navigation' },

  // Matrix-local (handled by the matrix grid while it has focus)
  { keys: ['Tab'], description: 'Move focus between technique cells', group: 'Matrix' },
  { keys: ['↑', '↓', '←', '→'], description: 'Move the focused cell within / across tactic columns', group: 'Matrix' },
  { keys: ['Enter', 'Space'], description: 'Open the focused technique in the sidebar', group: 'Matrix' },
  { keys: ['/'], description: 'Jump to the technique search box', group: 'Matrix' },
  { keys: ['Esc'], description: 'Clear the focused cell / exit multi-select', group: 'Matrix' },
] as const;
