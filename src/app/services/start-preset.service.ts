// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, inject } from '@angular/core';
import { FilterService } from './filter.service';
import { PanelNavService } from './panel-nav.service';
import { START_PRESETS, StartPreset, startPresetById } from '../models/start-presets';

/**
 * Applies a role-based start preset: pick the role's matrix lens, then open the
 * role's workspace. Both use the ordinary public paths a lens pick and a nav
 * click already use (FilterService.setHeatmapMode as an explicit choice,
 * PanelNavService.open), so a preset is exactly a shortcut for two actions the
 * user could take by hand — nothing is removed or hidden, and the user can
 * change either afterwards. Surfaced in the first-run onboarding and as
 * `start:<id>` command-palette actions.
 */
@Injectable({ providedIn: 'root' })
export class StartPresetService {
  private readonly filter = inject(FilterService);
  private readonly panelNav = inject(PanelNavService);

  readonly presets: readonly StartPreset[] = START_PRESETS;

  /** Apply the preset with this id. An unknown id is ignored. */
  apply(id: string): void {
    const preset = startPresetById(id);
    if (!preset) return;
    // A lens pick is an explicit choice (the View-menu default), so the chosen
    // lens travels into the URL like any other.
    this.filter.setHeatmapMode(preset.heat);
    this.panelNav.open(preset.panel);
  }
}
