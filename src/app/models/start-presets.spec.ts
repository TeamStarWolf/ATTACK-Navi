// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { START_PRESETS, startPresetById } from './start-presets';
import { PANEL_ROUTE_MAP } from '../app.routes-map';
import { isHeatmapMode } from '../services/filter.service';

describe('START_PRESETS', () => {
  it('has a non-empty, uniquely-identified list', () => {
    expect(START_PRESETS.length).toBeGreaterThan(0);
    const ids = START_PRESETS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('every preset lens is a registered heatmap mode', () => {
    for (const p of START_PRESETS) {
      expect(isHeatmapMode(p.heat)).withContext(`${p.id} -> ${p.heat}`).toBe(true);
    }
  });

  it('every preset panel is a real PANEL_ROUTE_MAP destination', () => {
    for (const p of START_PRESETS) {
      expect(PANEL_ROUTE_MAP[p.panel]).withContext(`${p.id} -> ${p.panel}`).toBeTruthy();
    }
  });

  it('pairs distinct lenses with distinct workspaces (not cosmetic duplicates)', () => {
    const lenses = START_PRESETS.map((p) => p.heat);
    const panels = START_PRESETS.map((p) => p.panel);
    expect(new Set(lenses).size).toBe(lenses.length);
    expect(new Set(panels).size).toBe(panels.length);
  });

  it('every preset has a label, icon and blurb', () => {
    for (const p of START_PRESETS) {
      expect(p.label.trim().length).toBeGreaterThan(0);
      expect(p.icon.trim().length).toBeGreaterThan(0);
      expect(p.blurb.trim().length).toBeGreaterThan(0);
    }
  });

  it('startPresetById resolves a known id and rejects an unknown one', () => {
    expect(startPresetById(START_PRESETS[0].id)).toBe(START_PRESETS[0]);
    expect(startPresetById('nope')).toBeUndefined();
  });
});
