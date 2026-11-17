// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { StartPresetService } from './start-preset.service';
import { FilterService } from './filter.service';
import { PanelNavService } from './panel-nav.service';
import { START_PRESETS } from '../models/start-presets';

describe('StartPresetService', () => {
  let service: StartPresetService;
  let setHeatmapMode: jasmine.Spy;
  let open: jasmine.Spy;

  beforeEach(() => {
    setHeatmapMode = jasmine.createSpy('setHeatmapMode');
    open = jasmine.createSpy('open');
    TestBed.configureTestingModule({
      providers: [
        StartPresetService,
        { provide: FilterService, useValue: { setHeatmapMode } },
        { provide: PanelNavService, useValue: { open } },
      ],
    });
    service = TestBed.inject(StartPresetService);
  });

  it('exposes the preset list', () => {
    expect(service.presets).toBe(START_PRESETS);
  });

  it('applies a preset: selects its lens, then opens its workspace', () => {
    const preset = START_PRESETS[0];
    service.apply(preset.id);
    expect(setHeatmapMode).toHaveBeenCalledWith(preset.heat);
    expect(open).toHaveBeenCalledWith(preset.panel);
  });

  it('applies every preset to its own lens and panel', () => {
    for (const p of START_PRESETS) {
      setHeatmapMode.calls.reset();
      open.calls.reset();
      service.apply(p.id);
      expect(setHeatmapMode).toHaveBeenCalledWith(p.heat);
      expect(open).toHaveBeenCalledWith(p.panel);
    }
  });

  it('ignores an unknown id (no lens change, no navigation)', () => {
    service.apply('not-a-preset');
    expect(setHeatmapMode).not.toHaveBeenCalled();
    expect(open).not.toHaveBeenCalled();
  });
});
