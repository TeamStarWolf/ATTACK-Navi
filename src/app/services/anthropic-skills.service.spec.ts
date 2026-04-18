// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { AnthropicSkillsService } from './anthropic-skills.service';

describe('AnthropicSkillsService', () => {
  let service: AnthropicSkillsService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(AnthropicSkillsService);
  });

  it('returns 0 skill count for unknown technique', () => {
    expect(service.getSkillCount('T9999')).toBe(0);
  });

  it('returns non-negative heat score for any input', () => {
    expect(service.getHeatScore('T1059')).toBeGreaterThanOrEqual(0);
  });
});
