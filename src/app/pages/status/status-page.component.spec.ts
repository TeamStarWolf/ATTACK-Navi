// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Post-Phase-1 QA (R9b): the Status page shows Known-tier mapped counts, so its
// headings say 'Mapped', not 'Coverage'. The child components are replaced by
// placeholders: this spec reads only the page's own headings and copy.
import { NO_ERRORS_SCHEMA } from '@angular/core';
import { CommonModule } from '@angular/common';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { BehaviorSubject } from 'rxjs';

import { StatusPageComponent } from './status-page.component';
import { DataService } from '../../services/data.service';
import { Domain } from '../../models/domain';

describe('StatusPageComponent headings', () => {
  function render(domain: Domain | null): HTMLElement {
    TestBed.configureTestingModule({
      imports: [StatusPageComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(domain), loading$: new BehaviorSubject(false) } },
        { provide: Router, useValue: { navigate: jasmine.createSpy('navigate') } },
      ],
    });
    TestBed.overrideComponent(StatusPageComponent, { set: { imports: [CommonModule], schemas: [NO_ERRORS_SCHEMA] } });
    const fixture = TestBed.createComponent(StatusPageComponent);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  const headings = (host: HTMLElement) =>
    [...host.querySelectorAll('.status-section-title')].map(h => h.textContent!.replace(/\s+/g, ' ').trim());

  it('labels the mapped count and the per-framework breakdown as mapped, not coverage', () => {
    const host = render({} as Domain);
    expect(headings(host)).toEqual(['Mapped', 'Mapped by framework', 'Data Sources & Integrations']);
    expect(host.querySelector('.status-sub')!.textContent).toContain('at-a-glance mapped counts');
    expect(host.textContent).not.toMatch(/\bcoverage\b/i);
  });

  it('keeps the Mapped heading while no domain is loaded', () => {
    expect(headings(render(null))).toEqual(['Mapped', 'Data Sources & Integrations']);
  });
});
