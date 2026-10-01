// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable, inject } from '@angular/core';
import { Router } from '@angular/router';
import { BehaviorSubject, Observable } from 'rxjs';
import { FilterService, HeatmapMode } from './filter.service';

/** A security role the whole app can be viewed through. */
export type ViewpointId =
  | 'analyst'
  | 'red'
  | 'detection'
  | 'defense'
  | 'cti'
  | 'vuln'
  | 'exec'
  | 'deception';

export interface Viewpoint {
  id: ViewpointId;
  /** Full label, e.g. "Red Team". */
  label: string;
  /** Short label for the compact rail trigger, e.g. "Red". */
  short: string;
  /** An EXISTING icon-registry name (icon-registry.ts). */
  icon: string;
  /** One line shown under the label in the picker. */
  tagline: string;
  /** Heatmap lens this role leads with (a real HeatmapMode value). */
  defaultLens: HeatmapMode;
  /** Home workspace route this role lands on (a real top-level route). */
  homeRoute: string;
  /** Lenses this role cares about, ordered — surfaced at the top of the lens menu. */
  featuredLenses: HeatmapMode[];
}

/** localStorage key holding the last chosen viewpoint id. */
const STORAGE_KEY = 'attack-navi-viewpoint';

/**
 * Re-frames the whole app for a security role: sets the matrix's default
 * heatmap lens, navigates to the role's home workspace, and marks that role's
 * featured lenses in the lens menu. The default `analyst` viewpoint reproduces
 * the app's neutral behaviour (unified lens, /matrix home), so users who never
 * touch the switcher see no change.
 *
 * Every lens value below is a real `HeatmapMode` (filter.service.ts) and every
 * `homeRoute` is a real top-level route (app.routes.ts); every `icon` is a name
 * that exists in icon-registry.ts.
 */
@Injectable({ providedIn: 'root' })
export class ViewpointService {
  private readonly filterService = inject(FilterService);
  private readonly router = inject(Router);

  readonly viewpoints: Viewpoint[] = [
    {
      id: 'analyst',
      label: 'Analyst',
      short: 'Analyst',
      icon: 'compass',
      tagline: 'Neutral, unified coverage view',
      defaultLens: 'unified',
      homeRoute: '/matrix',
      featuredLenses: ['unified', 'coverage', 'risk', 'detection'],
    },
    {
      id: 'red',
      label: 'Red Team',
      short: 'Red',
      icon: 'swords',
      tagline: 'Adversary emulation & offense',
      defaultLens: 'atomic',
      homeRoute: '/matrix',
      featuredLenses: ['atomic', 'software', 'campaign', 'intelligence', 'poc-exploits'],
    },
    {
      id: 'detection',
      label: 'Detection Engineering',
      short: 'Detection',
      icon: 'radar',
      tagline: 'Detection engineering & rules',
      defaultLens: 'detection',
      homeRoute: '/detect',
      featuredLenses: ['detection', 'sigma', 'car', 'elastic', 'splunk', 'wazuh', 'm365'],
    },
    {
      id: 'defense',
      label: 'Defense',
      short: 'Defense',
      icon: 'shield-check',
      tagline: 'Defensive countermeasures & coverage',
      defaultLens: 'd3fend',
      homeRoute: '/coverage',
      featuredLenses: ['d3fend', 'coverage', 'controls', 'nist', 'engage'],
    },
    {
      id: 'cti',
      label: 'Threat Intelligence',
      short: 'CTI',
      icon: 'users',
      tagline: 'Threat intelligence & actors',
      defaultLens: 'intelligence',
      homeRoute: '/intel',
      featuredLenses: ['intelligence', 'software', 'campaign', 'frequency'],
    },
    {
      id: 'vuln',
      label: 'Vulnerability & Exposure',
      short: 'Vuln',
      icon: 'shield-alert',
      tagline: 'Vulnerability & exposure management',
      defaultLens: 'kev',
      homeRoute: '/exposure',
      featuredLenses: ['kev', 'cve', 'epss', 'poc-exploits', 'kill-chain', 'my-exposure'],
    },
    {
      id: 'exec',
      label: 'Governance & Executive',
      short: 'Exec',
      icon: 'building',
      tagline: 'Governance, risk & compliance',
      defaultLens: 'controls',
      homeRoute: '/dashboard',
      featuredLenses: ['controls', 'nist', 'cri', 'csa-ccm', 'unified'],
    },
    {
      id: 'deception',
      label: 'Deception',
      short: 'Deception',
      icon: 'drama',
      tagline: 'Adversary engagement & deception',
      defaultLens: 'engage',
      homeRoute: '/matrix',
      featuredLenses: ['engage', 'd3fend'],
    },
  ];

  private readonly viewpointSubject = new BehaviorSubject<Viewpoint>(this.byId('analyst'));
  readonly viewpoint$: Observable<Viewpoint> = this.viewpointSubject.asObservable();

  /** The currently active viewpoint (defaults to `analyst`). */
  get current(): Viewpoint {
    return this.viewpointSubject.value;
  }

  /**
   * Switch to a viewpoint: set its default lens, persist the choice, emit, and
   * (unless `navigate: false`) navigate to its home workspace. UI callers omit
   * `opts` and get navigation.
   */
  setViewpoint(id: ViewpointId, opts?: { navigate?: boolean }): void {
    const vp = this.viewpoints.find((v) => v.id === id);
    if (!vp) return;
    this.filterService.setHeatmapMode(vp.defaultLens);
    this.persist(vp.id);
    this.viewpointSubject.next(vp);
    if (opts?.navigate !== false) {
      void this.router.navigateByUrl(vp.homeRoute);
    }
  }

  /**
   * Called once at startup. If a valid viewpoint is stored, restore it and —
   * unless the URL carries an explicit `heat` lens (a deep link) — apply its
   * default lens WITHOUT navigating (never yank a user off a deep-linked
   * route). Nothing stored → stay `analyst` and do nothing.
   */
  restore(): void {
    let storedId: string | null = null;
    try {
      storedId = localStorage.getItem(STORAGE_KEY);
    } catch {
      storedId = null;
    }
    if (!storedId) return;
    const vp = this.viewpoints.find((v) => v.id === storedId);
    if (!vp) return;
    this.viewpointSubject.next(vp);
    if (!this.urlHasHeatParam()) {
      this.filterService.setHeatmapMode(vp.defaultLens);
    }
  }

  /** True when `mode` is one of the active viewpoint's featured lenses. */
  isFeaturedLens(mode: HeatmapMode): boolean {
    return this.current.featuredLenses.includes(mode);
  }

  private byId(id: ViewpointId): Viewpoint {
    return this.viewpoints.find((v) => v.id === id) ?? this.viewpoints[0];
  }

  private persist(id: ViewpointId): void {
    try {
      localStorage.setItem(STORAGE_KEY, id);
    } catch {
      /* private windows / disabled storage — non-fatal */
    }
  }

  /**
   * Does the current URL carry an explicit `heat` lens? Filter state lives in
   * router query params inside the hash (e.g. `#/matrix?heat=kev`), so check
   * both the hash's query string and any plain search string.
   */
  private urlHasHeatParam(): boolean {
    try {
      if (new URLSearchParams(window.location.search).has('heat')) return true;
      const hash = window.location.hash || '';
      const q = hash.indexOf('?');
      if (q >= 0 && new URLSearchParams(hash.slice(q + 1)).has('heat')) return true;
      return false;
    } catch {
      return false;
    }
  }
}
