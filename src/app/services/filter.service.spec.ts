// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, fakeAsync, tick } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { AttackDomain, DataService } from './data.service';
import { AttackIdResolverService } from './attack-id-resolver.service';
import { Domain } from '../models/domain';
import { Technique } from '../models/technique';
import {
  DEFAULT_HEATMAP_MODE, FilterService, domainHintForAttackId, effectiveDefaultLens, isAttackDomain, techNotInDomainMessage,
  URL_TECH_ID_PATTERN, normalizeUrlTechId,
} from './filter.service';

describe('FilterService', () => {
  let service: FilterService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        FilterService,
        {
          provide: DataService,
          useValue: {
            domain$: new BehaviorSubject(null),
          },
        },
      ],
    });

    service = TestBed.inject(FilterService);
  });

  // E1.5 (D4): a fresh profile opens on Prevalence, a Threat lens, never on
  // Reference depth ('unified') or a posture lens.
  describe('default lens (E1.5, D4)', () => {
    it('starts on Prevalence (heat=frequency)', () => {
      expect(DEFAULT_HEATMAP_MODE).toBe('frequency');
      expect(service.getStateSnapshot().heatmapMode).toBe('frequency');
    });

    it('leaves the default out of the URL and writes any other lens, Reference depth included', () => {
      expect(service.serializeUrlState()['heat']).toBeUndefined();
      service.setHeatmapMode('unified');
      expect(service.serializeUrlState()['heat']).toBe('unified');
      service.setHeatmapMode('frequency');
      expect(service.serializeUrlState()['heat']).toBeUndefined();
    });
  });

  // P2-19 (E2.4): the default-lens rule. DEFAULT_HEATMAP_MODE stays
  // 'frequency'; owner data (D4) makes Posture the effective default.
  describe('default-lens rule (P2-19)', () => {
    it('effectiveDefaultLens is posture with owner data, else frequency; DEFAULT_HEATMAP_MODE stays frequency', () => {
      expect(DEFAULT_HEATMAP_MODE).toBe('frequency');
      expect(effectiveDefaultLens(false)).toBe('frequency');
      expect(effectiveDefaultLens(true)).toBe('posture');
    });

    it('ownerDataPresent starts false and picks defaultLens', () => {
      expect(service.ownerDataPresent.value).toBeFalse();
      expect(service.defaultLens).toBe('frequency');
      service.ownerDataPresent.next(true);
      expect(service.defaultLens).toBe('posture');
    });

    it('heat is left out for frequency with no owner data and no tech; with owner data every chosen lens is written, posture included', () => {
      expect(service.serializeUrlState()['heat']).toBeUndefined();
      service.ownerDataPresent.next(true);
      // RP-F decision 10: Prevalence that is only the default is not written once owner data exists.
      expect(service.serializeUrlState()['heat']).toBeUndefined();
      service.setHeatmapMode('posture');
      expect(service.serializeUrlState()['heat']).toBe('posture');
      service.setHeatmapMode('frequency');
      expect(service.serializeUrlState()['heat']).toBe('frequency');
      service.setHeatmapMode('posture');
      service.ownerDataPresent.next(false);
      expect(service.serializeUrlState()['heat']).toBe('posture');
    });

    // RP-F decision 10: owner data that first appears in a session (a bulk set, a run)
    // while Prevalence is on screen only as the D4 default must not pin heat=frequency:
    // heat stays absent, so a reload runs D4 and boots Posture. A chosen Prevalence is
    // still written and so honoured on reload.
    describe('the ownerDataPresent transition (RP-F decision 10)', () => {
      it('the default Prevalence: heat stays absent before and after owner data appears', () => {
        expect(service.lensExplicit).toBeFalse();
        expect(service.serializeUrlState()['heat']).toBeUndefined();
        service.ownerDataPresent.next(true);
        expect(service.getStateSnapshot().heatmapMode).toBe('frequency');
        expect(service.serializeUrlState()['heat']).toBeUndefined();
      });

      it('a Prevalence chosen through the View menu (setHeatmapMode): heat=frequency once owner data appears', () => {
        service.setHeatmapMode('frequency');
        expect(service.lensExplicit).toBeTrue();
        expect(service.serializeUrlState()['heat']).toBeUndefined();
        service.ownerDataPresent.next(true);
        expect(service.serializeUrlState()['heat']).toBe('frequency');
      });

      it('a pasted heat=frequency is a choice; an invalid heat= is not', () => {
        service.applyUrlState(new URLSearchParams('heat=bogus'));
        service.ownerDataPresent.next(true);
        expect(service.lensExplicit).toBeFalse();
        expect(service.serializeUrlState()['heat']).toBeUndefined();
        service.applyUrlState(new URLSearchParams('heat=frequency'));
        expect(service.lensExplicit).toBeTrue();
        expect(service.serializeUrlState()['heat']).toBe('frequency');
      });

      it('a default applied with { explicit: false } and clearAll are not choices', () => {
        service.setHeatmapMode('frequency');
        service.setHeatmapMode('frequency', { explicit: false });
        service.ownerDataPresent.next(true);
        expect(service.serializeUrlState()['heat']).toBeUndefined();
        service.setHeatmapMode('frequency');
        service.ownerDataPresent.next(false);
        service.clearAll();
        expect(service.lensExplicit).toBeFalse();
        service.ownerDataPresent.next(true);
        expect(service.serializeUrlState()['heat']).toBeUndefined();
      });

      it('with a technique open: heat=frequency without owner data (unchanged); absent once owner data appears, unless chosen', () => {
        service.selectTechnique({ id: 'attack-pattern--a', attackId: 'T1059', name: 'Command Interpreter' } as unknown as Technique);
        expect(service.serializeUrlState()['heat']).toBe('frequency');
        service.ownerDataPresent.next(true);
        expect(service.serializeUrlState()['heat']).toBeUndefined();
        service.setHeatmapMode('frequency');
        expect(service.serializeUrlState()['heat']).toBe('frequency');
      });

      it('a restored snapshot names a chosen lens', () => {
        service.ownerDataPresent.next(true);
        service.restoreStateSnapshot({ heatmapMode: 'frequency' });
        expect(service.serializeUrlState()['heat']).toBe('frequency');
      });
    });

    it('ownerDataPresent joins urlRelevantState$', fakeAsync(() => {
      let emissions = 0;
      const sub = service.urlRelevantState$.subscribe(() => emissions++);
      tick(300);
      expect(emissions).toBe(1);
      service.ownerDataPresent.next(true);
      tick(300);
      expect(emissions).toBe(2);
      sub.unsubscribe();
    }));

    it('clearAll returns to the effective default: posture with owner data, frequency without', () => {
      service.ownerDataPresent.next(true);
      service.setHeatmapMode('kev');
      service.clearAll();
      expect(service.getStateSnapshot().heatmapMode).toBe('posture');
      service.ownerDataPresent.next(false);
      service.setHeatmapMode('kev');
      service.clearAll();
      expect(service.getStateSnapshot().heatmapMode).toBe('frequency');
    });
  });

  describe('applyUrlState validation', () => {
    const apply = (query: string) => service.applyUrlState(new URLSearchParams(query));

    it('applies a known heatmap mode, scope and implementation status', () => {
      apply('heat=kev&scope=full&impl=planned');
      expect(service.getStateSnapshot().heatmapMode).toBe('kev');
      service.searchScope$.subscribe(v => expect(v).toBe('full')).unsubscribe();
      service.implStatusFilter$.subscribe(v => expect(v).toBe('planned')).unsubscribe();
    });

    it('ignores a heat value that is not a heatmap mode', () => {
      // A retired or mistyped mode used to put the matrix in an unknown mode with
      // the wrong legend and none of the mode's loaders running.
      apply('heat=mitigations');
      expect(service.getStateSnapshot().heatmapMode).toBe('frequency');
      apply('heat=bogus');
      expect(service.getStateSnapshot().heatmapMode).toBe('frequency');
    });

    it('ignores unknown scope and impl values but still applies the rest of the link', () => {
      apply('scope=everything&impl=done&heat=risk&tq=T1059');
      service.searchScope$.subscribe(v => expect(v).toBe('name')).unsubscribe();
      service.implStatusFilter$.subscribe(v => expect(v).toBeNull()).unsubscribe();
      expect(service.getStateSnapshot().heatmapMode).toBe('risk');
      service.techniqueQuery$.subscribe(v => expect(v).toBe('T1059')).unsubscribe();
    });

    // P2-17: the Threat gaps overlay is a session toggle carried as tgap=1.
    it('round-trips tgap=1 and ignores any other tgap value', () => {
      const overlay = (): boolean => {
        let v = false;
        service.threatGapOverlay$.subscribe(o => (v = o)).unsubscribe();
        return v;
      };
      expect(overlay()).toBeFalse();
      expect(service.serializeUrlState()['tgap']).toBeUndefined();
      for (const bad of ['tgap=0', 'tgap=true', 'tgap=yes', 'tgap=', 'tgap=11', 'tgap=%201']) {
        apply(bad);
        expect(overlay()).withContext(bad).toBeFalse();
        expect(service.serializeUrlState()['tgap']).withContext(bad).toBeUndefined();
      }
      apply('tgap=1&heat=kev');
      expect(overlay()).toBeTrue();
      const params = service.serializeUrlState();
      expect(params['tgap']).toBe('1');
      service.toggleThreatGapOverlay();
      expect(overlay()).toBeFalse();
      expect(service.serializeUrlState()['tgap']).toBeUndefined();
      service.applyUrlState(new URLSearchParams(params));
      expect(overlay()).toBeTrue();
      expect(service.serializeUrlState()).toEqual(params);
      service.setThreatGapOverlay(false);
      expect(overlay()).toBeFalse();
    });

    it('does not serialize a value that was rejected', () => {
      apply('heat=bogus&scope=everything');
      const params = service.serializeUrlState();
      expect(params['heat']).toBeUndefined();
      expect(params['scope']).toBeUndefined();
    });
  });

  describe('drawer Pin (E2.3)', () => {
    const tech = { id: 'attack-pattern--a', attackId: 'T1059', name: 'Command Interpreter' } as unknown as Technique;
    const pinned = (): boolean => {
      let v = false;
      service.drawerPinned$.subscribe(p => (v = p)).unsubscribe();
      return v;
    };

    it('starts unpinned, is set by setDrawerPinned and never reaches the URL', () => {
      expect(pinned()).toBeFalse();
      service.selectTechnique(tech);
      service.setDrawerPinned(true);
      expect(pinned()).toBeTrue();
      expect(Object.keys(service.serializeUrlState())).not.toContain('pin');
      service.setDrawerPinned(false);
      expect(pinned()).toBeFalse();
    });

    it('closing the drawer unpins it (selectTechnique(null): close button, Escape; clearAll)', () => {
      service.selectTechnique(tech);
      service.setDrawerPinned(true);
      service.selectTechnique({ ...tech, attackId: 'T1003' } as Technique);
      expect(pinned()).toBeTrue(); // another technique keeps the pin
      service.selectTechnique(null);
      expect(pinned()).toBeFalse();
      service.selectTechnique(tech);
      service.setDrawerPinned(true);
      service.clearAll();
      expect(pinned()).toBeFalse();
    });
  });

  it('should reset advanced filter state in clearAll', () => {
    service.setHeatmapMode('risk');
    service.setImplStatusFilter('implemented');
    service.setSearchScope('full');
    service.toggleSearchFilterMode();
    service.toggleTacticVisibility('ta0001');
    service.setCveFilter(['tech-1']);
    service.setTechniqueSearch('powershell');

    service.clearAll();

    expect(service.getStateSnapshot().heatmapMode).toBe('frequency');
    expect(service.getStateSnapshot().hiddenTacticIds).toEqual([]);
    expect(service.getTechniqueSearch()).toBe('');

    service.implStatusFilter$.subscribe(value => expect(value).toBeNull());
    service.searchScope$.subscribe(value => expect(value).toBe('name'));
    service.searchFilterMode$.subscribe(value => expect(value).toBeFalse());
    service.cveTechniqueIds$.subscribe(value => expect(value.size).toBe(0));
  });
});

// E2.3 (P2-04): tech= and dom= in the URL.
describe('FilterService tech= and dom= (E2.3)', () => {
  const NAMES: Record<AttackDomain, string> = {
    enterprise: 'Enterprise ATT&CK', ics: 'ICS ATT&CK', mobile: 'Mobile ATT&CK', f3: 'F3 Fraud Framework',
  };
  const t = (attackId: string): Technique => ({ id: `attack-pattern--${attackId}`, attackId, name: attackId } as unknown as Technique);
  const makeDomain = (key: AttackDomain, ids: string[]): Domain => ({
    name: NAMES[key], techniques: ids.map(t), mitigations: [], groups: [], software: [], campaigns: [], dataComponents: [],
  } as unknown as Domain);
  const ENTERPRISE = makeDomain('enterprise', ['T1059', 'T1059.001', 'T1685']);
  const ICS = makeDomain('ics', ['T0807', 'T0886']);

  let domain$: BehaviorSubject<Domain | null>;
  let currentDomain$: BehaviorSubject<AttackDomain>;
  let switchDomain: jasmine.Spy;
  let service: FilterService;

  /** A DataService stub whose switchDomain behaves like the real one: domain$ goes null until the new domain loads. */
  function stub(): Partial<DataService> {
    return {
      domain$, currentDomain$,
      switchDomain: switchDomain.and.callFake((d: AttackDomain) => {
        if (d === currentDomain$.value) return;
        currentDomain$.next(d);
        domain$.next(null);
      }),
    } as unknown as Partial<DataService>;
  }

  beforeEach(() => {
    domain$ = new BehaviorSubject<Domain | null>(ENTERPRISE);
    currentDomain$ = new BehaviorSubject<AttackDomain>('enterprise');
    switchDomain = jasmine.createSpy('switchDomain');
    TestBed.configureTestingModule({
      providers: [FilterService, { provide: DataService, useFactory: stub }],
    });
    service = TestBed.inject(FilterService);
  });

  const apply = (query: string) => service.applyUrlState(new URLSearchParams(query));
  const selected = (): Technique | null => {
    let v: Technique | null = null;
    service.selectedTechnique$.subscribe(x => (v = x)).unsubscribe();
    return v;
  };
  const notices = (): string[] => {
    const seen: string[] = [];
    service.urlNotice$.subscribe(m => seen.push(m));
    return seen;
  };

  it('tech and dom round-trip, Enterprise and ICS', () => {
    service.selectTechnique(ENTERPRISE.techniques[1]);
    const ent = service.serializeUrlState();
    expect(ent).toEqual(jasmine.objectContaining({ tech: 'T1059.001', dom: 'enterprise' }));

    const fresh = new FilterService(TestBed.inject(DataService), TestBed.inject(AttackIdResolverService));
    fresh.applyUrlState(new URLSearchParams(ent));
    expect(fresh.serializeUrlState()).toEqual(ent);

    // ICS on screen: dom=ics is written even without a technique, and with one.
    service.selectTechnique(null);
    service.applyUrlState(new URLSearchParams('dom=ics'));
    domain$.next(ICS);
    expect(service.serializeUrlState()).toEqual({ dom: 'ics' });
    service.selectTechnique(ICS.techniques[0]);
    const ics = service.serializeUrlState();
    expect(ics).toEqual({ heat: DEFAULT_HEATMAP_MODE, dom: 'ics', tech: 'T0807' });

    // A fresh Enterprise boot applies the ICS link: it switches, then selects.
    currentDomain$.next('enterprise');
    domain$.next(ENTERPRISE);
    const boot = new FilterService(TestBed.inject(DataService), TestBed.inject(AttackIdResolverService));
    boot.applyUrlState(new URLSearchParams(ics));
    domain$.next(ICS);
    expect(boot.serializeUrlState()).toEqual(ics);
  });

  it('with tech, heat is serialized even at the default lens; without tech, neither heat nor dom (Enterprise)', () => {
    expect(service.serializeUrlState()).toEqual({});
    service.selectTechnique(ENTERPRISE.techniques[0]);
    const params = service.serializeUrlState();
    expect(params['heat']).toBe(DEFAULT_HEATMAP_MODE);
    expect(params['dom']).toBe('enterprise');
    service.setHeatmapMode('kev');
    expect(service.serializeUrlState()['heat']).toBe('kev');
    service.selectTechnique(null);
    service.setHeatmapMode(DEFAULT_HEATMAP_MODE);
    expect(service.serializeUrlState()).toEqual({});
  });

  it('a retired id selects the live technique (AttackIdResolverService)', () => {
    TestBed.inject(AttackIdResolverService).setSupersededBy(new Map([['T1562.001', 'T1685']]));
    apply('tech=T1562.001');
    expect(selected()?.attackId).toBe('T1685');
    expect(service.serializeUrlState()['tech']).toBe('T1685');
  });

  it('dom=ics&tech=T0807 switches domain once and selects T0807 after the ICS domain emits', () => {
    const seen = notices();
    apply('dom=ics&tech=T0807');
    expect(switchDomain).toHaveBeenCalledOnceWith('ics');
    expect(selected()).toBeNull();
    // Until ICS loads, the pending tech and dom stay serialized.
    expect(service.serializeUrlState()).toEqual(jasmine.objectContaining({ dom: 'ics', tech: 'T0807' }));
    // A stale Enterprise emission is not the target domain.
    domain$.next(ENTERPRISE);
    expect(selected()).toBeNull();
    domain$.next(ICS);
    expect(selected()?.attackId).toBe('T0807');
    expect(switchDomain).toHaveBeenCalledTimes(1);
    expect(seen).toEqual([]);
  });

  it('an unknown tech raises the toast once and selects nothing', () => {
    const seen = notices();
    apply('tech=T0807');
    expect(selected()).toBeNull();
    expect(seen).toEqual(['T0807 is not in Enterprise ATT&CK. Add dom=ics to the link or switch domain.']);
    domain$.next(ENTERPRISE);
    expect(seen.length).toBe(1);
    expect(service.serializeUrlState()['tech']).toBeUndefined();
  });

  it('ignores a tech value outside URL_TECH_ID_PATTERN silently: no toast, no selection, nothing echoed', () => {
    const seen = notices();
    apply('tech=' + encodeURIComponent('Your session expired, call 555-0100'));
    apply('tech=' + encodeURIComponent('T1059 <b>x</b>'));
    apply('tech=T1059;drop');
    domain$.next(ENTERPRISE);
    expect(seen).toEqual([]);
    expect(selected()).toBeNull();
    expect(service.serializeUrlState()['tech']).toBeUndefined();
  });

  it('ignores a 40-character tech value', () => {
    const seen = notices();
    const long = 'T1059.001'.padEnd(40, '0');
    expect(long.length).toBe(40);
    apply('tech=' + long);
    expect(seen).toEqual([]);
    expect(selected()).toBeNull();
    expect(service.serializeUrlState()['tech']).toBeUndefined();
  });

  it('a lower-case, padded tech id is normalised and selects the technique', () => {
    apply('tech=' + encodeURIComponent(' t1059.001 '));
    expect(selected()?.attackId).toBe('T1059.001');
  });

  it('the not-in-domain toast echoes the normalised id, never the raw param', () => {
    const seen = notices();
    apply('tech=' + encodeURIComponent('  t0807 '));
    expect(selected()).toBeNull();
    expect(seen).toEqual(['T0807 is not in Enterprise ATT&CK. Add dom=ics to the link or switch domain.']);
  });

  it('URL_TECH_ID_PATTERN and normalizeUrlTechId cover ATT&CK, sub-technique, F3 and ATLAS ids', () => {
    for (const id of ['T1059', 'T1059.001', 'T0807', 'F1001', 'F1001.001', 'AML.T0051', 'AML.T0051.000', 'aml.t0051']) {
      expect(URL_TECH_ID_PATTERN.test(id)).withContext(id).toBeTrue();
    }
    for (const id of ['', 'T105', 'T10590', 'T1059.01', 'T1059.0011', 'AML.F1001', 'X1059', 'T1059 ', 'Your session expired, call 555-0100']) {
      expect(URL_TECH_ID_PATTERN.test(id)).withContext(id).toBeFalse();
    }
    expect(normalizeUrlTechId(' t1059.001 ')).toBe('T1059.001');
    expect(normalizeUrlTechId('AML.T0051')).toBe('AML.T0051');
    expect(normalizeUrlTechId('F1001')).toBe('F1001');
    expect(normalizeUrlTechId('T1059'.padEnd(40, ' ') + 'x')).toBeNull();
    expect(normalizeUrlTechId(null)).toBeNull();
    expect(normalizeUrlTechId('Your session expired, call 555-0100')).toBeNull();
  });

  it('AML.T0051 and F1001 pass validation and reach the not-in-domain notice by their normalised id', () => {
    const seen = notices();
    apply('tech=aml.t0051');
    apply('tech=F1001');
    expect(seen).toEqual([
      'AML.T0051 is not in Enterprise ATT&CK. Check the id or switch domain.',
      'F1001 is not in Enterprise ATT&CK. Add dom=f3 to the link or switch domain.',
    ]);
  });

  it('ignores a dom value that is not an ATT&CK domain (#118 pattern) and applies the rest', () => {
    apply('dom=bogus&tech=T1059.001&heat=kev');
    apply('dom=constructor');
    expect(switchDomain).not.toHaveBeenCalled();
    expect(selected()?.attackId).toBe('T1059.001');
    expect(service.getStateSnapshot().heatmapMode).toBe('kev');
    expect(service.serializeUrlState()['dom']).toBe('enterprise');
  });

  it('a user selection made while a tech link waits wins over the link', () => {
    apply('dom=ics&tech=T0807');
    service.selectTechnique(ENTERPRISE.techniques[0]);
    domain$.next(ICS);
    expect(selected()?.attackId).toBe('T1059');
  });

  it('isAttackDomain, domainHintForAttackId and the toast text', () => {
    expect(isAttackDomain('ics')).toBeTrue();
    expect(isAttackDomain('ICS')).toBeFalse();
    expect(isAttackDomain('toString')).toBeFalse();
    expect(isAttackDomain(null)).toBeFalse();
    expect(domainHintForAttackId('T0807')).toBe('ics');
    expect(domainHintForAttackId('F1001')).toBe('f3');
    expect(domainHintForAttackId('T1059.001')).toBeNull();
    expect(techNotInDomainMessage('T0807', 'enterprise'))
      .toBe('T0807 is not in Enterprise ATT&CK. Add dom=ics to the link or switch domain.');
    expect(techNotInDomainMessage('T9999', 'ics')).toBe('T9999 is not in ICS ATT&CK. Check the id or switch domain.');
  });
});
