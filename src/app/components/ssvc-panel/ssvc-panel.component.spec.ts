// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { SsvcPanelComponent } from './ssvc-panel.component';

describe('SsvcPanelComponent', () => {
  it('class is exported', () => {
    expect(SsvcPanelComponent).toBeTruthy();
  });
});

describe('SsvcPanelComponent selection', () => {
  const KEV = {
    cveID: 'CVE-2021-44228', vendorProject: 'Apache', product: 'Log4j2',
    vulnerabilityName: '', dateAdded: '2021-12-10', shortDescription: '',
    requiredAction: '', dueDate: '2021-12-24',
    knownRansomwareCampaignUse: 'Known', notes: '',
  };

  function panel() {
    const c = Object.create(SsvcPanelComponent.prototype) as any;
    c.cveService = { getKevEntry: (id: string) => (id === KEV.cveID ? KEV : undefined) };
    c.ssvc = { evaluate: (cve: any) => ({ action: cve.isKev ? 'act' : 'track', points: [] }) };
    c.cdr = { markForCheck: () => undefined };
    c.tablesLoaded = true;
    c.env = { exposed: 'yes', mission: 'medium' };
    c.overrides = {};
    return c;
  }

  it('enriches a raw record from activeCve$ before evaluating it', () => {
    // A record parsed before KEV loaded keeps isKev:false forever; evaluating it raw
    // yields a weaker verdict that then sticks.
    const c = panel();
    c.select({ id: 'CVE-2021-44228', isKev: false, references: [] });
    expect(c.selected.isKev).toBe(true);
    expect(c.selected.kevKnownRansomware).toBe(true);
    expect(c.selectedResult.action).toBe('act');
  });

  it('clears overrides when the selection changes', () => {
    const c = panel();
    c.overrides = { automatable: 'no' };
    c.select({ id: 'CVE-2000-0001', isKev: false, references: [] });
    expect(c.overrides).toEqual({});
  });

  it('does not invent KEV membership for a CVE that is not listed', () => {
    const c = panel();
    c.select({ id: 'CVE-2000-0001', isKev: true, references: [] });
    expect(c.selected.isKev).toBe(false);
  });
});

describe('SsvcPanelComponent assess', () => {
  function panel(cached: Record<string, unknown> = {}) {
    const c = Object.create(SsvcPanelComponent.prototype) as any;
    const searched: string[] = [];
    c.searched = searched;
    c.cveService = {
      getCachedCve: (id: string) => (cached as any)[id] ?? null,
      getKevEntry: () => undefined,
      getAllCachedCves: () => Object.values(cached),
      searchCves: (q: string) => searched.push(q),
    };
    c.ssvc = {
      available: true,
      evaluate: () => ({ action: 'track', timeline: '60 days', points: [] }),
      timelineDays: () => 60,
      actionRank: () => 3,
    };
    c.epssService = { getScore: () => null, fetchScores: () => ({ subscribe: () => undefined }) };
    c.attackCve = { getMappingForCve: () => undefined };
    c.cdr = { markForCheck: () => undefined };
    c.tablesLoaded = true;
    c.env = { exposed: 'yes', mission: 'medium' };
    c.overrides = {};
    c.rows = [];
    c.subs = { add: () => undefined };
    return c;
  }

  const rec = (id: string) => ({ id, isKev: false, references: [], cvssVector: null });

  it('selects a CVE that is already cached, without waiting', () => {
    const c = panel({ 'CVE-2026-96769': rec('CVE-2026-96769') });
    c.query = 'CVE-2026-96769';
    c.search();
    expect(c.selected.id).toBe('CVE-2026-96769');
  });

  it('does not leave a previous CVE on screen while the new one loads', () => {
    // The reported symptom: Assess appeared to do nothing because the detail kept
    // showing the previously selected CVE.
    const c = panel({ 'CVE-2026-96770': rec('CVE-2026-96770') });
    c.select(rec('CVE-2026-96770'));
    c.query = 'CVE-2026-96769';
    c.search();
    expect(c.selected.id).toBe('CVE-2026-96770');   // not yet fetched
    // ...and once NVD answers, the requested CVE takes over.
    (c.cveService as any).getCachedCve = (id: string) =>
      id === 'CVE-2026-96769' ? rec('CVE-2026-96769') : null;
    (c.cveService as any).getAllCachedCves = () => [rec('CVE-2026-96769')];
    c.recompute();
    expect(c.selected.id).toBe('CVE-2026-96769');
  });

  it('issues the NVD search', () => {
    const c = panel();
    c.query = 'CVE-2026-96769';
    c.search();
    expect(c.searched).toEqual(['CVE-2026-96769']);
  });

  it('holds no pending selection for a keyword query', () => {
    const c = panel();
    c.query = 'apache struts';
    c.search();
    expect(c.pendingSelect).toBeNull();
  });
});
