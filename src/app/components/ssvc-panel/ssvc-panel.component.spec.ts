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
