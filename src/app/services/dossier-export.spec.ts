// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { CveDossier } from '../models/dossier';
import { dossierToJson, dossierToMarkdown } from './dossier-export';

function emptyDossier(overrides: Partial<CveDossier> = {}): CveDossier {
  return {
    cveId: 'CVE-2021-44228',
    generated: '2026-10-01T00:00:00Z',
    source: 'live',
    description: 'Log4Shell',
    cvssScore: 10,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    severity: 'CRITICAL',
    epss: 0.975,
    epssPercentile: 0.999,
    isKev: true,
    kevDateAdded: '2021-12-10',
    kevDueDate: '2021-12-24',
    kevRansomware: true,
    ssvc: { cveId: 'CVE-2021-44228', points: [], action: 'act', actionTable: '', timeline: '3 days', timelineTable: '', warnings: [] },
    cisaSsvc: null,
    cwes: [],
    capecs: [],
    techniques: [],
    mitigations: [],
    countermeasures: [],
    engage: [],
    controls: [],
    controlFrameworks: [],
    threatActors: { groups: [], software: [], campaigns: [] },
    f3: { techniques: [] },
    detection: [],
    exploits: { hasPoc: false, exploitDb: [], publicPocs: [], advisories: [], exploitTaggedRefs: [] },
    articles: [],
    warnings: [],
    attackVersion: '19.2',
    ...overrides,
  };
}

describe('dossierToMarkdown', () => {
  it('renders the header, CVSS/EPSS/KEV summary and computed SSVC', () => {
    const md = dossierToMarkdown(emptyDossier());
    expect(md).toContain('# CVE-2021-44228 — CVE Enrichment Dossier');
    expect(md).toContain('**CVSS:** 10 CRITICAL');
    expect(md).toContain('**EPSS:** 0.975');
    expect(md).toContain('**KEV:** yes');
    expect(md).toContain('known ransomware use');
    expect(md).toContain('**SSVC (computed):** act');
  });

  it('renders CISA published SSVC when present, and a clear absence when not', () => {
    expect(dossierToMarkdown(emptyDossier())).toContain('**SSVC (CISA published):** not published');

    const withCisa = emptyDossier({
      cisaSsvc: {
        cveId: 'CVE-2021-44228',
        exploitation: 'active',
        automatable: 'yes',
        technicalImpact: 'total',
        decision: 'Act',
        decisionRange: ['Act'],
        assumedMissionWellbeing: 'medium',
        role: 'CISA Coordinator',
        version: '2.0.3',
        timestamp: '',
      },
    });
    const md = dossierToMarkdown(withCisa);
    expect(md).toContain('**SSVC (CISA published):** Act');
    expect(md).toContain('Exploitation active');
  });

  it('prints "None found" for every empty aggregate section', () => {
    const md = dossierToMarkdown(emptyDossier());
    expect(md).toContain('## Mapped ATT&CK techniques\nNone found.');
    expect(md).toContain('## Threat actors using these techniques\nNone found.');
    expect(md).toContain('## F3 Fraud Framework overlap\nNone found.');
    expect(md).toContain('## Security controls\nNone found.');
  });

  it('renders populated sections with ids, names and counts', () => {
    const md = dossierToMarkdown(
      emptyDossier({
        techniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application', tier: 'exploitation', tactics: ['initial access'] }],
        cwes: [{ id: 'CWE-502', name: 'Deserialization of Untrusted Data', url: 'https://cwe' }],
        controlFrameworks: [{ framework: 'CRI Profile', source: 'CRI', items: [{ id: 'PR.AC-1', name: 'Identities verified', detail: 'Protect', url: 'https://cri' }] }],
        threatActors: { groups: [{ id: 'G0016', name: 'APT29', url: 'https://g' }], software: [], campaigns: [] },
        f3: { techniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application', url: 'https://f3' }] },
        detection: [{ techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', notes: [], dataComponents: ['Network Traffic'], sigmaRuleCount: 3, atomicTestCount: 2, carAnalyticCount: 1, queries: [] }],
      }),
    );
    expect(md).toContain('### Exploitation');
    expect(md).toContain('- T1190 Exploit Public-Facing Application [initial access]');
    expect(md).toContain('- CWE-502 Deserialization of Untrusted Data');
    expect(md).toContain('### CRI Profile (1)');
    expect(md).toContain('- PR.AC-1 Identities verified — Protect');
    expect(md).toContain('### Groups (1)');
    expect(md).toContain('- G0016 APT29');
    expect(md).toContain('3 Sigma · 2 Atomic · 1 CAR');
  });

  it('always lists the data sources and inferred-mapping caveat', () => {
    const md = dossierToMarkdown(emptyDossier());
    expect(md).toContain('## Data sources & caveats');
    expect(md).toContain('CISA KEV & SSVC');
    expect(md).toContain('inferred links');
  });
});

describe('dossierToJson', () => {
  it('is valid, round-trippable JSON of the dossier', () => {
    const d = emptyDossier();
    const parsed = JSON.parse(dossierToJson(d));
    expect(parsed.cveId).toBe('CVE-2021-44228');
    expect(parsed.threatActors.groups).toEqual([]);
  });
});
