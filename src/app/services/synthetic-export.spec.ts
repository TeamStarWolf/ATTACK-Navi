// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Plan epic E1.6 ("Stop shipping broken or misleading output"), PR 1: the
// synthetic Sigma generator and the Zeek package.
//
//   - no export contains 'TODO', and no generated template carries level: high;
//   - every generated Sigma document is a 'Template (not a rule)' at level
//     informational, and uses only fields its logsource has (the old
//     GrantedAccess-under-process_creation patterns are gone);
//   - the Zeek generic stub is excluded from every export;
//   - curated and fetched content is NOT synthetic: real community Sigma rules,
//     the Wazuh stock-rule table and the curated Zeek scripts keep their own
//     titles, levels and bodies.
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import {
  SigmaService,
  SigmaRuleDetail,
  SIGMA_GENERATOR_AUTHOR,
  SIGMA_TEMPLATE_HEADER,
  SIGMA_TEMPLATE_LEVEL,
  SIGMA_TEMPLATE_STATUS,
  SIGMA_TEMPLATE_TITLE_PREFIX,
} from './sigma.service';
import { ZeekService } from './zeek.service';
import { WazuhService } from './wazuh.service';
import { Technique } from '../models/technique';
import { parseFixtureDomain } from '../testing/lens-harness';

function tech(attackId: string, name: string, tactics: string[], platforms: string[] = ['Windows']): Technique {
  return {
    id: `attack-pattern--${attackId}`,
    attackId,
    name,
    description: '',
    url: '',
    tacticShortnames: tactics,
    isSubtechnique: attackId.includes('.'),
    parentId: null,
    subtechniques: [],
    mitigationCount: 0,
    platforms,
    dataSources: [],
    detectionText: '',
    defenseBypassed: [],
    permissionsRequired: [],
    effectivePermissions: [],
    systemRequirements: [],
    impactType: [],
    remoteSupport: false,
    capecIds: [],
  };
}

/** One technique per template pattern, each pattern the generator has. */
const WITH_TEMPLATE: Technique[] = [
  tech('T1059.001', 'PowerShell', ['execution']),
  tech('T1059.003', 'Windows Command Shell', ['execution']),
  tech('T1053.005', 'Scheduled Task', ['execution', 'persistence', 'privilege-escalation']),
  tech('T1547.001', 'Registry Run Keys / Startup Folder', ['persistence', 'privilege-escalation']),
  tech('T1112', 'Modify Registry', ['stealth']),
  tech('T1046', 'Network Service Discovery', ['discovery'], ['Windows', 'Linux', 'macOS']),
  tech('T1566.001', 'Spearphishing Attachment', ['initial-access']),
];

/**
 * Techniques that used to get a synthetic rule and now get none: the two
 * GrantedAccess patterns (credential access, process injection), the generic
 * TODO fallback, and Windows patterns offered for non-Windows techniques.
 */
const WITHOUT_TEMPLATE: Technique[] = [
  tech('T1003.001', 'LSASS Memory', ['credential-access']),
  tech('T1110.003', 'Password Spraying', ['credential-access']),
  tech('T1055', 'Process Injection', ['stealth', 'privilege-escalation']),
  tech('T1055.001', 'Dynamic-link Library Injection', ['stealth', 'privilege-escalation']),
  tech('T1001', 'Data Obfuscation', ['command-and-control']),
  tech('T1095', 'Non-Application Layer Protocol', ['command-and-control']),
  tech('T1547.006', 'Kernel Modules and Extensions', ['persistence', 'privilege-escalation'], ['Linux', 'macOS']),
];

/**
 * Fields each logsource category has (Sysmon process creation, registry value
 * set and network connection events). A template may use only these, both in
 * its detection and in its fields list.
 */
const LOGSOURCE_FIELDS: Record<string, ReadonlySet<string>> = {
  process_creation: new Set(['Image', 'CommandLine', 'ParentImage', 'ParentCommandLine', 'User', 'OriginalFileName', 'CurrentDirectory', 'IntegrityLevel', 'Hashes']),
  registry_set: new Set(['TargetObject', 'Details', 'Image', 'User', 'EventType']),
  network_connection: new Set(['Image', 'User', 'Initiated', 'DestinationIp', 'DestinationPort', 'DestinationHostname', 'SourceIp', 'SourcePort', 'Protocol']),
};

/** Split a Sigma export into its YAML documents (comment-only parts dropped). */
function documents(text: string): string[] {
  return text.split(/^---$/m).map(d => d.trim()).filter(d => /^title:/m.test(d));
}

/** The logsource category, detection field names and fields list of one document. */
function shape(doc: string): { category: string; detectionFields: string[]; fieldsList: string[] } {
  const lines = doc.split('\n');
  const category = (doc.match(/^logsource:\n(?: {2}\w+: .*\n)*? {2}category: (\S+)/m) ?? [])[1] ?? '';
  const detectionFields: string[] = [];
  const fieldsList: string[] = [];
  let section = '';
  for (const line of lines) {
    const top = line.match(/^(\w+):/);
    if (top) { section = top[1]; continue; }
    if (section === 'detection') {
      // Search-identifier maps sit at two spaces; their field names at four.
      const field = line.match(/^ {4}([A-Za-z]+)(?:\|[\w|]+)?:/);
      if (field) detectionFields.push(field[1]);
    } else if (section === 'fields') {
      const item = line.match(/^ {2}- (\S+)/);
      if (item) fieldsList.push(item[1]);
    }
  }
  return { category, detectionFields, fieldsList };
}

describe('synthetic export honesty (E1.6)', () => {
  let sigma: SigmaService;
  let zeek: ZeekService;
  let http: HttpTestingController;
  let everyTechnique: Technique[];

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    sigma = TestBed.inject(SigmaService);
    zeek = TestBed.inject(ZeekService);
    http = TestBed.inject(HttpTestingController);
    // The SigmaHQ coverage layer requested at construction is not under test.
    http.match(() => true);
    // The characterization fixture (a slice of the bundled Enterprise ATT&CK,
    // parsed by the production parser) plus one technique per pattern branch.
    everyTechnique = [...parseFixtureDomain().techniques, ...WITH_TEMPLATE, ...WITHOUT_TEMPLATE];
  });

  afterEach(() => http.verify());

  /** Run an export and return the text of the Blob it downloads. */
  async function downloaded(run: () => void): Promise<{ text: string; filename: string }> {
    let blob: Blob | undefined;
    let filename = '';
    spyOn(URL, 'createObjectURL').and.callFake((b: Blob | MediaSource) => { blob = b as Blob; return 'blob:spec'; });
    spyOn(URL, 'revokeObjectURL');
    spyOn(HTMLAnchorElement.prototype, 'click').and.callFake(function (this: HTMLAnchorElement) { filename = this.download; });
    run();
    expect(blob).withContext('the export created a download').toBeDefined();
    return { text: await blob!.text(), filename };
  }

  describe('Sigma generator', () => {
    it('emits a template for every pattern branch and nothing for the removed ones', () => {
      for (const t of WITH_TEMPLATE) {
        expect(sigma.hasTemplate(t)).withContext(t.attackId).toBeTrue();
        expect(sigma.generateRuleForTechnique(t)).withContext(t.attackId).not.toBeNull();
      }
      for (const t of WITHOUT_TEMPLATE) {
        expect(sigma.hasTemplate(t)).withContext(t.attackId).toBeFalse();
        expect(sigma.generateRuleForTechnique(t)).withContext(t.attackId).toBeNull();
      }
    });

    it('no export contains TODO and no generated template carries level: high', async () => {
      const { text, filename } = await downloaded(() => sigma.exportRules(everyTechnique));
      expect(filename).toMatch(/^sigma-templates-\d{4}-\d{2}-\d{2}\.yml$/);
      expect(text).not.toContain('TODO');
      expect(text).not.toMatch(/^level:\s*high\b/m);
      const levels = text.split('\n').filter(l => l.startsWith('level:'));
      expect(levels.length).toBe(documents(text).length);
      expect(new Set(levels)).toEqual(new Set([`level: ${SIGMA_TEMPLATE_LEVEL}`]));
      expect(SIGMA_TEMPLATE_LEVEL).toBe('informational');
    });

    it('the single-technique export is a labelled template too', async () => {
      const { text, filename } = await downloaded(() => sigma.exportRules([WITH_TEMPLATE[0]]));
      expect(filename).toBe('sigma-template-T1059.001.yml');
      expect(text.startsWith(SIGMA_TEMPLATE_HEADER)).toBeTrue();
      expect(text).toContain(`title: '${SIGMA_TEMPLATE_TITLE_PREFIX}: PowerShell (T1059.001)'`);
      expect(text).not.toContain('TODO');
    });

    it('every generated document is a Template (not a rule): title, description, status, level, author', () => {
      const docs = documents(sigma.generateRulesForTechniques(everyTechnique));
      expect(docs.length).toBe(everyTechnique.filter(t => sigma.hasTemplate(t)).length);
      expect(docs.length).toBeGreaterThanOrEqual(WITH_TEMPLATE.length);
      for (const doc of docs) {
        expect(doc.split('\n').some(l => l.startsWith(`title: '${SIGMA_TEMPLATE_TITLE_PREFIX}: `))).withContext(doc).toBeTrue();
        expect(doc).toMatch(/^description: 'Template \(not a rule\) for ATT&CK technique /m);
        expect(doc).toMatch(new RegExp(`^status: ${SIGMA_TEMPLATE_STATUS}$`, 'm'));
        expect(doc).toMatch(/^level: informational$/m);
        expect(doc).toContain(`author: '${SIGMA_GENERATOR_AUTHOR}'`);
      }
    });

    it('the export says it holds templates and names the techniques without one', () => {
      const text = sigma.generateRulesForTechniques([WITH_TEMPLATE[0], ...WITHOUT_TEMPLATE.slice(0, 3)]);
      expect(text.startsWith(SIGMA_TEMPLATE_HEADER)).toBeTrue();
      expect(SIGMA_TEMPLATE_HEADER).toContain('templates, not rules');
      expect(text).toContain('# No template for 3 of 4 selected techniques: T1003.001, T1110.003, T1055.');
      expect(documents(text).length).toBe(1);
    });

    it('no template matches on GrantedAccess, and every field belongs to its logsource', () => {
      const text = sigma.generateRulesForTechniques(everyTechnique);
      expect(text).not.toContain('GrantedAccess');
      for (const doc of documents(text)) {
        const { category, detectionFields, fieldsList } = shape(doc);
        const allowed = LOGSOURCE_FIELDS[category];
        expect(allowed).withContext(`known logsource category in:\n${doc}`).toBeDefined();
        expect(detectionFields.length).withContext(doc).toBeGreaterThan(0);
        for (const f of [...detectionFields, ...fieldsList]) {
          expect(allowed.has(f)).withContext(`${f} under ${category}`).toBeTrue();
        }
      }
    });

    it('CIDR ranges in the network template carry the cidr modifier', () => {
      const net = sigma.generateRuleForTechnique(WITH_TEMPLATE[5])!.yaml;
      expect(net).toContain('category: network_connection');
      expect(net).toContain('DestinationIp|cidr:');
      expect(net).not.toMatch(/^ {4}DestinationIp:/m);
    });
  });

  describe('Zeek package', () => {
    it('no export contains TODO; the generic stub is gone from every export', async () => {
      const { text } = await downloaded(() => zeek.exportScripts(everyTechnique));
      expect(text).not.toContain('TODO');
      expect(text).not.toContain('Add your detection logic here');
      expect(text).not.toContain('Generic network detection');
      expect(text).not.toMatch(/â€/); // no double-encoded dashes either
      // Network techniques with no curated script get nothing, not a stub.
      for (const t of WITHOUT_TEMPLATE.filter(x => x.tacticShortnames.includes('command-and-control'))) {
        expect(zeek.generateScriptsForTechnique(t)).withContext(t.attackId).toEqual([]);
      }
    });

    it('says how many selected techniques have no curated script', () => {
      const curated = tech('T1071.001', 'Web Protocols', ['command-and-control']);
      const text = zeek.generatePackageForTechniques([curated, ...WITHOUT_TEMPLATE.slice(4, 6)]);
      expect(text).toContain('# No curated script for 2 of 3 selected techniques.');
      expect(zeek.generatePackageForTechniques(WITHOUT_TEMPLATE.slice(4, 6)))
        .toContain('# No Zeek scripts available for selected techniques');
    });
  });

  describe('curated and fetched content is not synthetic', () => {
    it('a real community Sigma rule keeps its own title and level: high', () => {
      let got: SigmaRuleDetail[] | undefined;
      sigma.fetchRulesForTechnique('T1003.001').subscribe(r => (got = r));
      http.expectOne(r => r.url.includes('/git/trees/main')).flush({
        tree: [{ type: 'blob', path: 'windows/credential_access/T1003.001_lsass_access.yml' }],
      });
      http.expectOne(r => r.url.includes('T1003.001_lsass_access.yml')).flush(
        "title: LSASS process memory access\nid: 0d894093-71bc-43c3-8c4d-ecfa28dcadc8\nstatus: stable\n"
        + 'level: high\ndescription: Real rule body from the community repository\n',
      );
      expect(got?.length).toBe(1);
      expect(got![0].title).toBe('LSASS process memory access');
      expect(got![0].level).toBe('high');
      expect(got![0].title.startsWith(SIGMA_TEMPLATE_TITLE_PREFIX)).toBeFalse();
    });

    it('the Wazuh stock-rule table keeps its own levels and is never relabelled as a template', () => {
      const wazuh = TestBed.inject(WazuhService);
      const rootkit = wazuh.getRulesForTechnique('T1014').find(r => r.ruleId === '510');
      expect(rootkit?.level).toBe(12);
      for (const rule of wazuh.getAllRules()) {
        expect(rule.description.startsWith(SIGMA_TEMPLATE_TITLE_PREFIX)).withContext(rule.ruleId).toBeFalse();
      }
    });

    it('curated Zeek scripts still ship whole', () => {
      const [script] = zeek.generateScriptsForTechnique(tech('T1071.001', 'Web Protocols', ['command-and-control']));
      expect(script.filename).toBe('detect-http-c2.zeek');
      expect(script.script).toContain('@load base/protocols/http');
      expect(script.script).toContain('NOTICE([$note=HTTP_Beaconing_Detected');
      expect(zeek.generatePackageForTechniques([tech('T1071.001', 'Web Protocols', ['command-and-control'])]))
        .toContain('module ATT_CK_T1071_001;');
    });
  });
});
