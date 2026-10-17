// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Plan P1 row E1.6 fixes the double-encoded mojibake at cve-panel.component.html:505.
// The same defect (UTF-8 decoded as Windows-1252 and saved again) sat in strings the
// app exports: every SIEM query-library header, the Suricata rule export and the
// Windows event-logging script. These cases generate each export and check its text.
import { TestBed } from '@angular/core/testing';
import { CARService } from '../services/car.service';
import { SiemExportComponent } from '../components/siem-export/siem-export.component';
import { SuricataService } from '../services/suricata.service';
import { EventLoggingService, TECHNIQUE_TO_LOGGING } from '../services/event-logging.service';
import { Technique } from '../models/technique';
import { parseFixtureDomain } from './lens-harness';

/** UTF-8 read as Windows-1252 or Latin-1, or a character already lost (U+FFFD). */
const MOJIBAKE = /\u00e2[\u0080-\u00bf\u0152\u0153\u20ac\u2018-\u201e\u2122]|[\u00c3\u00c2][\u0080-\u00bf]|\u00f0\u0178|\ufffd/;

describe('exported text carries no double-encoded characters (E1.6)', () => {
  it('the SIEM query-library exports (Splunk, Sentinel, Elastic)', () => {
    const analytics = (Object.create(CARService.prototype) as CARService).getAll();
    expect(analytics.length).toBeGreaterThan(10);
    // The query builders read only the loaded domain (for tactic tags), so the component
    // is used without its template.
    const domain = parseFixtureDomain();
    const siem = Object.assign(Object.create(SiemExportComponent.prototype), { domain, techniques: domain.techniques }) as SiemExportComponent;
    for (const [name, text] of [
      ['Splunk', siem.buildSplunkExport(analytics)],
      ['Sentinel', siem.buildSentinelExport(analytics)],
      ['Elastic', siem.buildElasticExport(analytics)],
    ] as const) {
      expect(text.match(MOJIBAKE)).withContext(name).toBeNull();
      expect(text).withContext(name).toContain('MITRE ATT&CK CAR Analytics \u2014 ');
    }
  });

  it('the Suricata rule export', () => {
    const suricata = new SuricataService();
    const domain = parseFixtureDomain();
    const supported = new Set(suricata.getSupportedTechniqueIds());
    const techniques: Technique[] = [
      ...domain.techniques,
      ...[...supported].map(attackId => ({ ...domain.techniques[0], attackId, name: attackId })),
    ];
    const text = suricata.generateRulesForTechniques(techniques);
    expect(text.match(MOJIBAKE)).toBeNull();
    expect(text).toContain('# Suricata IDS Rules \u2014 MITRE ATT&CK');
  });

  it('the Windows event-logging script', () => {
    const text = TestBed.inject(EventLoggingService).generateScript(Object.keys(TECHNIQUE_TO_LOGGING));
    expect(text.match(MOJIBAKE)).toBeNull();
    expect(text).toMatch(/^# \u2500\u2500 T\d{4}/m);
  });
});
