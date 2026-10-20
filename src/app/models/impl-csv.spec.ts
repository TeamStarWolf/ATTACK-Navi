// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { previewStatusCsv, TECHNIQUE_ID_REASON } from './impl-csv';
import { csvRow } from '../utils/csv';
import { Domain } from './domain';
import { Mitigation } from './mitigation';

function mit(id: string, attackId: string, name = `mit-${attackId}`): Mitigation {
  return { id, attackId, name, description: '', url: '' };
}
function domainWith(mits: Mitigation[]): Domain {
  return { name: 'Enterprise ATT&CK', mitigations: mits, techniquesByMitigation: new Map() } as unknown as Domain;
}

// M1036 and M1015 are real Enterprise mitigation ATT&CK ids; the STIX ids are fixtures.
const DOMAIN = domainWith([
  mit('course-of-action--aaa', 'M1036', 'Account Use Policies'),
  mit('course-of-action--bbb', 'M1015', 'Active Directory Configuration'),
]);

// The two headers the app's own exports write, verbatim:
//  - settings-panel.component.ts:386 (Export Implementation CSV)
//  - export-actions.service.ts:95   (Implementation Plan)
const SETTINGS_HEADER = 'Mitigation ID,Mitigation Name,Status,Mapped Techniques';
const PLAN_HEADER = 'Mitigation ID,Mitigation Name,Status,Owner,Target Date,Security Controls,Evidence URL,Mapped Techniques,Unique Coverage,Notes';

describe('impl-csv previewStatusCsv', () => {
  it('accepts the mitigation_id,status header and resolves an Mxxxx id', () => {
    const p = previewStatusCsv('mitigation_id,status\nM1036,implemented', DOMAIN);
    expect(p.matched).toEqual([{ mitStixId: 'course-of-action--aaa', status: 'implemented' }]);
    expect(p.unmatched.length).toBe(0);
    expect(p.errors).toBe(0);
  });

  it('accepts the legacy technique_id,status header (an Mxxxx in it still resolves)', () => {
    const p = previewStatusCsv('technique_id,status\nM1015,planned', DOMAIN);
    expect(p.matched).toEqual([{ mitStixId: 'course-of-action--bbb', status: 'planned' }]);
  });

  it('accepts the settings-panel export header and skips not-tracked rows', () => {
    const text = [
      SETTINGS_HEADER,
      csvRow(['M1036', 'Account Use Policies', 'implemented', 2]),
      csvRow(['M1015', 'Active Directory Configuration', 'not-tracked', 0]),
    ].join('\n');
    const p = previewStatusCsv(text, DOMAIN);
    expect(p.matched).toEqual([{ mitStixId: 'course-of-action--aaa', status: 'implemented' }]);
    expect(p.unmatched.length).toBe(0);   // not-tracked is skipped, not unmatched
    expect(p.errors).toBe(0);
  });

  it('accepts the export-actions implementation-plan header', () => {
    const text = [
      PLAN_HEADER,
      csvRow(['M1036', 'Account Use Policies', 'planned', '', '', '', '', 3, 1, '']),
    ].join('\n');
    const p = previewStatusCsv(text, DOMAIN);
    expect(p.matched).toEqual([{ mitStixId: 'course-of-action--aaa', status: 'planned' }]);
  });

  it('keeps columns aligned when a quoted name contains a comma (RFC-4180)', () => {
    const text = [
      SETTINGS_HEADER,
      csvRow(['M1036', 'Policies, strict and long', 'implemented', 2]),
    ].join('\n');
    const p = previewStatusCsv(text, DOMAIN);
    expect(p.matched).toEqual([{ mitStixId: 'course-of-action--aaa', status: 'implemented' }]);
    expect(p.errors).toBe(0);
  });

  it('un-doubles quotes inside a quoted field', () => {
    const text = `${SETTINGS_HEADER}\n${csvRow(['M1036', 'a "quoted" name', 'in-progress', 1])}`;
    const p = previewStatusCsv(text, DOMAIN);
    expect(p.matched).toEqual([{ mitStixId: 'course-of-action--aaa', status: 'in-progress' }]);
  });

  it('reports technique ids as unmatched with the exact reason', () => {
    const p = previewStatusCsv('mitigation_id,status\nT1059,implemented\nT1059.001,planned', DOMAIN);
    expect(p.matched.length).toBe(0);
    expect(p.unmatched).toEqual([
      { row: 2, id: 'T1059', reason: TECHNIQUE_ID_REASON },
      { row: 3, id: 'T1059.001', reason: TECHNIQUE_ID_REASON },
    ]);
    expect(p.errors).toBe(0);
  });

  it('reports an Mxxxx not in the domain as unmatched, not matched', () => {
    const p = previewStatusCsv('mitigation_id,status\nM9999,implemented', DOMAIN);
    expect(p.matched.length).toBe(0);
    expect(p.unmatched.length).toBe(1);
    expect(p.unmatched[0].id).toBe('M9999');
  });

  it('passes a STIX mitigation id through when it exists in the domain', () => {
    const p = previewStatusCsv('mitigation_id,status\ncourse-of-action--aaa,in-progress', DOMAIN);
    expect(p.matched).toEqual([{ mitStixId: 'course-of-action--aaa', status: 'in-progress' }]);
  });

  it('counts a malformed status and a missing id as errors', () => {
    const p = previewStatusCsv('mitigation_id,status\nM1036,bogus\n,implemented', DOMAIN);
    expect(p.matched.length).toBe(0);
    expect(p.errors).toBe(2);
  });

  it('treats an unrecognised header as an unusable file (data rows counted as errors)', () => {
    const p = previewStatusCsv('foo,bar\nM1036,implemented', DOMAIN);
    expect(p.matched.length).toBe(0);
    expect(p.errors).toBe(1);
  });

  it('handles CRLF line endings', () => {
    const p = previewStatusCsv('mitigation_id,status\r\nM1036,implemented\r\n', DOMAIN);
    expect(p.matched).toEqual([{ mitStixId: 'course-of-action--aaa', status: 'implemented' }]);
  });

  it('is case-insensitive on the Mxxxx id and the status', () => {
    const p = previewStatusCsv('mitigation_id,status\nm1036,IMPLEMENTED', DOMAIN);
    expect(p.matched).toEqual([{ mitStixId: 'course-of-action--aaa', status: 'implemented' }]);
  });
});
