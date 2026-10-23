// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F decision 41: the Validation pill, the Proven block and the Covered block describe
// the SAME run, the latest by the one latest-run comparator (decision 24: on the same
// instant the run that proves less first, then by id), and the other runs of that day are
// named by count and status. Round 8 (letter G, T1005) found the pill on the untested
// deployed run ("UNTESTED 0 of 1") while the Proven block said "1 rule fired in the
// range run (status partial)" and the Covered block listed the partial run's telemetry row.
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ValidationStatusPillComponent } from '../components/validation-status-pill/validation-status-pill.component';
import { ValidationService } from '../services/validation.service';
import { DataService, type AttackDomain } from '../services/data.service';
import { runInputsFor } from '../services/posture-adapters';
import { DEFAULT_POSTURE_RULES, derivePosture } from '../models/posture/derive-posture';
import type { PostureState, RunSummary } from '../models/posture/posture.types';
import { provenNoneCellWords, provenNoneLine } from '../models/posture/proof-gap';
import { writeV2 } from '../models/storage-envelope';
import { rpf8Runs } from './rpf8-shapes';

const KEY = 'navi.v2.validation-runs';
const NOW = new Date(2026, 9, 23, 12);
const fakeData = {
  getCurrentDomain: (): unknown => null,
  getCurrentAttackDomain: (): AttackDomain => 'enterprise',
};

describe('RP-F decision 41: one run on every surface', () => {
  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({ providers: [provideRouter([]), { provide: DataService, useValue: fakeData }] });
  });
  afterEach(() => localStorage.clear());

  function pill(attackId: string): { status: string; meta: string } {
    const fixture = TestBed.createComponent(ValidationStatusPillComponent);
    fixture.componentInstance.attackId = attackId;
    fixture.componentInstance.ngOnChanges({});
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const text = (sel: string) => (el.querySelector(sel)?.textContent ?? '').replace(/\s+/g, ' ').trim();
    return { status: text('.vsp-status'), meta: text('.vsp-meta') };
  }

  function derive(attackId: string): PostureState {
    const runs = TestBed.inject(ValidationService).forTechnique(attackId);
    const inputs = runInputsFor(runs);
    return derivePosture(`attack/enterprise/${attackId}@19.2`, {
      knownSignals: 2, threatWeight: 1, exposureWeight: 0,
      covered: inputs.flatMap(i => i.covered), proof: inputs.flatMap(i => i.proof),
      verdicts: inputs.flatMap(i => i.verdicts), runs: inputs.map(i => i.summary),
    }, DEFAULT_POSTURE_RULES, NOW);
  }

  it('T1005 (wazuh:207 telemetry alerted and deployed none, same day): the pill, the Proven block and the Covered block name the untested deployed run; the partial run is counted', () => {
    writeV2(KEY, { schema: 2, tombstones: [], records: rpf8Runs().get('T1005')! as never[] });
    const service = TestBed.inject(ValidationService);
    const latest = service.latestFor('T1005')!;
    expect(latest.status).toBe('untested');
    expect(latest.outcomes.map(o => o.coverageState)).toEqual(['deployed']);

    // The pill: the deployed run.
    expect(pill('T1005')).toEqual({ status: 'UNTESTED', meta: '0 of 1 expected rules fired' });

    const s = derive('T1005');
    // The Proven block: the same run and status, then the other run of the day by count and status.
    expect(s.runsWithoutProof[0].runId).toBe(latest.id);
    expect(provenNoneLine(s)).toBe(
      'No proof: no rule fired in the range run on 10/21/26 (status untested); '
      + 'and 1 more run the same day: partial (1 rule fired); a run is proof only when its status is passed');
    expect(provenNoneCellWords(s)).toBe(
      'no proof, no rule fired in the range run on 10/21/26 (status untested), and 1 more run the same day: partial (1 rule fired)');
    // The Covered block: the deployed run's mark only; the partial run's telemetry row of the
    // same rule is superseded by it (decision 40), so no block names the partial run as current.
    expect(s.covered.map(m => [m.basis, m.via, m.at])).toEqual([['range-deployed', 'wazuh:207', latest.runDate]]);
    expect(s.bucket).toBe('covered');
  });

  it('the same-day note counts every other run of the day; an older fired run is named as earlier', () => {
    const run = (runId: string, status: string, date: string, rulesFired: number): RunSummary =>
      ({ runId, status, date, source: 'manual', rulesFired, rules: ['siem:a'] });
    const twoMore = { runsWithoutProof: [run('c', 'failed', '2026-10-21', 0), run('a', 'untested', '2026-10-21', 1), run('b', 'partial', '2026-10-21', 0)] };
    expect(provenNoneLine(twoMore)).toBe(
      'No proof: no rule fired in your run on 10/21/26 (status failed); and 2 more runs the same day: untested (1 rule fired), partial; '
      + 'a run is proof only when its status is passed');
    const earlier = { runsWithoutProof: [run('c', 'failed', '2026-10-21', 0), run('a', 'untested', '2026-10-15', 2)] };
    expect(provenNoneLine(earlier)).toBe(
      'No proof: no rule fired in your run on 10/21/26 (status failed); earlier, 2 rules fired in your run on 10/15/26 (status untested); '
      + 'a run is proof only when its status is passed');
    expect(provenNoneLine({ runsWithoutProof: [run('c', 'failed', '2026-10-21', 0)] })).toBe('No recorded detection for this technique');
  });
});
