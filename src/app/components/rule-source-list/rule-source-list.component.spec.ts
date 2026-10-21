// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import {
  RULE_SOURCE_EMPTY, RULE_SOURCE_KEYS, RuleSourceListComponent, type RuleSourceView, ruleSourceError, ruleSourceView,
} from './rule-source-list.component';
import type { RuleCoverageKey, RuleCoverageSection } from '../../services/rule-coverage-snapshot.service';
import { RULE_COVERAGE_FIXTURE } from '../../testing/rule-coverage-fixture';

const section = (key: RuleCoverageKey): RuleCoverageSection =>
  ({ ...RULE_COVERAGE_FIXTURE.sources[key], generated: RULE_COVERAGE_FIXTURE.generated });

describe('ruleSourceView', () => {
  it('reads the count, the rules with permalinks and the pin from one section', () => {
    const v = ruleSourceView('splunk', section('splunk'), 'T1560.001');
    expect(v.label).toBe('Splunk security_content');
    expect(v.repo).toBe('splunk/security_content');
    expect(v.repoUrl).toBe('https://github.com/splunk/security_content/tree/678e76c5f36f6fadd93a1eaa0d82c1dbe273c486');
    expect(v.count).toBe(4);
    expect(v.rules.map(r => r.name)).toEqual(['7zip CommandLine To SMB Share Path', 'Anomalous usage of 7zip']);
    expect(v.rules[1].url).toBe('https://github.com/splunk/security_content/blob/678e76c5f36f6fadd93a1eaa0d82c1dbe273c486/'
      + 'detections/endpoint/anomalous_usage_of_7zip.yml');
    expect(v.sha).toBe('678e76c5f36f6fadd93a1eaa0d82c1dbe273c486');
    expect(v.commitDate).toBe('2026-10-20');
    expect(v.generated).toBe('2026-10-21');
    expect(v.error).toBeNull();
  });

  it('a technique the section does not name has count 0 and no rules', () => {
    const v = ruleSourceView('elastic', section('elastic'), 'T9999');
    expect(v.count).toBe(0);
    expect(v.rules).toEqual([]);
    expect(v.sha).toBe('7115bb0ab06c11c7994486ffe2bc0dc801ad8502');
  });

  it('a section that did not load keeps its reason and claims nothing', () => {
    const v = ruleSourceError('mdecrevoisier', new Error('bundled snapshot missing (not in this build)'));
    expect(v).toEqual(jasmine.objectContaining({
      key: 'mdecrevoisier', label: 'mdecrevoisier SIGMA', count: 0, rules: [], sha: '', repoUrl: '',
      error: 'bundled snapshot missing (not in this build)',
    }));
    expect(ruleSourceError('elastic', 'plain').error).toBe('plain');
  });

  it('the drawer order is Elastic, Splunk, mdecrevoisier', () => {
    expect([...RULE_SOURCE_KEYS]).toEqual(['elastic', 'splunk', 'mdecrevoisier']);
  });
});

describe('RuleSourceListComponent', () => {
  function render(view: RuleSourceView): HTMLElement {
    TestBed.configureTestingModule({ imports: [RuleSourceListComponent] });
    const f = TestBed.createComponent(RuleSourceListComponent);
    f.componentRef.setInput('source', view);
    f.detectChanges();
    return f.nativeElement as HTMLElement;
  }
  const text = (el: Element | null) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();

  it('lists each rule name as a link to its permalink, with the count and the provenance line', () => {
    const el = render(ruleSourceView('mdecrevoisier', section('mdecrevoisier'), 'T1059.001'));
    expect(text(el.querySelector('.rs-label'))).toBe('mdecrevoisier SIGMA');
    expect(text(el.querySelector('[data-testid="rule-source-count"]'))).toBe('4 rules');
    const links = [...el.querySelectorAll<HTMLAnchorElement>('a.rs-rule')];
    expect(links.map(a => text(a))).toEqual(['Encoded PowerShell payload deployed (PowerShell)', 'Payload downloaded via PowerShell']);
    expect(links[1].getAttribute('href')).toBe('https://github.com/mdecrevoisier/SIGMA-detection-rules/blob/'
      + 'd61408af8769c74c96296b7ccc92d4bc3abb15af/windows-os/win-os-payload%20download%20(PowerShell).yaml');
    expect(text(el)).toContain('2 of 4 listed by name');
    expect(text(el.querySelector('[data-testid="rule-source-provenance"]')))
      .toBe('Pinned mdecrevoisier/SIGMA-detection-rules@d61408a, commit 2026-05-20; snapshot 2026-10-21');
    expect(el.querySelector('[data-testid="rule-source-empty"]')).toBeNull();
  });

  it('one rule: singular, and no "of" note when every rule is listed', () => {
    const el = render(ruleSourceView('mdecrevoisier', section('mdecrevoisier'), 'T1484.002'));
    expect(text(el.querySelector('[data-testid="rule-source-count"]'))).toBe('1 rule');
    expect(text(el)).not.toContain('listed by name');
  });

  it('count 0: the honest empty state and the pin it was read at', () => {
    const el = render(ruleSourceView('splunk', section('splunk'), 'T1114'));
    expect(text(el.querySelector('[data-testid="rule-source-count"]'))).toBe('0 rules');
    expect(text(el.querySelector('[data-testid="rule-source-empty"]'))).toBe(RULE_SOURCE_EMPTY);
    expect(el.querySelectorAll('a.rs-rule').length).toBe(0);
    expect(text(el.querySelector('[data-testid="rule-source-provenance"]'))).toContain('splunk/security_content@678e76c');
  });

  it('not loaded: the reason, no count, no empty state and no provenance line', () => {
    const el = render(ruleSourceError('elastic', new Error('bundled snapshot missing (not in this build (HTTP 404))')));
    expect(text(el.querySelector('[data-testid="rule-source-error"]'))).toBe('Not loaded: bundled snapshot missing (not in this build (HTTP 404))');
    expect(el.querySelector('[data-testid="rule-source-count"]')).toBeNull();
    expect(el.querySelector('[data-testid="rule-source-empty"]')).toBeNull();
    expect(el.querySelector('[data-testid="rule-source-provenance"]')).toBeNull();
  });
});
