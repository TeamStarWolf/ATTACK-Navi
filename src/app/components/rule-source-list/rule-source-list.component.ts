// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// One rule source in the technique drawer's Rule sources section: the rules a public
// repository holds for the open technique at the commit the bundled rule-coverage
// snapshot pins (src/assets/data/rule-coverage-snapshot.json, built from the rule
// bodies by scripts/build-rule-coverage-snapshot.mjs). The drawer renders one of these
// per source (Elastic detection-rules, Splunk security_content, mdecrevoisier SIGMA)
// from ruleSourceView(); this component only presents it. A rule listed here exists in
// a public repository: it is reference data, not a rule running anywhere.
import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { DrawerRowComponent } from '../drawer-primitives';
import {
  type RuleCoverageKey, type RuleCoverageLink, type RuleCoverageSection, ruleLinks,
} from '../../services/rule-coverage-snapshot.service';

/** The drawer's order. */
export const RULE_SOURCE_KEYS: readonly RuleCoverageKey[] = ['elastic', 'splunk', 'mdecrevoisier'];

export const RULE_SOURCE_LABELS: Readonly<Record<RuleCoverageKey, string>> = {
  elastic: 'Elastic detection-rules',
  splunk: 'Splunk security_content',
  mdecrevoisier: 'mdecrevoisier SIGMA',
};

/** What a source with a count of 0 says. */
export const RULE_SOURCE_EMPTY = 'no rules reference this technique at the pinned commit';

/** One source for one technique, as the drawer shows it. */
export interface RuleSourceView {
  key: RuleCoverageKey;
  label: string;
  /** owner/repo; empty when the snapshot did not load. */
  repo: string;
  /** The repository tree at the pinned commit; empty when the snapshot did not load. */
  repoUrl: string;
  /** Rules in the repository naming the technique (a parent counts its sub-techniques' rules too). */
  count: number;
  /** Up to ten of them, each with its permalink at the pinned commit. */
  rules: RuleCoverageLink[];
  /** The pinned commit (40 hex characters); empty when the snapshot did not load. */
  sha: string;
  /** The pinned commit's date, YYYY-MM-DD. */
  commitDate: string;
  /** The date the snapshot was generated. */
  generated: string;
  /** Why the section did not load, or null. */
  error: string | null;
}

/** The view of one snapshot section for one technique. */
export function ruleSourceView(key: RuleCoverageKey, section: RuleCoverageSection, attackId: string): RuleSourceView {
  return {
    key,
    label: RULE_SOURCE_LABELS[key],
    repo: `${section.owner}/${section.repo}`,
    repoUrl: `https://github.com/${section.owner}/${section.repo}/tree/${section.sha}`,
    count: section.techniques[attackId]?.count ?? 0,
    rules: ruleLinks(section, attackId),
    sha: section.sha,
    commitDate: section.commitDate.slice(0, 10),
    generated: section.generated,
    error: null,
  };
}

/** The view of a source whose section did not load: its reason, no count and no rules. */
export function ruleSourceError(key: RuleCoverageKey, err: unknown): RuleSourceView {
  return {
    key, label: RULE_SOURCE_LABELS[key], repo: '', repoUrl: '', count: 0, rules: [], sha: '', commitDate: '', generated: '',
    error: err instanceof Error ? err.message : String(err),
  };
}

@Component({
  selector: 'app-rule-source-list',
  standalone: true,
  imports: [DrawerRowComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './rule-source-list.component.html',
  styleUrl: './rule-source-list.component.scss',
})
export class RuleSourceListComponent {
  readonly source = input.required<RuleSourceView>();
  protected readonly empty = RULE_SOURCE_EMPTY;
}
