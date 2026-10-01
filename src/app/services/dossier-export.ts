// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { CveDossier, DossierNamed, DossierTechnique, TIER_LABEL, TIER_ORDER } from '../models/dossier';

/**
 * Render an assembled dossier as analyst-ready Markdown for pasting into a report.
 *
 * Pure and guarded: every section tolerates empty/missing data and prints "None found"
 * rather than being omitted silently or throwing, so the shape of the output is stable
 * regardless of how much the assembly could establish.
 */
export function dossierToMarkdown(d: CveDossier): string {
  const L: string[] = [];
  const line = (s = '') => L.push(s);

  line(`# ${d.cveId} — CVE Enrichment Dossier`);
  line();
  line(
    `> ${d.source === 'asset' ? 'Generated dossier' : 'Composed live from loaded data'}` +
      `${d.attackVersion ? ` · ATT&CK v${d.attackVersion}` : ''}` +
      `${d.generated ? ` · generated ${d.generated}` : ''}`,
  );
  line();

  // ── Summary ────────────────────────────────────────────────────────────────
  line('## Summary');
  if (d.cvssScore !== null) line(`- **CVSS:** ${d.cvssScore} ${d.severity}${d.cvssVector ? ` (${d.cvssVector})` : ''}`);
  if (d.epss !== null) {
    const pct = d.epssPercentile !== null ? ` (p${Math.round(d.epssPercentile * 100)})` : '';
    line(`- **EPSS:** ${d.epss}${pct}`);
  }
  line(
    `- **KEV:** ${d.isKev ? 'yes' : 'no'}` +
      (d.isKev
        ? `${d.kevDateAdded ? `, added ${d.kevDateAdded}` : ''}` +
          `${d.kevDueDate ? `, CISA due ${d.kevDueDate}` : ''}` +
          `${d.kevRansomware ? ', known ransomware use' : ''}`
        : ''),
  );
  if (d.cisaSsvc) {
    const s = d.cisaSsvc;
    const range = s.decisionRange.length > 1 ? ` (range ${s.decisionRange.join('→')}, assumes M&W ${s.assumedMissionWellbeing})` : '';
    line(
      `- **SSVC (CISA published):** ${s.decision}${range} — ` +
        `Exploitation ${s.exploitation} · Automatable ${s.automatable} · Technical impact ${s.technicalImpact}`,
    );
  } else {
    line('- **SSVC (CISA published):** not published by CISA for this CVE');
  }
  if (d.ssvc) {
    line(`- **SSVC (computed):** ${d.ssvc.action}${d.ssvc.timeline ? ` — ${d.ssvc.timeline}` : ''}`);
  }
  if (d.description) {
    line();
    line(d.description);
  }
  line();

  // ── Techniques ───────────────────────────────────────────────────────────────
  line('## Mapped ATT&CK techniques');
  if (d.techniques.length === 0) {
    line('None found.');
  } else {
    for (const tier of TIER_ORDER) {
      const items = d.techniques.filter(t => t.tier === tier);
      if (items.length === 0) continue;
      line();
      line(`### ${TIER_LABEL[tier]}`);
      for (const t of items) line(technique(t));
    }
  }
  line();

  section(line, 'Root cause (CWE)', d.cwes);
  section(line, 'Attack patterns (CAPEC)', d.capecs);
  section(line, 'Mitigations (ATT&CK)', d.mitigations);
  section(
    line,
    'Defensive countermeasures (D3FEND)',
    d.countermeasures.map(c => ({ id: c.id, name: c.name })),
  );
  section(line, 'Adversary engagement (MITRE Engage)', d.engage);

  // ── Detection ────────────────────────────────────────────────────────────────
  line('## Detection');
  if (d.detection.length === 0) {
    line('None found.');
  } else {
    for (const det of d.detection) {
      const counts = [
        det.sigmaRuleCount ? `${det.sigmaRuleCount} Sigma` : '',
        det.atomicTestCount ? `${det.atomicTestCount} Atomic` : '',
        det.carAnalyticCount ? `${det.carAnalyticCount} CAR` : '',
      ]
        .filter(Boolean)
        .join(' · ');
      line(`- **${det.techniqueId}** ${det.techniqueName}${counts ? ` — ${counts}` : ''}`);
      if (det.dataComponents.length) line(`  - Data components: ${det.dataComponents.join(', ')}`);
    }
  }
  line();

  // ── Controls ─────────────────────────────────────────────────────────────────
  line('## Security controls');
  if (d.controlFrameworks.length === 0) {
    line('None found.');
  } else {
    for (const fw of d.controlFrameworks) {
      line();
      line(`### ${fw.framework} (${fw.items.length})`);
      for (const c of fw.items) line(named(c));
    }
  }
  line();

  // ── Threat actors ────────────────────────────────────────────────────────────
  line('## Threat actors using these techniques');
  const { groups, software, campaigns } = d.threatActors;
  if (groups.length === 0 && software.length === 0 && campaigns.length === 0) {
    line('None found.');
  } else {
    if (groups.length) {
      line();
      line(`### Groups (${groups.length})`);
      for (const g of groups) line(named(g));
    }
    if (software.length) {
      line();
      line(`### Software (${software.length})`);
      for (const s of software) line(named(s));
    }
    if (campaigns.length) {
      line();
      line(`### Campaigns (${campaigns.length})`);
      for (const c of campaigns) line(named(c));
    }
  }
  line();

  // ── F3 Fraud ─────────────────────────────────────────────────────────────────
  line('## F3 Fraud Framework overlap');
  if (d.f3.techniques.length === 0) {
    line('None found.');
  } else {
    for (const t of d.f3.techniques) line(`- ${t.id} ${t.name}${t.url ? ` (${t.url})` : ''}`);
  }
  line();

  // ── Exploit evidence ───────────────────────────────────────────────────────────
  line('## Exploit evidence');
  const ex = d.exploits;
  const hasExploit =
    ex.hasPoc || ex.exploitDb.length > 0 || ex.publicPocs.length > 0 || ex.exploitTaggedRefs.length > 0;
  if (!hasExploit) {
    line('None found.');
  } else {
    if (ex.hasPoc) line(`- Proof-of-concept available${ex.pocUrl ? ` (${ex.pocUrl})` : ''}`);
    for (const e of ex.exploitDb) line(`- Exploit-DB ${e.id}: ${e.title} (${e.url})`);
    for (const p of ex.publicPocs) line(`- PoC repo: ${p.repo} (${p.url})`);
    for (const r of ex.exploitTaggedRefs) line(`- NVD exploit ref: ${r}`);
  }
  line();

  // ── Attribution ──────────────────────────────────────────────────────────────
  line('## Data sources & caveats');
  line(
    '- Sources: MITRE ATT&CK, D3FEND, CAPEC, CWE, Engage; CISA KEV & SSVC; FIRST EPSS; ' +
      'CTID (CVE→ATT&CK, control-framework & F3 Fraud mappings).',
  );
  line(
    '- Mappings include inferred links: "weakness-class" techniques are derived from the ' +
      "CVE's CWEs via CAPEC and describe the weakness class, not this CVE specifically. " +
      'Confidence is shown by tier.',
  );
  line('- Nothing here is generated by a language model.');
  for (const w of d.warnings) line(`- ${w}`);
  line();

  return L.join('\n');
}

/** Pretty-printed JSON of the full assembled dossier. */
export function dossierToJson(d: CveDossier): string {
  return JSON.stringify(d, null, 2);
}

function section(line: (s?: string) => void, title: string, items: DossierNamed[]): void {
  line(`## ${title}`);
  if (items.length === 0) {
    line('None found.');
  } else {
    for (const it of items) line(named(it));
  }
  line();
}

function named(it: DossierNamed): string {
  const name = it.name ? ` ${it.name}` : '';
  const detail = it.detail ? ` — ${it.detail}` : '';
  const url = it.url ? ` (${it.url})` : '';
  return `- ${it.id}${name}${detail}${url}`;
}

function technique(t: DossierTechnique): string {
  const tactics = t.tactics.length ? ` [${t.tactics.join(', ')}]` : '';
  const retired = t.supersedes ? ` (replaces retired ${t.supersedes})` : '';
  const unresolved = t.unresolved ? ' (not in loaded ATT&CK release)' : '';
  return `- ${t.id} ${t.name || t.id}${tactics}${retired}${unresolved}`;
}
