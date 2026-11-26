// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The Live Defense "brain" (Live Defense slice, first vertical slice of the
// sourced-matrix vision). It turns the bundled CISA KEV snapshot into two
// shipped, dated artifacts keyed by ATT&CK techniqueID:
//
//   src/assets/data/live-defense/live-defense.layer.json
//       a standard ATT&CK Navigator layer (techniques:[{techniqueID,score,
//       color,comment}]) so it renders through the EXISTING lens engine with
//       no new render code, as the "Live Defense" lens.
//   src/assets/data/live-defense/live-defense.evidence.json
//       the cell-detail panel's fuel: per technique the heat, its breakdown,
//       a plain-language cite-or-abstain brief, and the sourced KEV items
//       (cve, source, url, dateAdded, confidence, quote) behind the colour.
//
// MAPPING (bias correctness over coverage, fail quiet, source hard):
//   Each KEV CVE is mapped to ATT&CK technique(s) by the EXPLOITATION NATURE of
//   its weakness, using ONLY the project-authored CWE->ATT&CK exploitation
//   anchor (src/assets/data/cwe-exploitation-anchor.json, MIT) over the CVE's
//   own CWEs from the KEV catalog (CC0). This is the high-confidence tier the
//   runtime cve.service and build-cve-technique-map.mjs already use; the
//   low-confidence CWE->CAPEC->ATT&CK fan-out (Galeax/CVE2CAPEC, GPL-3.0) is
//   DELIBERATELY NOT consulted here, so this slice adds no GPL surface and
//   every heated technique is a defensible, sourced exploitation mapping. A KEV
//   CVE whose weakness anchors no technique does not heat anything (fail quiet).
//
// HEAT = sum over a technique's KEV CVEs of recency * severity, where
//   recency = 0.5 ^ (ageDays / HALF_LIFE_DAYS)   (a half-life decay; an old
//             KEV entry fades, a fresh one dominates — the matrix senses the
//             CURRENT landscape), ageDays measured from the KEV snapshot date
//             (NOT wall-clock) so the artifact is fully reproducible;
//   severity = 1 + RANSOM_BONUS when CISA marks known ransomware use, else 1.
// The per-technique 0-100 score is the share of the highest technique's heat.
//
// DETERMINISTIC + OFFLINE: the only inputs are three committed assets, and heat
// is measured against the snapshot date, so a regeneration is byte-identical.
// `--check` reproduces and compares, writing nothing (the CI gate). Freshness is
// build-kev-snapshot.mjs's job: move the KEV pin, then re-run this.
//
//   node scripts/build-live-defense.mjs            regenerate both artifacts
//   node scripts/build-live-defense.mjs --check    reproduce and compare (exit 1 on drift)
//
// Requires Node 20+. No network, no shell commands: it reads, maps, gates and writes.

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// The truth-vocab lint pulls in the TypeScript compiler, a dev dependency. Load it
// lazily so this script also runs with only Node's built-ins (the scheduled refresh
// needs no npm ci, so no third-party lifecycle script runs in the data path): the
// brief lint is applied when it is available, and ci.yml always runs with deps, so
// the full gate — truth-vocab included — gates every pull request.
async function loadLint() {
  try {
    return (await import('./lint-truth-vocab.mjs')).lintText;
  } catch {
    return null;
  }
}

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const KEV = 'src/assets/data/kev-snapshot.json';
const ANCHOR = 'src/assets/data/cwe-exploitation-anchor.json';
const BUNDLE = 'src/assets/data/enterprise-attack.json';
const OUT_DIR = 'src/assets/data/live-defense';
const OUT_LAYER = `${OUT_DIR}/live-defense.layer.json`;
const OUT_EVIDENCE = `${OUT_DIR}/live-defense.evidence.json`;

// ── Tunables (recorded in both artifacts' __meta so the numbers are legible) ──
const HALF_LIFE_DAYS = 180;   // a KEV entry's recency weight halves every ~6 months
const RANSOM_BONUS = 0.5;     // CISA "known ransomware campaign use" adds 50%
const ITEMS_PER_TECHNIQUE = 25; // sourced items shown per technique (itemCount is exact)
const DAY_MS = 86_400_000;
const CVE_RE = /^CVE-\d{4}-\d{4,}$/;
const TID_RE = /^T\d{4}(\.\d{3})?$/;

const cweNum = (c) => String(c).replace(/^CWE-/i, '').trim();

// ── ATT&CK bundle: live technique ids, names and enterprise tactics ──────────
function attackIdOf(obj) {
  return (obj.external_references ?? []).find((r) => r.source_name === 'mitre-attack')?.external_id ?? null;
}

/** id -> { name, tactics[] } for every live (non-revoked, non-deprecated) Enterprise technique. */
export function readBundle(bundle) {
  const byId = new Map();
  for (const obj of bundle.objects ?? []) {
    if (obj.type !== 'attack-pattern' || obj.revoked || obj.x_mitre_deprecated) continue;
    const id = attackIdOf(obj);
    if (!id) continue;
    const tactics = (obj.kill_chain_phases ?? [])
      .filter((p) => p.kill_chain_name === 'mitre-attack')
      .map((p) => p.phase_name);
    byId.set(id, { name: obj.name ?? id, tactics: [...new Set(tactics)] });
  }
  return byId;
}

const attackVersionOf = (bundle) =>
  String((bundle.objects ?? []).find((o) => o.type === 'x-mitre-collection')?.x_mitre_version ?? '');

// ── Mapping: KEV CVE -> technique(s), high-confidence anchor only ────────────
//
// Mirrors the HIGH tier of cwe-attack-anchor.ts / build-cve-technique-map.mjs:
// a CWE in an exploitation class contributes that class's techniques (confidence
// "high"); the RCE and remote-access-appliance keyword hints add their techniques
// from the KEV free-text (confidence "medium"), but only once a weakness has
// already anchored the CVE (so a keyword alone never heats a technique). The
// low-confidence CAPEC fan-out is not consulted here.
export function buildAnchor(anchor) {
  const classesByCwe = new Map(); // cwe num -> [{technique, rationale}]
  for (const cls of Object.values(anchor.exploitationClasses ?? {})) {
    for (const cwe of cls.cwes ?? []) {
      const list = classesByCwe.get(cwe) ?? [];
      for (const t of cls.techniques) list.push({ technique: t, rationale: cls.rationale ?? '' });
      classesByCwe.set(cwe, list);
    }
  }
  return {
    classesByCwe,
    rceKeywords: (anchor.rceKeywords ?? []).map((k) => k.toLowerCase()),
    rceTechniques: anchor.rceTechniques ?? [],
    raKeywords: (anchor.remoteAccessApplianceKeywords ?? []).map((k) => k.toLowerCase()),
    raTechniques: anchor.remoteAccessTechniques ?? [],
  };
}

/**
 * Map one KEV entry to techniques. Returns a Map techniqueId -> { confidence,
 * via } where `via` is the quotable rationale for the mapping. Empty when the
 * entry's weakness anchors nothing (the caller then heats nothing: fail quiet).
 */
export function techniquesForKev(entry, anchor) {
  const out = new Map();
  const add = (t, confidence, via) => {
    const prev = out.get(t);
    // "high" beats "medium" if a technique is reached both ways.
    if (!prev || (prev.confidence === 'medium' && confidence === 'high')) out.set(t, { confidence, via });
  };
  for (const raw of entry.cwes ?? []) {
    for (const { technique, rationale } of anchor.classesByCwe.get(cweNum(raw)) ?? []) {
      add(technique, 'high', `CWE-${cweNum(raw)}: ${rationale}`);
    }
  }
  if (out.size === 0) return out; // no weakness anchor: a keyword alone never heats
  const text = `${entry.vulnerabilityName ?? ''} ${entry.vendorProject ?? ''} ${entry.product ?? ''}`.toLowerCase();
  if (anchor.rceKeywords.some((k) => text.includes(k))) {
    for (const t of anchor.rceTechniques) add(t, 'medium', 'KEV names remote/arbitrary code or command execution');
  }
  if (anchor.raKeywords.some((k) => text.includes(k))) {
    for (const t of anchor.raTechniques) add(t, 'medium', 'KEV names a remote-access gateway/VPN appliance');
  }
  return out;
}

// ── Heat ─────────────────────────────────────────────────────────────────────
const recencyWeight = (ageDays) => Math.pow(0.5, Math.max(0, ageDays) / HALF_LIFE_DAYS);
const severityWeight = (entry) => (entry.knownRansomwareCampaignUse === 'Known' ? 1 + RANSOM_BONUS : 1);

/** CVE ids newest-first by (year, numeric id). */
function cveSortKey(cveId) {
  const m = /^CVE-(\d{4})-(\d+)$/.exec(cveId);
  return m ? Number(m[1]) * 1e9 + Number(m[2]) : 0;
}

const round2 = (n) => Math.round(n * 100) / 100;

/**
 * Build the per-technique heat model from the KEV catalog. Pure: same inputs,
 * same output. Returns techniques sorted by heat (desc), each with its sourced
 * items and the breakdown behind its number.
 */
export function buildModel(kevDoc, anchor, bundleById) {
  const snapshotDate = kevDoc.__meta?.snapshotDate ?? '';
  const asOf = new Date(`${snapshotDate}T00:00:00Z`).getTime();
  const tech = new Map(); // id -> { items[], heat, ransomware }

  for (const entry of kevDoc.vulnerabilities ?? []) {
    const mapped = techniquesForKev(entry, anchor);
    if (mapped.size === 0) continue;
    const ageDays = (asOf - new Date(`${entry.dateAdded}T00:00:00Z`).getTime()) / DAY_MS;
    const recency = recencyWeight(ageDays);
    const severity = severityWeight(entry);
    const weight = recency * severity;
    const ransom = entry.knownRansomwareCampaignUse === 'Known';
    for (const [id, { confidence, via }] of mapped) {
      if (!bundleById.has(id)) continue; // never heat an id the bundle doesn't carry
      const slot = tech.get(id) ?? { items: [], heat: 0, ransomware: 0 };
      slot.heat += weight;
      if (ransom) slot.ransomware += 1;
      slot.items.push({
        cve: entry.cveID,
        source: 'CISA KEV',
        url: `https://nvd.nist.gov/vuln/detail/${entry.cveID}`,
        dateAdded: entry.dateAdded,
        knownRansomware: ransom,
        confidence,
        quote: entry.vulnerabilityName ?? '',
        cwes: entry.cwes ?? [],
        via,
        weight: round2(weight),
      });
      tech.set(id, slot);
    }
  }

  const list = [...tech.entries()].map(([id, slot]) => ({ id, ...slot }));
  list.sort((a, b) => b.heat - a.heat || a.id.localeCompare(b.id));
  return { snapshotDate, catalogVersion: String(kevDoc.__meta?.catalogVersion ?? ''), list };
}

// ── Brief (plain-language, cite-or-abstain, Known/Covered/Proven vocabulary) ──
function briefFor(t, name, maxHeatId) {
  const n = t.items.length;
  const cves = n === 1 ? '1 CVE' : `${n} CVEs`;
  const newest = t.items.reduce((a, b) => (b.dateAdded > a ? b.dateAdded : a), t.items[0].dateAdded);
  const lead =
    t.id === maxHeatId
      ? `${cves} in the CISA KEV catalog map to this technique by exploitation weakness, the most of any technique.`
      : `${cves} in the CISA KEV catalog map to this technique by exploitation weakness.`;
  const ransom =
    t.ransomware > 0
      ? ` ${t.ransomware} ${t.ransomware === 1 ? 'is' : 'are'} KEV-linked to known ransomware campaign use.`
      : '';
  return (
    `${lead}${ransom} The most recent was added ${newest}. ` +
    `Heat is recency-weighted with a ${HALF_LIFE_DAYS}-day half-life, as of the ${t.asOf} KEV snapshot; ` +
    `it reflects active exploitation pressure, not your defensive posture.`
  );
}

// ── Artifacts ────────────────────────────────────────────────────────────────
const RAMP = ['#12122a', '#5a1a1a', '#9a2a1a', '#d4551b', '#ff7a18']; // zero + 4 heat stops
function colorFor(score) {
  if (score <= 0) return RAMP[0];
  if (score < 25) return RAMP[1];
  if (score < 50) return RAMP[2];
  if (score < 75) return RAMP[3];
  return RAMP[4];
}

export function buildArtifacts(model, bundleById, attackVersion) {
  const maxHeat = model.list.length ? model.list[0].heat : 0;
  const maxHeatId = model.list.length ? model.list[0].id : null;
  const provenance = {
    generator: 'scripts/build-live-defense.mjs',
    snapshotDate: model.snapshotDate,
    kevCatalogVersion: model.catalogVersion,
    attackVersion,
    halfLifeDays: HALF_LIFE_DAYS,
    ransomwareBonus: RANSOM_BONUS,
    sources: [
      'CISA Known Exploited Vulnerabilities catalog (CC0 1.0; THIRD_PARTY_NOTICES.md section 1.5)',
      'CWE->ATT&CK exploitation anchor (cwe-exploitation-anchor.json; project-authored, MIT)',
      `ATT&CK Enterprise ${attackVersion} (enterprise-attack.json)`,
    ],
    method:
      'Each KEV CVE is mapped to ATT&CK technique(s) by the exploitation nature of its CWE (high-confidence anchor only; ' +
      'the low-confidence CWE->CAPEC->ATT&CK fan-out is not used). Heat = sum of recency(0.5^(age/half-life)) x severity ' +
      '(known ransomware use adds 50%), measured from the snapshot date. A KEV CVE whose weakness anchors no technique does not heat.',
  };

  const techniques = [];
  const evidence = {};
  for (let i = 0; i < model.list.length; i++) {
    const t = model.list[i];
    t.asOf = model.snapshotDate;
    const name = bundleById.get(t.id)?.name ?? t.id;
    const score = maxHeat > 0 ? Math.round((100 * t.heat) / maxHeat) : 0;
    const color = colorFor(score);
    const confidence = t.items.some((it) => it.confidence === 'high') ? 'high' : 'medium';
    const comment = `Live Defense: ${t.items.length} KEV CVEs map here (${t.ransomware} ransomware-linked). Heat ${score}/100 as of ${model.snapshotDate}.`;

    // One Navigator row per (technique, enterprise tactic) so the cell heats under
    // every tactic column it occupies; the score is the same across its tactics.
    const tactics = bundleById.get(t.id)?.tactics ?? [];
    const rows = tactics.length ? tactics : [null];
    for (const tactic of rows) {
      techniques.push({
        techniqueID: t.id,
        ...(tactic ? { tactic } : {}),
        score,
        color,
        comment,
        enabled: true,
        showSubtechniques: false,
      });
    }

    const items = [...t.items]
      .sort((a, b) => b.weight - a.weight || cveSortKey(b.cve) - cveSortKey(a.cve))
      .slice(0, ITEMS_PER_TECHNIQUE);
    evidence[t.id] = {
      techniqueID: t.id,
      name,
      rank: i + 1,
      score,
      heat: round2(t.heat),
      confidence,
      itemCount: t.items.length,
      ransomwareCount: t.ransomware,
      breakdown: {
        halfLifeDays: HALF_LIFE_DAYS,
        ransomwareBonus: RANSOM_BONUS,
        asOf: model.snapshotDate,
        itemsShown: items.length,
      },
      brief: briefFor(t, name, maxHeatId),
      items,
    };
  }

  const layer = {
    name: 'Live Defense (KEV)',
    versions: { attack: attackVersion.split('.')[0] || attackVersion, navigator: '4.9', layer: '4.5' },
    domain: 'enterprise-attack',
    description:
      'Live Defense — which ATT&CK techniques the current CISA KEV catalog is exploiting right now, by the ' +
      'exploitation weakness of each listed CVE, recency-weighted. A Threat-dimension lens (active exploitation ' +
      'pressure), not a statement about your defensive posture. Generated by scripts/build-live-defense.mjs; ' +
      `as of the ${model.snapshotDate} KEV snapshot. Sourced per technique in live-defense.evidence.json.`,
    sorting: 3, // descending by score
    layout: { layout: 'side', showID: true, showName: true, showAggregateScores: false },
    hideDisabled: true,
    techniques,
    gradient: { colors: [RAMP[0], RAMP[2], RAMP[4]], minValue: 0, maxValue: 100 },
    legendItems: [
      { label: 'High KEV exploitation pressure (recency-weighted)', color: RAMP[4] },
      { label: 'Lower pressure', color: RAMP[1] },
    ],
    metadata: [
      { name: 'lens', value: 'live-defense' },
      { name: 'rung', value: 'Threat (active exploitation pressure; not a posture rung)' },
      { name: 'as_of', value: model.snapshotDate },
      { name: 'kev_catalog_version', value: model.catalogVersion },
      { name: 'attack_matrix', value: 'enterprise-attack' },
      { name: 'generated_by', value: 'scripts/build-live-defense.mjs (deterministic, from the bundled KEV snapshot)' },
      { name: 'evidence', value: 'live-defense.evidence.json (sourced items + brief per technique)' },
    ],
    links: [],
    showTacticRowBackground: true,
    tacticRowBackground: '#2b2b3a',
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
    __meta: provenance,
  };

  const evidenceDoc = {
    __meta: {
      title: 'Live Defense — sourced KEV exploitation evidence per ATT&CK technique',
      ...provenance,
      techniqueCount: model.list.length,
      note:
        'Keyed by techniqueID. Each entry is the evidence behind that cell\'s heat: a cite-or-abstain brief and the ' +
        'KEV CVEs that map to it (newest/heaviest first, capped; itemCount is exact). A technique absent here does not ' +
        'heat (fail quiet). Absence is not evidence of safety.',
    },
    techniques: evidence,
  };

  return { layer, evidenceDoc };
}

// ── Self-gate (the accuracy gate: schema + consistency + truth-vocab + sourced) ─
export function gate(layer, evidenceDoc, kevDoc, bundleById, lintText = null) {
  const problems = [];
  const kevIds = new Set((kevDoc.vulnerabilities ?? []).map((v) => v.cveID));
  const ev = evidenceDoc.techniques ?? {};
  const evIds = new Set(Object.keys(ev));

  // Layer <-> evidence agree on the technique set.
  const layerIds = new Set(layer.techniques.map((t) => t.techniqueID));
  for (const id of layerIds) if (!evIds.has(id)) problems.push(`layer heats ${id} but it has no evidence entry`);
  for (const id of evIds) if (!layerIds.has(id)) problems.push(`evidence has ${id} but the layer does not heat it`);

  for (const t of layer.techniques) {
    if (!TID_RE.test(t.techniqueID)) problems.push(`layer: bad techniqueID ${t.techniqueID}`);
    if (typeof t.score !== 'number' || t.score < 0 || t.score > 100) problems.push(`layer: ${t.techniqueID} score out of 0..100`);
    if (!t.color) problems.push(`layer: ${t.techniqueID} has no color`);
    if (!t.comment) problems.push(`layer: ${t.techniqueID} has no comment`);
  }

  for (const [id, e] of Object.entries(ev)) {
    if (!TID_RE.test(id)) problems.push(`evidence: bad techniqueID key ${id}`);
    if (!bundleById.has(id)) problems.push(`evidence: ${id} is not a live Enterprise technique in the bundle`);
    if (!Array.isArray(e.items) || e.items.length === 0) problems.push(`evidence: ${id} has heat but no sourced items (un-sourced heat)`);
    if (!e.brief || !e.brief.trim()) problems.push(`evidence: ${id} has no brief (cite-or-abstain)`);
    if (!(e.itemCount > 0)) problems.push(`evidence: ${id} itemCount must be > 0`);
    if (!['high', 'medium'].includes(e.confidence)) problems.push(`evidence: ${id} confidence not high/medium (below the bar)`);
    // Truth-vocabulary lint over the rendered brief (plan E1.1): no claim beyond the
    // data. Applied when the linter is available (ci.yml always has it; see loadLint).
    if (lintText) {
      for (const f of lintText(e.brief, 'md', `live-defense.evidence.json:${id}`).findings) {
        problems.push(`evidence: ${id} brief fails truth-vocab (${f.rule}): "${f.match}" — ${f.hint}`);
      }
    }
    for (const it of e.items ?? []) {
      if (!CVE_RE.test(it.cve ?? '')) problems.push(`evidence: ${id} item has a bad cve ${it.cve}`);
      else if (!kevIds.has(it.cve)) problems.push(`evidence: ${id} item ${it.cve} is not in the KEV snapshot`);
      if (!it.source) problems.push(`evidence: ${id} item ${it.cve} has no source`);
      if (!it.url) problems.push(`evidence: ${id} item ${it.cve} has no url`);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(it.dateAdded ?? '')) problems.push(`evidence: ${id} item ${it.cve} bad dateAdded`);
      if (!it.quote || !it.quote.trim()) problems.push(`evidence: ${id} item ${it.cve} has no quote (cite-or-abstain)`);
    }
  }
  return problems;
}

// ── Serialisation (stable, diff-friendly: evidence one item per line) ─────────
const stable = (obj) => JSON.stringify(obj, null, 2) + '\n';

async function main(argv) {
  const check = argv.includes('--check');
  const read = (rel) => JSON.parse(readFileSync(join(ROOT, rel), 'utf8'));
  const kevDoc = read(KEV);
  const anchor = buildAnchor(read(ANCHOR));
  const bundle = read(BUNDLE);
  const bundleById = readBundle(bundle);
  const attackVersion = attackVersionOf(bundle);

  const model = buildModel(kevDoc, anchor, bundleById);
  const { layer, evidenceDoc } = buildArtifacts(model, bundleById, attackVersion);

  const lintText = await loadLint();
  if (!lintText) console.warn('build-live-defense: truth-vocab lint skipped (TypeScript not installed); ci.yml runs the full gate.');
  const problems = gate(layer, evidenceDoc, kevDoc, bundleById, lintText);
  if (problems.length) {
    console.error(`build-live-defense: accuracy gate FAILED (${problems.length}):`);
    for (const p of problems.slice(0, 40)) console.error(`  - ${p}`);
    return 1;
  }

  const layerText = stable(layer);
  const evidenceText = stable(evidenceDoc);

  if (check) {
    const cmp = (rel, text) => {
      const onDisk = existsSync(join(ROOT, rel)) ? readFileSync(join(ROOT, rel), 'utf8').replace(/\r\n/g, '\n') : '';
      if (onDisk !== text) {
        console.error(`${rel} differs from a fresh build: run node scripts/build-live-defense.mjs`);
        return false;
      }
      return true;
    };
    const ok = cmp(OUT_LAYER, layerText) & cmp(OUT_EVIDENCE, evidenceText);
    if (!ok) return 1;
    console.log(`build-live-defense: ${model.list.length} techniques heated; artifacts match a fresh build.`);
    return 0;
  }

  mkdirSync(join(ROOT, OUT_DIR), { recursive: true });
  writeFileSync(join(ROOT, OUT_LAYER), layerText);
  writeFileSync(join(ROOT, OUT_EVIDENCE), evidenceText);
  console.log(
    `build-live-defense: wrote ${OUT_LAYER} and ${OUT_EVIDENCE}: ${model.list.length} techniques heated ` +
      `from ${kevDoc.vulnerabilities.length} KEV entries, as of ${model.snapshotDate}.`,
  );
  for (const t of model.list) console.log(`  ${t.id} score=${evidenceDoc.techniques[t.id].score} items=${t.items.length} ransomware=${t.ransomware}`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main(process.argv.slice(2)).then(
    (code) => { process.exitCode = code; },
    (err) => { console.error(err.message ?? err); process.exitCode = 1; },
  );
}
