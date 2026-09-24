// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Regenerates src/assets/data/ssvc-decision-tables.json from CERT/CC's published
// SSVC decision tables. The tables are FETCHED, never transcribed: a miscopied cell
// would hand an analyst the wrong remediation deadline, and these tables are small
// enough that hand-copying looks safe right up until it isn't.
//
//   cisa_coordinator_2_0_3   Exploitation x Automatable x Technical Impact x
//                            Mission & Well-being -> track / track* / attend / act
//   cisa_bod_26_04_1_0_0     In KEV x Publicly Exposed x Automatable x
//                            Technical Impact -> a concrete remediation timeline
//
// Output schema:
//   { __meta: { source, generated, tables: [...] },
//     tables: { [id]: { id, url, columns: [...], outcomeColumn, rows: [{ key, outcome }] } } }
//
// Usage: node scripts/build-ssvc-tables.mjs
// Requires Node 20+ (built-in fetch). No shell commands are run by this script.

import { writeFileSync } from 'node:fs';

const BASE =
  'https://raw.githubusercontent.com/CERTCC/SSVC/main/data/csv/cisa';

const TABLES = [
  {
    id: 'cisa-coordinator',
    file: 'cisa_coordinator_2_0_3.csv',
    label: 'CISA Coordinator SSVC v2.0.3',
    describes: 'Prioritization outcome',
  },
  {
    id: 'bod-26-04',
    file: 'cisa_bod_26_04_1_0_0.csv',
    label: 'CISA BOD 26-04 Remediation Timelines v1.0.0',
    describes: 'Remediation timeline',
  },
];

const OUT = 'src/assets/data/ssvc-decision-tables.json';

/** Minimal RFC4180-ish split: these tables have no embedded commas or quotes. */
function parseCsv(text) {
  return text
    .replace(/\r/g, '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => line.split(',').map((cell) => cell.trim()));
}

const tables = {};
const metaTables = [];

for (const spec of TABLES) {
  const url = `${BASE}/${spec.file}`;
  process.stdout.write(`fetching ${spec.file} ... `);
  const res = await fetch(url, { headers: { 'User-Agent': 'ATTACK-Navi build script' } });
  if (!res.ok) {
    throw new Error(`${spec.file}: HTTP ${res.status}`);
  }
  const rowsRaw = parseCsv(await res.text());
  const header = rowsRaw.shift();
  if (!header || header.length < 3) {
    throw new Error(`${spec.file}: unexpected header`);
  }

  // First column is a row index, last column is the outcome; the rest are the
  // decision points, in the order the table expects them.
  const columns = header.slice(1, -1);
  const outcomeColumn = header[header.length - 1];
  const rows = [];
  for (const cells of rowsRaw) {
    if (cells.length !== header.length) continue;
    rows.push({
      key: cells.slice(1, -1).map((c) => c.toLowerCase()),
      outcome: cells[cells.length - 1],
    });
  }
  if (rows.length === 0) {
    throw new Error(`${spec.file}: no rows parsed`);
  }

  // Every combination of the observed values should be present; warn if not, since a
  // gap means some CVEs would get no answer at all.
  const domains = columns.map((_, i) => new Set(rows.map((r) => r.key[i])));
  const expected = domains.reduce((n, d) => n * d.size, 1);
  if (expected !== rows.length) {
    console.warn(
      `\n  warning: ${spec.file} has ${rows.length} rows but ${expected} value ` +
        `combinations — some inputs will not resolve.`,
    );
  }

  tables[spec.id] = {
    id: spec.id,
    label: spec.label,
    describes: spec.describes,
    url,
    columns,
    outcomeColumn,
    outcomes: [...new Set(rows.map((r) => r.outcome))],
    rows,
  };
  metaTables.push({ id: spec.id, label: spec.label, url, rows: rows.length });
  console.log(`${rows.length} rows, ${columns.length} decision points`);
}

const payload = {
  __meta: {
    source: 'CERT/CC SSVC published decision tables (github.com/CERTCC/SSVC)',
    home: 'https://certcc.github.io/SSVC/',
    generated: new Date().toISOString().slice(0, 10),
    tables: metaTables,
    note:
      'Fetched verbatim from CERT/CC, not transcribed. Two decision points are ' +
      'environmental and cannot be derived from a CVE: Publicly Exposed and Mission ' +
      'and Well-Being Impact. The app supplies those as explicit assumptions.',
  },
  tables,
};

writeFileSync(OUT, JSON.stringify(payload, null, 2) + '\n', 'utf8');
console.log(`\nwrote ${OUT}`);
