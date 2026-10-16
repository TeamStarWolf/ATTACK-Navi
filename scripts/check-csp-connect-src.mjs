// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Verifies that the Content-Security-Policy shipped by nginx allows every origin
// the SPA fetches at runtime, so a new upstream cannot silently break the Docker
// deployment (D3FEND and CVE Services were missing until 2026-10).
//
//   node scripts/check-csp-connect-src.mjs                    checks nginx-security-headers.conf
//   node scripts/check-csp-connect-src.mjs path/to/file.conf  checks that file
//   node scripts/check-csp-connect-src.mjs --header "<CSP>"   checks a served header value
//
// Each required origin names the service file that fetches it; the script also
// asserts the origin still appears in that file, so an entry cannot go stale when a
// feed moves or is removed.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = new URL('../', import.meta.url);

/** [origin, file under src/app/services that fetches it, what it serves] */
const REQUIRED_CONNECT_SRC = [
  ['https://raw.githubusercontent.com', 'cve.service.ts', 'ATT&CK STIX, Engage, CAPEC, Sigma, Atomic, KEV mirror and other GitHub-hosted data'],
  ['https://api.first.org', 'epss.service.ts', 'EPSS scores'],
  ['https://services.nvd.nist.gov', 'cve.service.ts', 'NVD CVE lookups'],
  ['https://api.github.com', 'elastic.service.ts', 'GitHub API listings (Elastic, Splunk, changelog)'],
  ['https://gitlab.com', 'exploitdb.service.ts', 'Exploit-DB index'],
  ['https://www.cisa.gov', 'cve.service.ts', 'CISA KEV catalog'],
  ['https://d3fend.mitre.org', 'd3fend.service.ts', 'D3FEND technique mappings'],
  ['https://cveawg.mitre.org', 'cisa-ssvc.service.ts', 'CVE Services record (CISA SSVC)'],
];

function extractDirective(csp, name) {
  const directive = csp
    .split(';')
    .map(part => part.trim())
    .find(part => part.toLowerCase().startsWith(name + ' ') || part.toLowerCase() === name);
  if (!directive) return null;
  return directive.slice(name.length).trim().split(/\s+/).filter(Boolean);
}

function cspFromFile(path) {
  const text = readFileSync(path, 'utf8');
  const match = text.match(/Content-Security-Policy\s+"([^"]+)"/i);
  if (!match) throw new Error(`No Content-Security-Policy add_header found in ${path}`);
  return match[1];
}

const args = process.argv.slice(2);
let csp;
let source;
if (args[0] === '--header') {
  csp = args.slice(1).join(' ').trim();
  source = 'served header';
  if (!csp) {
    console.error('check-csp-connect-src: --header needs the Content-Security-Policy value');
    process.exit(2);
  }
} else {
  const file = resolve(args[0] ?? new URL('nginx-security-headers.conf', root).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
  csp = cspFromFile(file);
  source = file;
}

const connectSrc = extractDirective(csp, 'connect-src');
if (!connectSrc) {
  console.error(`check-csp-connect-src: ${source} has no connect-src directive`);
  process.exit(1);
}

let failures = 0;
if (!connectSrc.includes("'self'")) {
  console.error("connect-src must include 'self' (bundled assets, the /api/ proxy route)");
  failures += 1;
}
for (const [origin, file, purpose] of REQUIRED_CONNECT_SRC) {
  const serviceFile = new URL(`src/app/services/${file}`, root);
  const serviceText = readFileSync(serviceFile, 'utf8');
  if (!serviceText.includes(origin)) {
    console.error(`stale entry: ${origin} is no longer referenced by src/app/services/${file} — update REQUIRED_CONNECT_SRC`);
    failures += 1;
    continue;
  }
  if (!connectSrc.includes(origin)) {
    console.error(`missing from connect-src: ${origin} (${purpose}; fetched by src/app/services/${file})`);
    failures += 1;
  }
}

const scriptSrc = extractDirective(csp, 'script-src') ?? [];
if (scriptSrc.includes("'unsafe-inline'") || scriptSrc.includes("'unsafe-eval'")) {
  console.error(`script-src must not allow inline or eval: ${scriptSrc.join(' ')}`);
  failures += 1;
}

if (failures > 0) {
  console.error(`check-csp-connect-src: ${failures} problem(s) in ${source}`);
  process.exit(1);
}
console.log(`check-csp-connect-src: ${source} allows all ${REQUIRED_CONNECT_SRC.length} runtime origins; script-src is ${scriptSrc.join(' ') || '(default-src)'}`);
