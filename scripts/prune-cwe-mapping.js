#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
/**
 * Prunes over-mapped CWE→ATT&CK entries to follow CTID methodology:
 * Each CWE should map to 2-8 techniques max (exploitation + primary + secondary).
 *
 * Uses the CTID's own curated vulnerability type table as the authoritative source,
 * then fills in missing CWEs with conservative defaults.
 */
const fs = require('fs');
const path = require('path');

// CTID's own curated vulnerability type → technique table
// Source: https://ctid.mitre.org/projects/mapping-attck-to-cve-for-impact/
const CTID_VULN_TYPES = {
  // CWE → [exploitation, primary, secondary] (max 2-3 each)
  '89':   { e: ['T1190'], p: ['T1059'], s: ['T1005', 'T1505.003'] },           // SQL Injection
  '78':   { e: ['T1190'], p: ['T1059'], s: [] },                                // OS Command Injection
  '77':   { e: ['T1190'], p: ['T1059'], s: [] },                                // Command Injection
  '79':   { e: ['T1189'], p: ['T1059.007'], s: ['T1185'] },                    // XSS
  '94':   { e: ['T1190'], p: ['T1059'], s: [] },                                // Code Injection
  '502':  { e: ['T1190'], p: ['T1059'], s: ['T1068'] },                        // Deserialization
  '611':  { e: ['T1190'], p: ['T1059'], s: ['T1005'] },                        // XXE
  '918':  { e: ['T1190'], p: ['T1090'], s: ['T1005'] },                        // SSRF
  '352':  { e: ['T1204.001'], p: ['T1185'], s: [] },                            // CSRF
  '22':   { e: ['T1190'], p: ['T1005'], s: ['T1552.001'] },                    // Path Traversal
  '434':  { e: ['T1190'], p: ['T1505.003'], s: ['T1059'] },                    // File Upload
  '287':  { e: ['T1190'], p: ['T1078'], s: [] },                                // Improper Auth
  '306':  { e: ['T1190'], p: ['T1078'], s: [] },                                // Missing Auth
  '798':  { e: [], p: ['T1078.001'], s: ['T1552'] },                            // Hardcoded Creds
  '307':  { e: ['T1110'], p: ['T1078'], s: [] },                                // Brute Force
  '384':  { e: [], p: ['T1185'], s: ['T1550'] },                                // Session Fixation
  '601':  { e: ['T1566.002'], p: ['T1204.001'], s: [] },                        // Open Redirect
  '312':  { e: [], p: ['T1552'], s: ['T1078'] },                                // Cleartext Storage
  '319':  { e: ['T1040'], p: ['T1552'], s: ['T1078'] },                        // Cleartext Transmission
  '522':  { e: [], p: ['T1552'], s: ['T1078'] },                                // Weak Credentials
  '326':  { e: [], p: ['T1573'], s: ['T1040'] },                                // Weak Crypto
  '327':  { e: [], p: ['T1573'], s: ['T1040'] },                                // Broken Crypto
  '295':  { e: [], p: ['T1557'], s: [] },                                        // Improper Cert Validation
  '400':  { e: [], p: ['T1499'], s: [] },                                        // Resource Consumption
  '770':  { e: [], p: ['T1499'], s: [] },                                        // No Limits
  '476':  { e: [], p: ['T1499'], s: [] },                                        // NULL Deref
  '119':  { e: ['T1190'], p: ['T1203'], s: ['T1068'] },                        // Buffer Overflow
  '120':  { e: ['T1190'], p: ['T1203'], s: ['T1068'] },                        // Classic Buffer Overflow
  '121':  { e: ['T1190'], p: ['T1203'], s: ['T1068'] },                        // Stack Overflow
  '122':  { e: [], p: ['T1203'], s: ['T1068'] },                                // Heap Overflow
  '125':  { e: ['T1190'], p: ['T1005'], s: ['T1068'] },                        // OOB Read
  '787':  { e: ['T1190'], p: ['T1203'], s: ['T1068'] },                        // OOB Write
  '416':  { e: [], p: ['T1203'], s: ['T1068'] },                                // Use After Free
  '190':  { e: ['T1190'], p: ['T1203'], s: [] },                                // Integer Overflow
  '362':  { e: [], p: ['T1068'], s: [] },                                        // Race Condition
  '269':  { e: [], p: ['T1548'], s: ['T1068'] },                                // Improper Priv Mgmt
  '276':  { e: [], p: ['T1222'], s: [] },                                        // Wrong Default Perms
  '284':  { e: ['T1190'], p: ['T1548'], s: [] },                                // Improper Access Control
  '862':  { e: ['T1190'], p: ['T1548'], s: [] },                                // Missing Authorization
  '863':  { e: [], p: ['T1548'], s: ['T1134'] },                                // Incorrect Authorization
  '639':  { e: ['T1190'], p: ['T1134'], s: [] },                                // IDOR
  '426':  { e: [], p: ['T1574'], s: [] },                                        // Untrusted Search Path
  '427':  { e: [], p: ['T1574.001'], s: [] },                                   // Uncontrolled Search Path
  '428':  { e: [], p: ['T1574.009'], s: [] },                                   // Unquoted Search Path
  '494':  { e: [], p: ['T1195.002'], s: ['T1553'] },                            // Download Without Integrity
  '200':  { e: [], p: ['T1005'], s: [] },                                        // Info Exposure
  '532':  { e: [], p: ['T1552'], s: [] },                                        // Info in Log
  '59':   { e: [], p: ['T1574'], s: [] },                                        // Symlink
  '843':  { e: [], p: ['T1203'], s: ['T1068'] },                                // Type Confusion
  '20':   { e: ['T1190'], p: ['T1203'], s: [] },                                // Input Validation
  '345':  { e: [], p: ['T1553'], s: [] },                                        // Insufficient Data Auth
  '347':  { e: [], p: ['T1553'], s: [] },                                        // Improper Crypto Sig
  '506':  { e: [], p: ['T1195.002'], s: ['T1059'] },                            // Embedded Malicious Code
  '912':  { e: [], p: ['T1195.002'], s: ['T1059'] },                            // Hidden Functionality
};

// Load current CWE_TO_ATTACK
const svcPath = path.join(__dirname, '..', 'src', 'app', 'services', 'cve.service.ts');
const svcSrc = fs.readFileSync(svcPath, 'utf8');
const CWE_TO_ATTACK = {};
for (const m of svcSrc.matchAll(/'CWE-(\d+)':\s*\[([^\]]*)\]/g)) {
  CWE_TO_ATTACK[m[1]] = m[2].match(/'([^']+)'/g)?.map(s => s.replace(/'/g, '')) || [];
}

const origTotal = Object.values(CWE_TO_ATTACK).reduce((s, a) => s + a.length, 0);
const origTechs = new Set(Object.values(CWE_TO_ATTACK).flat());
console.log('Before pruning:', Object.keys(CWE_TO_ATTACK).length, 'CWEs,', origTotal, 'total links,', origTechs.size, 'unique techniques');

// Replace over-mapped CWEs with CTID curated values
let pruned = 0;
for (const [cwe, vtm] of Object.entries(CTID_VULN_TYPES)) {
  const newTechs = [...vtm.e, ...vtm.p, ...vtm.s];
  if (CWE_TO_ATTACK[cwe] && CWE_TO_ATTACK[cwe].length > newTechs.length) {
    const oldLen = CWE_TO_ATTACK[cwe].length;
    CWE_TO_ATTACK[cwe] = newTechs;
    pruned += oldLen - newTechs.length;
  } else if (!CWE_TO_ATTACK[cwe] && newTechs.length > 0) {
    CWE_TO_ATTACK[cwe] = newTechs;
  }
}

// For remaining CWEs not in CTID table, cap at 8 techniques max
for (const [cwe, techs] of Object.entries(CWE_TO_ATTACK)) {
  if (techs.length > 8 && !CTID_VULN_TYPES[cwe]) {
    const oldLen = techs.length;
    CWE_TO_ATTACK[cwe] = techs.slice(0, 8);
    pruned += oldLen - 8;
  }
}

const newTotal = Object.values(CWE_TO_ATTACK).reduce((s, a) => s + a.length, 0);
const newTechs = new Set(Object.values(CWE_TO_ATTACK).flat());
console.log('After pruning:', Object.keys(CWE_TO_ATTACK).length, 'CWEs,', newTotal, 'total links,', newTechs.size, 'unique techniques');
console.log('Removed', pruned, 'over-mapped links');

// Write back to cve.service.ts
const lines = [];
for (const cwe of Object.keys(CWE_TO_ATTACK).sort((a, b) => Number(a) - Number(b))) {
  const techs = CWE_TO_ATTACK[cwe].map(t => "'" + t + "'").join(', ');
  lines.push("  'CWE-" + cwe + "':  [" + techs + "],");
}
const newMapStr = "export const CWE_TO_ATTACK: Record<string, string[]> = {\n" + lines.join('\n') + '\n};';
const newSrc = svcSrc.replace(/export const CWE_TO_ATTACK[^{]*\{[\s\S]*?\n\};/, newMapStr);
fs.writeFileSync(svcPath, newSrc);
console.log('Updated cve.service.ts');
