// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkPlatformNav,
  extractRailCatalog,
  collectPending,
  collectMenuErrors,
  hrefError,
  hrefErrorExternal,
  rawBytesErrors,
} from './check-platform-nav.mjs';

test('rawBytesErrors rejects a carriage return and non-ASCII bytes', () => {
  assert.deepEqual(rawBytesErrors(Buffer.from('{"a":1}\n', 'utf8')), []);
  assert.match(rawBytesErrors(Buffer.from('{"a":1}\r\n', 'utf8'))[0], /CR/);
  assert.match(rawBytesErrors(Buffer.from('{"a":"é"}', 'utf8'))[0], /non-ASCII/);
});

test('extractRailCatalog parses route and label in order', () => {
  const src = `
    const CATALOG = {
      '/matrix':   { route: '/matrix',   icon: 'grid',  label: 'Matrix' },
      '/exposure': { route: '/exposure', icon: 'shield-alert', label: 'Exposure' },
    };`;
  assert.deepEqual(extractRailCatalog(src), [
    { route: '/matrix', label: 'Matrix' },
    { route: '/exposure', label: 'Exposure' },
  ]);
});

test('collectPending finds pending entries at every level', () => {
  const nav = {
    items: [
      { label: 'Home', menu: [{ label: 'A' }, { label: 'B', pending: 'x' }] },
      { label: 'Book', menu: [{ label: 'C', menu: [{ label: 'D', pending: 'y' }] }] },
    ],
  };
  assert.deepEqual(collectPending(nav), ['Home > B', 'Book > C > D']);
});

// ---- The internal four-host rule (unchanged from version 5) ----

test('hrefError allows the known TeamStarWolf hosts and rejects others', () => {
  // Allowed
  assert.equal(hrefError('https://teamstarwolf.com/'), null);
  assert.equal(hrefError('https://library.teamstarwolf.com/#/INDEX'), null);
  assert.equal(hrefError('https://teamstarwolf.github.io/ATTACK-Navi/#/matrix'), null);
  assert.equal(hrefError('https://github.com/TeamStarWolf'), null);
  assert.equal(hrefError('https://github.com/TeamStarWolf/cybersecurity-resources/blob/main/LINKS.md#mitre'), null);
  // Rejected: non-https
  assert.match(hrefError('http://teamstarwolf.com/'), /not https/);
  // Rejected: unknown host
  assert.match(hrefError('https://evil.example.com/phish'), /host not allowed/);
  // Rejected: github.com outside the org
  assert.match(hrefError('https://github.com/SomeoneElse/repo'), /under \/TeamStarWolf/);
});

test('hrefError rejects traversal, backslash, port and host tricks', () => {
  // Dot path segments: plain "..", percent-encoded "%2e%2e", and a single "." that
  // normalises back into /TeamStarWolf and would otherwise slip past the prefix test.
  assert.match(hrefError('https://github.com/TeamStarWolf/../someone/repo'), /dot path segment/);
  assert.match(hrefError('https://github.com/TeamStarWolf/%2e%2e/someone/repo'), /dot path segment/);
  assert.match(hrefError('https://github.com/TeamStarWolf/./repo'), /dot path segment/);
  // A backslash anywhere.
  assert.match(hrefError('https://teamstarwolf.com\\@evil.example/'), /backslash/);
  // An explicit port is a different origin.
  assert.match(hrefError('https://teamstarwolf.com:8443/'), /explicit port/);
  // Host tricks.
  assert.match(hrefError('https://teamstarwolf.com.evil.example/'), /host not allowed/);
  // The real host is evil.example; caught as userinfo (which fires first) or a bad host.
  assert.match(hrefError('https://teamstarwolf.com@evil.example/'), /credentials|host not allowed/);
  assert.match(hrefError('https://github.com/TeamStarWolfX/repo'), /under \/TeamStarWolf/);
  assert.match(hrefError('//teamstarwolf.com/'), /not a valid URL/);
  // Userinfo that keeps an allowed host is still rejected.
  assert.match(hrefError('https://user@github.com/TeamStarWolf'), /credentials/);
});

// ---- The outside-link rule (version 6; bookmarks external leaves only) ----

test('hrefErrorExternal accepts genuine outside https addresses', () => {
  assert.equal(hrefErrorExternal('https://nvd.nist.gov/'), null);
  assert.equal(hrefErrorExternal('https://www.cisa.gov/known-exploited-vulnerabilities-catalog'), null);
  assert.equal(hrefErrorExternal('https://attack.mitre.org/'), null);
  assert.equal(hrefErrorExternal('https://www.first.org/epss/'), null);
});

test('hrefErrorExternal rejects an internal address wearing the external flag', () => {
  // Any address the four-host rule would accept must be rejected as "external".
  assert.match(hrefErrorExternal('https://teamstarwolf.com/'), /internal address wearing the external flag/);
  assert.match(hrefErrorExternal('https://github.com/TeamStarWolf/cybersecurity-resources'), /internal address wearing the external flag/);
});

test('hrefErrorExternal rejects the hostile shapes', () => {
  // Non-https.
  assert.match(hrefErrorExternal('http://flaws.cloud/'), /not https/);
  // Userinfo.
  assert.match(hrefErrorExternal('https://user:pass@nvd.nist.gov/'), /credentials/);
  // Explicit port.
  assert.match(hrefErrorExternal('https://nvd.nist.gov:8443/'), /explicit port/);
  // Backslash.
  assert.match(hrefErrorExternal('https://nvd.nist.gov\\@evil.example/'), /backslash/);
  // Whitespace / control character.
  assert.match(hrefErrorExternal('https://nvd.nist.gov/a b'), /whitespace or control/);
  assert.match(hrefErrorExternal('https://nvd.nist.gov/a\tb'), /whitespace or control/);
  // Dot path segment (the brief's example), tested on the path alone (query cut off).
  assert.match(hrefErrorExternal('https://nvd.nist.gov/a/..?x=1'), /dot path segment/);
  assert.match(hrefErrorExternal('https://nvd.nist.gov/%2e%2e/x'), /dot path segment/);
  // Encoded slash / backslash in the path.
  assert.match(hrefErrorExternal('https://nvd.nist.gov/a%2fb'), /encoded slash\/backslash/);
  assert.match(hrefErrorExternal('https://nvd.nist.gov/a%5cb'), /encoded slash\/backslash/);
  // IP literal (v4 and v6).
  assert.match(hrefErrorExternal('https://192.168.0.1/'), /IP literal/);
  assert.match(hrefErrorExternal('https://[2001:db8::1]/'), /IP literal/);
  // Single-label host (no dot).
  assert.match(hrefErrorExternal('https://localhost/'), /single-label host/);
  // Punycode.
  assert.match(hrefErrorExternal('https://xn--80ak6aa92e.com/'), /punycode/);
  // Over 512 characters.
  assert.match(hrefErrorExternal('https://nvd.nist.gov/' + 'a'.repeat(600)), /longer than 512/);
});

// ---- The structural walker: external placement, nesting depth, caps ----

test('collectMenuErrors flags the external flag outside Bookmarks', () => {
  const nav = { items: [{ id: 'library', label: 'Library', href: 'https://library.teamstarwolf.com/', menu: [{ label: 'Out', href: 'https://nvd.nist.gov/', external: true }] }] };
  const errs = collectMenuErrors(nav);
  assert.ok(errs.some((e) => /flagged external outside Bookmarks/.test(e)), errs.join('\n'));
});

test('collectMenuErrors flags an outside leaf without the external flag', () => {
  const nav = { items: [{ id: 'bookmarks', label: 'Bookmarks', href: 'https://github.com/TeamStarWolf', menu: [{ label: 'NVD', href: 'https://nvd.nist.gov/' }] }] };
  const errs = collectMenuErrors(nav);
  assert.ok(errs.some((e) => /host not allowed/.test(e)), errs.join('\n'));
});

test('collectMenuErrors flags a flagged leaf on one of our own hosts', () => {
  const nav = { items: [{ id: 'bookmarks', label: 'Bookmarks', href: 'https://github.com/TeamStarWolf', menu: [{ label: 'Self', href: 'https://teamstarwolf.com/', external: true }] }] };
  const errs = collectMenuErrors(nav);
  assert.ok(errs.some((e) => /internal address wearing the external flag/.test(e)), errs.join('\n'));
});

test('collectMenuErrors flags a flagged entry that has children', () => {
  const nav = {
    items: [{ id: 'bookmarks', label: 'Bookmarks', href: 'https://github.com/TeamStarWolf', menu: [
      { label: 'Cat', href: 'https://github.com/TeamStarWolf', external: true, menu: [{ label: 'NVD', href: 'https://nvd.nist.gov/', external: true }] },
    ] }],
  };
  const errs = collectMenuErrors(nav);
  assert.ok(errs.some((e) => /flagged external but has children/.test(e)), errs.join('\n'));
});

test('collectMenuErrors enforces nesting depth per item', () => {
  // Bookmarks: category > subsection > leaf is fine; a fourth level is not.
  const okBm = { items: [{ id: 'bookmarks', label: 'Bookmarks', href: 'https://github.com/TeamStarWolf', menu: [
    { label: 'Cat', href: 'https://github.com/TeamStarWolf', menu: [
      { label: 'Sub', href: 'https://github.com/TeamStarWolf', menu: [
        { label: 'NVD', href: 'https://nvd.nist.gov/', external: true },
      ] },
    ] },
  ] }] };
  assert.deepEqual(collectMenuErrors(okBm), []);

  const tooDeepBm = structuredClone(okBm);
  tooDeepBm.items[0].menu[0].menu[0].menu[0].menu = [{ label: 'X', href: 'https://nvd.nist.gov/x', external: true }];
  assert.ok(collectMenuErrors(tooDeepBm).some((e) => /nests deeper than allowed/.test(e)));

  // A non-bookmarks item may nest one level only; two is too deep.
  const tooDeepMenu = { items: [{ id: 'hub', label: 'Hub', href: 'https://teamstarwolf.github.io/', menu: [
    { label: 'A', href: 'https://teamstarwolf.github.io/', menu: [
      { label: 'B', href: 'https://teamstarwolf.github.io/', menu: [{ label: 'C', href: 'https://teamstarwolf.github.io/' }] },
    ] },
  ] }] };
  assert.ok(collectMenuErrors(tooDeepMenu).some((e) => /nests deeper than allowed/.test(e)));
});

test('collectMenuErrors enforces the per-list caps (16 bookmarks, 14 others)', () => {
  const leaf = (i) => ({ label: 'L' + i, href: 'https://nvd.nist.gov/' + i, external: true });
  const bm17 = { items: [{ id: 'bookmarks', label: 'Bookmarks', href: 'https://github.com/TeamStarWolf', menu: Array.from({ length: 17 }, (_, i) => leaf(i)) }] };
  assert.ok(collectMenuErrors(bm17).some((e) => /cap 16/.test(e)));

  const sub = (i) => ({ label: 'S' + i, href: 'https://teamstarwolf.github.io/' + i });
  const menu15 = { items: [{ id: 'hub', label: 'Hub', href: 'https://teamstarwolf.github.io/', menu: Array.from({ length: 15 }, (_, i) => sub(i)) }] };
  assert.ok(collectMenuErrors(menu15).some((e) => /cap 14/.test(e)));
});

// ---- The real vendored menu ----

test('the real vendored menu passes every gate', () => {
  const { ok, errors } = checkPlatformNav('.');
  assert.equal(ok, true, errors.join('\n'));
});

test('the real menu holds back at least one pending entry', () => {
  const { pending } = checkPlatformNav('.');
  assert.ok(pending.length >= 1, 'expected pending entries to be enumerated');
});
