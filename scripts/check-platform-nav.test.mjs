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
  assert.match(hrefError('//teamstarwolf.com/'), /not https/);
  // Userinfo that keeps an allowed host is still rejected.
  assert.match(hrefError('https://user@github.com/TeamStarWolf'), /credentials/);
});

test('hrefError rejects raw-string tricks the URL constructor normalises away', () => {
  // One slash: a browser on an https page reads this as a relative path on the current site.
  assert.match(hrefError('https:/teamstarwolf.com/x'), /not https/);
  // A default port the URL constructor drops, and empty userinfo it accepts.
  assert.match(hrefError('https://teamstarwolf.com:443/x'), /explicit port/);
  assert.match(hrefError('https://@teamstarwolf.com/x'), /credentials/);
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
  // IP literal (v4 reads as an IP address via its all-digit final label; a bracketed v6 literal
  // carries colons, so the raw-authority check rejects it as a port — still rejected either way).
  assert.match(hrefErrorExternal('https://192.168.0.1/'), /IP address/);
  assert.match(hrefErrorExternal('https://[2001:db8::1]/'), /IP literal|explicit port/);
  // Single-label host (no dot).
  assert.match(hrefErrorExternal('https://localhost/'), /single-label host/);
  // Punycode.
  assert.match(hrefErrorExternal('https://xn--80ak6aa92e.com/'), /punycode/);
  // Over 512 characters.
  assert.match(hrefErrorExternal('https://nvd.nist.gov/' + 'a'.repeat(600)), /longer than 512/);
});

test('hrefErrorExternal checks the raw authority, not the normalised URL', () => {
  // A default port URL drops, an empty port, empty userinfo, a percent-encoded host, and the
  // one-slash form a browser reads as a relative path — all rejected on the raw string.
  assert.match(hrefErrorExternal('https://nvd.nist.gov:443/x'), /explicit port/);
  assert.match(hrefErrorExternal('https://nvd.nist.gov:/x'), /explicit port/);
  assert.match(hrefErrorExternal('https://@nvd.nist.gov/x'), /credentials/);
  assert.match(hrefErrorExternal('https://:@nvd.nist.gov/x'), /explicit port|credentials/);
  assert.match(hrefErrorExternal('https://%6evd.nist.gov/x'), /percent-encoded host/);
  assert.match(hrefErrorExternal('https:/nvd.nist.gov/a/../b'), /not https/);
});

test('hrefErrorExternal rejects hosts a browser reads as an IP address', () => {
  // Dotted-decimal shorthands the browser resolves to an IPv4 address.
  assert.ok(hrefErrorExternal('https://127.1/') !== null);
  assert.ok(hrefErrorExternal('https://0x7f.0.0.1/') !== null);
  assert.ok(hrefErrorExternal('https://1.2.3/') !== null);
  assert.ok(hrefErrorExternal('https://1.2.3.0x7f/') !== null);
  // Forms that stay non-IPv4 but end in an all-digit or 0x label (the new shape guard).
  assert.match(hrefErrorExternal('https://example.123/'), /IP address/);
  assert.match(hrefErrorExternal('https://example.0x1f/'), /IP address/);
  // A genuine host ending in an alphabetic TLD is fine even with a numeric first label.
  assert.equal(hrefErrorExternal('https://123.example.com/'), null);
});

test('hrefErrorExternal rejects a non-ASCII character in the parsed address', () => {
  // A \u escape in the JSON parses to a real non-ASCII character in the string.
  assert.match(hrefErrorExternal('https://nvd.nist.gov/café'), /non-ASCII/);
  assert.match(hrefErrorExternal('https://nvd.nist.gov/‮evil'), /non-ASCII/);
});

test('both rules reject malformed host labels (empty, hyphen edges, trailing dot)', () => {
  // External leaf rule.
  assert.match(hrefErrorExternal('https://nvd..nist.gov/'), /malformed host label/);
  assert.match(hrefErrorExternal('https://-nvd.nist.gov/'), /malformed host label/);
  assert.match(hrefErrorExternal('https://nvd-.nist.gov/'), /malformed host label/);
  assert.match(hrefErrorExternal('https://nvd.nist.gov./'), /malformed host label/);
  // Internal four-host rule (a trailing dot on an allowed host must not slip through).
  assert.match(hrefError('https://teamstarwolf.com./'), /malformed host label/);
  assert.match(hrefError('https://-teamstarwolf.com/'), /malformed host label/);
  assert.match(hrefError('https://github..com/TeamStarWolf'), /malformed host label/);
  // A valid label set still passes the internal rule.
  assert.equal(hrefError('https://library.teamstarwolf.com/#/INDEX'), null);
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

test('collectMenuErrors rejects a duplicate item id', () => {
  const nav = { items: [
    { id: 'bookmarks', label: 'Bookmarks', href: 'https://github.com/TeamStarWolf', menu: [] },
    { id: 'bookmarks', label: 'Impostor', href: 'https://github.com/TeamStarWolf', menu: [{ label: 'X', href: 'https://nvd.nist.gov/', external: true }] },
  ] };
  assert.ok(collectMenuErrors(nav).some((e) => /duplicate item id/.test(e)));
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

test('collectMenuErrors accepts a top-level item with no menu (a plain link)', () => {
  // Version 7's Home item carries id/label/href and no menu key; it must pass the gate.
  assert.deepEqual(collectMenuErrors({ items: [{ id: 'home', label: 'Home', href: 'https://teamstarwolf.com/' }] }), []);
  // An empty menu array is equally a plain link and must not error either.
  assert.deepEqual(collectMenuErrors({ items: [{ id: 'home', label: 'Home', href: 'https://teamstarwolf.com/', menu: [] }] }), []);
});

test('collectPending still holds back pending entries (filter kept, tested on a fixture)', () => {
  // The real file may have no pending entry (version 7 has none), so the filter is tested on a
  // fixture here; a future entry may be pending again and must still be enumerated/dropped.
  const nav = { items: [{ label: 'Home', menu: [{ label: 'A' }, { label: 'B', pending: 'later' }] }] };
  assert.deepEqual(collectPending(nav), ['Home > B']);
});

test('the real vendored menu passes every gate', () => {
  const { ok, errors } = checkPlatformNav('.');
  assert.equal(ok, true, errors.join('\n'));
});
