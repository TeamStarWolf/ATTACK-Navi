// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkPlatformNav, extractRailCatalog, collectPending, hrefError } from './check-platform-nav.mjs';

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

test('collectPending finds pending entries at both levels', () => {
  const nav = {
    items: [
      { label: 'Home', menu: [{ label: 'A' }, { label: 'B', pending: 'x' }] },
      { label: 'Book', menu: [{ label: 'C', menu: [{ label: 'D', pending: 'y' }] }] },
    ],
  };
  assert.deepEqual(collectPending(nav), ['Home > B', 'Book > C > D']);
});

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

test('the real vendored menu passes every gate', () => {
  const { ok, errors } = checkPlatformNav('.');
  assert.equal(ok, true, errors.join('\n'));
});

test('the real menu holds back at least one pending entry', () => {
  const { pending } = checkPlatformNav('.');
  assert.ok(pending.length >= 1, 'expected pending entries to be enumerated');
});
