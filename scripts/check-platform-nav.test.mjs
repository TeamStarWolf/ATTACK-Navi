// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkPlatformNav, extractRailCatalog, collectPending } from './check-platform-nav.mjs';

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

test('the real vendored menu passes every gate', () => {
  const { ok, errors } = checkPlatformNav('.');
  assert.equal(ok, true, errors.join('\n'));
});

test('the real menu holds back at least one pending entry', () => {
  const { pending } = checkPlatformNav('.');
  assert.ok(pending.length >= 1, 'expected pending entries to be enumerated');
});
