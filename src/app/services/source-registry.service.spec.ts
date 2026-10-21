// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { HttpErrorResponse, HttpHeaders } from '@angular/common/http';
import { SourceRegistryService, describeLoadError } from './source-registry.service';
import { INVENTORY_ROW, LICENCE_NOTES, NOT_IN_INVENTORY, SOURCE_DEFINITIONS } from './source-inventory';
import { REQUIRED_RECORDS_BY_ROW, SECTION_6_3_INVENTORY } from '../testing/source-inventory-6-3';

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

describe('SourceRegistryService', () => {
  let registry: SourceRegistryService;

  beforeEach(() => {
    registry = new SourceRegistryService();
  });

  describe('the inventory (product plan 6.3)', () => {
    it('has exactly one record per definition, with unique ids', () => {
      const ids = SOURCE_DEFINITIONS.map(d => d.id);
      expect(new Set(ids).size).toBe(ids.length);
      expect(registry.all().map(r => r.id)).toEqual(ids);
    });

    it('gives every source a version or a reviewed date', () => {
      const missing = registry.all().filter(r => !r.version?.trim() && !r.reviewedDate);
      expect(missing.map(r => r.id)).withContext('records with neither a version nor a reviewed date').toEqual([]);
      const badDates = registry.all().filter(r => r.reviewedDate !== undefined && !ISO_DATE.test(r.reviewedDate));
      expect(badDates.map(r => r.id)).withContext('reviewedDate must be YYYY-MM-DD').toEqual([]);
    });

    it("records every hand-authored source as 'project-authored, reviewed <date>, no upstream'", () => {
      const authored = registry.all().filter(r => r.kind === 'project-authored');
      expect(authored.length).toBeGreaterThan(0);
      for (const r of authored) {
        expect(r.upstream).withContext(r.id).toBe('no upstream');
        expect(r.reviewedDate).withContext(r.id).toMatch(ISO_DATE);
      }
      // The two hand-authored files the plan names explicitly.
      expect(registry.get('cwe-exploitation-anchor').kind).toBe('project-authored');
      expect(registry.get('technique-queries').kind).toBe('project-authored');
    });

    it('gives every record an upstream, a known licence note, an owner and a 6.3 row', () => {
      const rows = new Set<string>([...Object.values(INVENTORY_ROW), NOT_IN_INVENTORY]);
      for (const r of registry.all()) {
        expect(r.upstream === 'no upstream' || /^https:\/\//.test(r.upstream)).withContext(`${r.id} upstream`).toBeTrue();
        expect(LICENCE_NOTES[r.licence]).withContext(`${r.id} licence`).toBeDefined();
        expect(r.owner.trim()).withContext(`${r.id} owner`).not.toBe('');
        expect(rows.has(r.inventoryRow)).withContext(`${r.id} row '${r.inventoryRow}'`).toBeTrue();
      }
    });

    it('gives each stand-in a live source in the same 6.3 row, and a dated version (the KEV snapshot)', () => {
      const standIns = registry.all().filter(r => r.fallbackFor);
      expect(standIns.map(r => r.id)).toEqual(['cisa-kev-snapshot']);
      for (const s of standIns) {
        const live = registry.get(s.fallbackFor!);
        expect(live.kind).withContext(s.id).toBe('live');
        expect(s.kind).withContext(s.id).toBe('bundled');
        expect(s.inventoryRow).withContext(s.id).toBe(live.inventoryRow);
        expect(s.version).withContext(s.id).toMatch(/snapshot of \d{4}-\d{2}-\d{2}/);
      }
    });

    it('covers every row of the checked-in section 6.3 list with at least one record', () => {
      const uncovered = SECTION_6_3_INVENTORY
        .filter(row => !row.absentToday)
        .filter(row => !registry.all().some(r => r.inventoryRow === row.source))
        .map(row => row.source);
      expect(uncovered).toEqual([]);
    });

    it('registers every named source of the multi-source rows', () => {
      for (const [row, ids] of Object.entries(REQUIRED_RECORDS_BY_ROW)) {
        for (const id of ids) {
          expect(registry.has(id)).withContext(`${row}: ${id}`).toBeTrue();
          expect(registry.get(id).inventoryRow).withContext(id).toBe(row);
        }
      }
    });

    it('names only rows that exist in the section 6.3 list', () => {
      const listed = new Set(SECTION_6_3_INVENTORY.map(row => row.source));
      expect(Object.values(INVENTORY_ROW).filter(row => !listed.has(row))).toEqual([]);
      expect(SECTION_6_3_INVENTORY.map(row => row.source).filter(s => !Object.values(INVENTORY_ROW).includes(s as never)))
        .toEqual([]);
    });

    it('registers nothing for a row the app does not ship today (ATLAS)', () => {
      for (const row of SECTION_6_3_INVENTORY.filter(r => r.absentToday)) {
        expect(registry.all().filter(r => r.inventoryRow === row.source)).withContext(row.source).toEqual([]);
      }
    });

    it('starts truthfully: nothing claims to be loaded before a loader has run, except compiled-in tables', () => {
      for (const r of registry.all()) {
        if (r.kind === 'bundled' || r.kind === 'live') {
          expect(['pending', 'archived-upstream']).withContext(r.id).toContain(r.status);
        }
        expect(r.lastLoadedAt).toBeNull();
        expect(r.lastError).toBeNull();
      }
      expect(registry.get('cis-controls').status).toBe('archived-upstream');
      expect(registry.hasData('cis-controls')).toBeFalse();
      expect(registry.get('d3fend-seed').status).toBe('stale');
    });
  });

  describe('status transitions', () => {
    it('records a failure as failed with the reason, never as loaded', () => {
      registry.begin('capec');
      expect(registry.get('capec').status).toBe('loading');
      registry.fail('capec', new HttpErrorResponse({ status: 503, statusText: 'Service Unavailable', url: 'https://x.test/a' }));
      const r = registry.get('capec');
      expect(r.status).toBe('failed');
      expect(r.lastError).toBe('HTTP 503 Service Unavailable from https://x.test/a');
      expect(r.lastLoadedAt).toBeNull();
      expect(registry.hasData('capec')).toBeFalse();
    });

    it('records a success with rows as loaded, and zero rows as empty', () => {
      registry.succeed('capec', 42);
      expect(registry.get('capec').status).toBe('loaded');
      expect(registry.get('capec').rows).toBe(42);
      expect(registry.get('capec').lastLoadedAt).not.toBeNull();
      expect(registry.hasData('capec')).toBeTrue();

      registry.succeed('elastic-tree', 0);
      expect(registry.get('elastic-tree').status).toBe('empty');
      expect(registry.hasData('elastic-tree')).toBeFalse();
    });

    it('clears a previous error when a retry starts and when it succeeds', () => {
      registry.fail('capec', 'network error');
      registry.begin('capec');
      expect(registry.get('capec').lastError).toBeNull();
      registry.succeed('capec', 1);
      expect(registry.get('capec').status).toBe('loaded');
    });

    it("keeps 'archived-upstream' and 'stale' visible after a successful load", () => {
      registry.succeed('ctid-attack-to-cve', 839);
      expect(registry.get('ctid-attack-to-cve').status).toBe('archived-upstream');
      expect(registry.hasData('ctid-attack-to-cve')).toBeTrue();
      registry.succeed('m365-hunting-queries', 10);
      expect(registry.get('m365-hunting-queries').status).toBe('archived-upstream');
    });

    it('lets a load correct the declared version from the data itself', () => {
      registry.succeed('attack-enterprise', 100, { version: '19.2' });
      expect(registry.get('attack-enterprise').version).toBe('19.2');
    });

    it('emits record changes', () => {
      const seen: string[] = [];
      const sub = registry.record$('capec').subscribe(r => seen.push(r.status));
      registry.begin('capec');
      registry.fail('capec', 'x');
      sub.unsubscribe();
      expect(seen).toEqual(['pending', 'loading', 'failed']);
    });

    it('throws for an id that is not in the inventory', () => {
      expect(() => registry.begin('no-such-source')).toThrowError(/unknown source id/);
    });
  });

  describe('describeLoadError', () => {
    it('describes HTTP, network, Error and string failures', () => {
      expect(describeLoadError(new HttpErrorResponse({ status: 0, url: 'https://x.test/' }))).toBe('network error: https://x.test/');
      expect(describeLoadError(new HttpErrorResponse({ status: 0 }))).toBe('network error (no response)');
      expect(describeLoadError(new HttpErrorResponse({ status: 503, statusText: 'Service Unavailable', url: 'https://x.test/a' })))
        .toBe('HTTP 503 Service Unavailable from https://x.test/a');
      expect(describeLoadError(new Error('boom'))).toBe('boom');
      expect(describeLoadError('blocked')).toBe('blocked');
      expect(describeLoadError(new ProgressEvent('error'))).toBe('network error');
      expect(describeLoadError(undefined)).toBe('unknown error');
    });

    it('says a 404 means the branch or path moved, with the URL when there is one', () => {
      const url = 'https://api.github.com/repos/o/r/git/trees/main?recursive=1';
      expect(describeLoadError(new HttpErrorResponse({ status: 404, statusText: 'Not Found', url })))
        .toBe(`not found (branch or path moved): ${url}`);
      expect(describeLoadError(new HttpErrorResponse({ status: 404, statusText: 'Not Found' }))).toBe('not found (branch or path moved)');
    });

    describe('rate limits', () => {
      const url = 'https://api.github.com/repos/o/r/git/trees/main?recursive=1';
      const reset = Math.floor(new Date(2026, 9, 21, 7, 4).getTime() / 1000);
      const limited = (status: number, headers: Record<string, string>, at: string | undefined = url) =>
        new HttpErrorResponse({ status, statusText: status === 429 ? 'Too Many Requests' : 'Forbidden', url: at, headers: new HttpHeaders(headers) });

      it('names a GitHub rate limit (403 or 429 with X-RateLimit-Remaining 0) and its reset time in local HH:MM', () => {
        const expected = 'GitHub rate limit reached (60 requests per hour per address); resets at 07:04';
        expect(describeLoadError(limited(403, { 'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': String(reset) }))).toBe(expected);
        expect(describeLoadError(limited(429, { 'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': String(reset) }))).toBe(expected);
      });

      it('falls back to "GitHub rate limit reached" when the reset header is absent or unreadable', () => {
        expect(describeLoadError(limited(403, { 'X-RateLimit-Remaining': '0' }))).toBe('GitHub rate limit reached');
        expect(describeLoadError(limited(403, { 'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': 'soon' }))).toBe('GitHub rate limit reached');
      });

      it('keeps a plain 403 (quota left, or no rate-limit headers) as an HTTP error', () => {
        expect(describeLoadError(limited(403, { 'X-RateLimit-Remaining': '12' }))).toBe(`HTTP 403 Forbidden from ${url}`);
        expect(describeLoadError(limited(403, {}))).toBe(`HTTP 403 Forbidden from ${url}`);
      });

      it('does not claim the GitHub limit for another host', () => {
        expect(describeLoadError(limited(429, { 'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': String(reset) }, 'https://x.test/a')))
          .toBe('rate limit reached (HTTP 429); resets at 07:04: https://x.test/a');
      });
    });
  });
});
