// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { SplunkContentService } from './splunk-content.service';
import { SourceRegistryService, TRUNCATED_LISTING } from './source-registry.service';
import TREES from '../../testing/fixtures/github-tree-listings.json';

describe('SplunkContentService', () => {
  let service: SplunkContentService;
  let httpMock: HttpTestingController;
  let registry: SourceRegistryService;

  // Service now scans the GitHub tree instead of fetching a pre-built layer
  const SPLUNK_TREE_URL =
    'https://api.github.com/repos/splunk/security_content/git/trees/develop?recursive=1';

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });

    service = TestBed.inject(SplunkContentService);
    httpMock = TestBed.inject(HttpTestingController);
    registry = TestBed.inject(SourceRegistryService);
  });

  afterEach(() => {
    httpMock.verify();
  });

  // Helper: flush the live load request that fires in the constructor.
  // Pass null to simulate an HTTP error; pass a tree object to simulate success.
  function flushLiveLoad(tree: any = null): void {
    const req = httpMock.expectOne(SPLUNK_TREE_URL);
    if (tree === null) {
      req.error(new ProgressEvent('error'));
    } else {
      req.flush(tree);
    }
  }

  // --- getRuleCount() ---

  it('should return 0 before any layer is loaded', () => {
    expect(service.getRuleCount('T1059')).toBe(0);
    flushLiveLoad(null);
  });

  it('should return the correct count after ingestLayer', () => {
    flushLiveLoad(null);
    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1059', score: 5 },
        { techniqueID: 'T1078', score: 3 },
      ],
    });
    expect(service.getRuleCount('T1059')).toBe(5);
    expect(service.getRuleCount('T1078')).toBe(3);
  });

  it('should return 0 for a technique not in the layer', () => {
    flushLiveLoad(null);
    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1059', score: 5 },
      ],
    });
    expect(service.getRuleCount('T9999')).toBe(0);
  });

  // --- getHeatScore() ---

  it('should return the same value as getRuleCount (alias)', () => {
    flushLiveLoad(null);
    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1059', score: 7 },
      ],
    });
    expect(service.getHeatScore('T1059')).toBe(service.getRuleCount('T1059'));
  });

  // --- ingestLayer() ---

  it('should parse a Navigator layer and update loaded$', () => {
    flushLiveLoad(null);
    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1059', score: 5 },
      ],
    });
    let loaded = false;
    service.loaded$.subscribe(val => { loaded = val; });
    expect(loaded).toBeTrue();
  });

  it('should update total$ with the sum of all scores', () => {
    flushLiveLoad(null);
    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1059', score: 5 },
        { techniqueID: 'T1078', score: 3 },
      ],
    });
    let total = 0;
    service.total$.subscribe(val => { total = val; });
    expect(total).toBe(8);
  });

  it('should update covered$ with the count of covered techniques', () => {
    flushLiveLoad(null);
    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1059', score: 5 },
        { techniqueID: 'T1078', score: 3 },
        { techniqueID: 'T1190', score: 0 },
      ],
    });
    let covered = 0;
    service.covered$.subscribe(val => { covered = val; });
    expect(covered).toBe(2);
  });

  it('should skip entries with score <= 0', () => {
    flushLiveLoad(null);
    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1059', score: 0 },
        { techniqueID: 'T1078', score: -1 },
      ],
    });
    expect(service.getRuleCount('T1059')).toBe(0);
    expect(service.getRuleCount('T1078')).toBe(0);
  });

  it('should skip entries without a techniqueID', () => {
    flushLiveLoad(null);
    service.ingestLayer({
      techniques: [
        { techniqueID: '', score: 5 },
        { techniqueID: 'T1059', score: 3 },
      ],
    });
    expect(service.getRuleCount('T1059')).toBe(3);
  });

  // --- Parent technique rollup ---

  it('should roll up subtechnique counts to the parent technique', () => {
    flushLiveLoad(null);
    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1059', score: 2 },
        { techniqueID: 'T1059.001', score: 3 },
        { techniqueID: 'T1059.002', score: 4 },
      ],
    });
    expect(service.getRuleCount('T1059')).toBe(9);
  });

  it('should not roll up parent counts to subtechniques', () => {
    flushLiveLoad(null);
    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1059', score: 2 },
        { techniqueID: 'T1059.001', score: 3 },
      ],
    });
    expect(service.getRuleCount('T1059.001')).toBe(3);
  });

  it('should roll up to parent even when parent has no direct score', () => {
    flushLiveLoad(null);
    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1059.001', score: 3 },
        { techniqueID: 'T1059.002', score: 4 },
      ],
    });
    expect(service.getRuleCount('T1059')).toBe(7);
  });

  // --- Live load from constructor (GitHub tree scan) ---

  it('reads no technique id from a real-shaped Splunk listing and records the source as empty, rows 0', () => {
    // An abridged real listing: upstream files are named by behaviour
    // ('detections/application/aws_bedrock_claude_excessive_use_of_tokens.yml') and keep the ids in the file body.
    const listing = TREES.splunk.listing;
    expect(listing.tree.some(e => e.path === 'detections/application/aws_bedrock_claude_excessive_use_of_tokens.yml')).toBeTrue();
    flushLiveLoad(listing);
    const record = registry.get('splunk-tree');
    expect(record.status).toBe('empty');
    expect(record.rows).toBe(0);
    expect(record.lastError).toBeNull();
    expect(service.getRuleCount('T1114')).toBe(0);
  });

  it('synthetic: counts a rule path that does carry a technique id (keeps the path regex covered)', () => {
    flushLiveLoad({ truncated: false, tree: [{ path: 'detections/endpoint/T1059_synthetic.yml', type: 'blob' }] });
    expect(service.getRuleCount('T1059')).toBe(1);
    expect(registry.get('splunk-tree').status).toBe('loaded');
    expect(registry.get('splunk-tree').rows).toBe(1);
  });

  it('records a GitHub rate limit (403, X-RateLimit-Remaining 0) as failed, with the reset time', () => {
    const reset = Math.floor(new Date(2026, 9, 21, 14, 5).getTime() / 1000);
    httpMock.expectOne(SPLUNK_TREE_URL).flush(
      { message: 'API rate limit exceeded for 203.0.113.7.' },
      { status: 403, statusText: 'Forbidden', headers: { 'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': String(reset) } },
    );
    const record = registry.get('splunk-tree');
    expect(record.status).toBe('failed');
    expect(record.lastError).toBe('GitHub rate limit reached (60 requests per hour per address); resets at 14:05');
  });

  it('records a 404 as not found (branch or path moved), with the URL', () => {
    httpMock.expectOne(SPLUNK_TREE_URL).flush({ message: 'Not Found' }, { status: 404, statusText: 'Not Found' });
    expect(registry.get('splunk-tree').status).toBe('failed');
    expect(registry.get('splunk-tree').lastError).toBe(`not found (branch or path moved): ${SPLUNK_TREE_URL}`);
  });

  it('records status 0 as a network error, with the URL', () => {
    flushLiveLoad(null);
    expect(registry.get('splunk-tree').status).toBe('failed');
    expect(registry.get('splunk-tree').lastError).toBe(`network error: ${SPLUNK_TREE_URL}`);
  });

  it('does not parse a truncated listing: failed, with the truncated wording, and no ids recorded', () => {
    flushLiveLoad({ truncated: true, tree: [{ path: 'detections/endpoint/T1059_synthetic.yml', type: 'blob' }] });
    const record = registry.get('splunk-tree');
    expect(record.status).toBe('failed');
    expect(record.lastError).toBe(TRUNCATED_LISTING);
    expect(record.rows).toBeNull();
    expect(service.getRuleCount('T1059')).toBe(0);
  });

  it('records a parse error thrown inside the response handler as failed, not loading', () => {
    // A listing whose tree is not a list makes the parser throw.
    flushLiveLoad({ truncated: false, tree: 42 });
    expect(registry.get('splunk-tree').status).toBe('failed');
    expect(registry.get('splunk-tree').lastError).toContain('not iterable');
  });

  it('should handle constructor HTTP error gracefully', () => {
    flushLiveLoad(null);
    expect(service.getRuleCount('T1059')).toBe(0);
  });

  it('should clear old counts when ingestLayer is called again', () => {
    flushLiveLoad(null);
    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1059', score: 5 },
      ],
    });
    expect(service.getRuleCount('T1059')).toBe(5);

    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1078', score: 3 },
      ],
    });
    expect(service.getRuleCount('T1059')).toBe(0);
    expect(service.getRuleCount('T1078')).toBe(3);
  });

  it('should handle empty techniques array', () => {
    flushLiveLoad(null);
    service.ingestLayer({ techniques: [] });
    let total = 0;
    service.total$.subscribe(val => { total = val; });
    expect(total).toBe(0);
  });

  it('should handle missing score (default to 0, skipped)', () => {
    flushLiveLoad(null);
    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1059' } as any,
      ],
    });
    expect(service.getRuleCount('T1059')).toBe(0);
  });
});
