import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ElasticService } from './elastic.service';

describe('ElasticService', () => {
  let service: ElasticService;
  let httpMock: HttpTestingController;

  const ELASTIC_LAYER_URL =
    'https://raw.githubusercontent.com/elastic/detection-rules/main/etc/attack-navigator-layer.json';

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    });

    service = TestBed.inject(ElasticService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  // Helper: flush the live load request that fires in the constructor
  function flushLiveLoad(layer: any = null): void {
    const req = httpMock.expectOne(ELASTIC_LAYER_URL);
    if (layer === null) {
      req.error(new ProgressEvent('error'));
    } else {
      req.flush(layer);
    }
  }

  // --- getRuleCount() ---

  it('should return 0 before any layer is loaded', () => {
    // Don't flush the request yet - test pre-load state
    expect(service.getRuleCount('T1059')).toBe(0);
    // Flush to satisfy afterEach
    flushLiveLoad(null);
  });

  it('should return the correct count after ingestLayer', () => {
    flushLiveLoad(null); // flush the constructor call with error so no data
    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1059', score: 5 },
        { techniqueID: 'T1078', score: 3 },
      ],
    });
    expect(service.getRuleCount('T1059')).toBe(5);
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
        { techniqueID: 'T1190', score: 0 }, // score 0, should be excluded
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
    // Parent should get direct + all subtechniques
    expect(service.getRuleCount('T1059')).toBe(9); // 2 + 3 + 4
  });

  it('should not roll up parent counts to subtechniques', () => {
    flushLiveLoad(null);
    service.ingestLayer({
      techniques: [
        { techniqueID: 'T1059', score: 2 },
        { techniqueID: 'T1059.001', score: 3 },
      ],
    });
    // Subtechnique should only have its own direct count
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
    // Parent has no direct count but gets subtechnique sum
    expect(service.getRuleCount('T1059')).toBe(7); // 0 + 3 + 4
  });

  // --- Live load from constructor ---

  it('should ingest the live layer from the constructor HTTP call', () => {
    flushLiveLoad({
      techniques: [
        { techniqueID: 'T1059', score: 10 },
      ],
    });
    expect(service.getRuleCount('T1059')).toBe(10);
  });

  it('should handle constructor HTTP error gracefully', () => {
    flushLiveLoad(null);
    // Service should still work, just with empty counts
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
});
