// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { GraphFocusService, GraphFocus } from './graph-focus.service';

describe('GraphFocusService', () => {
  let service: GraphFocusService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(GraphFocusService);
  });

  it('is created', () => {
    expect(service).toBeTruthy();
  });

  it('starts with a null focus', () => {
    expect(service.focus$.value).toBeNull();
  });

  it('focusNode() publishes the requested kind + id', () => {
    service.focusNode('group', 'intrusion-set--abc');
    expect(service.focus$.value).toEqual({ kind: 'group', id: 'intrusion-set--abc' });
  });

  it('focusNode() emits to subscribers', () => {
    const seen: (GraphFocus | null)[] = [];
    const sub = service.focus$.subscribe(f => seen.push(f));
    service.focusNode('software', 'malware--xyz');
    sub.unsubscribe();
    // First replayed value is the initial null, then the pushed focus.
    expect(seen[0]).toBeNull();
    expect(seen[seen.length - 1]).toEqual({ kind: 'software', id: 'malware--xyz' });
  });

  it('clear() resets the focus to null', () => {
    service.focusNode('campaign', 'campaign--c1');
    service.clear();
    expect(service.focus$.value).toBeNull();
  });
});
