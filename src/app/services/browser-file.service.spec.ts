// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { BrowserFileService } from './browser-file.service';

describe('BrowserFileService', () => {
  let service: BrowserFileService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(BrowserFileService);
  });

  it('downloadBlob triggers an anchor click with given filename', () => {
    const aSpy = jasmine.createSpyObj<HTMLAnchorElement>('a', ['click']);
    Object.assign(aSpy, { href: '', download: '' });
    spyOn(document, 'createElement').and.callFake((tag: string) => {
      if (tag === 'a') return aSpy;
      return document.createElement(tag);
    });
    spyOn(URL, 'createObjectURL').and.returnValue('blob:mock');
    spyOn(URL, 'revokeObjectURL');

    service.downloadBlob(new Blob(['x']), 'file.txt');
    expect(aSpy.click).toHaveBeenCalled();
    expect(aSpy.download).toBe('file.txt');
  });

  it('downloadText wraps content in a Blob', () => {
    const aSpy = jasmine.createSpyObj<HTMLAnchorElement>('a', ['click']);
    Object.assign(aSpy, { href: '', download: '' });
    spyOn(document, 'createElement').and.callFake((tag: string) => {
      if (tag === 'a') return aSpy;
      return document.createElement(tag);
    });
    spyOn(URL, 'createObjectURL').and.returnValue('blob:mock');
    spyOn(URL, 'revokeObjectURL');

    service.downloadText('hello', 'note.txt');
    expect(aSpy.download).toBe('note.txt');
  });

  it('downloadJson serializes value to JSON', () => {
    const aSpy = jasmine.createSpyObj<HTMLAnchorElement>('a', ['click']);
    Object.assign(aSpy, { href: '', download: '' });
    spyOn(document, 'createElement').and.callFake((tag: string) => {
      if (tag === 'a') return aSpy;
      return document.createElement(tag);
    });
    spyOn(URL, 'createObjectURL').and.returnValue('blob:mock');
    spyOn(URL, 'revokeObjectURL');

    service.downloadJson({ a: 1, b: 'x' }, 'out.json');
    expect(aSpy.download).toBe('out.json');
  });
});
