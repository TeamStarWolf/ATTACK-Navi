// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { PaletteWarmupComponent } from './palette-warmup.component';
import { AnnotationService } from '../../services/annotation.service';
import { AtomicService } from '../../services/atomic.service';
import { CARService } from '../../services/car.service';
import { CustomMitigationService } from '../../services/custom-mitigation.service';
import { D3fendService } from '../../services/d3fend.service';
import { DocumentationService } from '../../services/documentation.service';
import { EngageService } from '../../services/engage.service';
import { UserLayerService } from '../../services/user-layer.service';

describe('PaletteWarmupComponent', () => {
  it('creates the services the palette used to create first, in the palette\'s order, and renders nothing', () => {
    const created: string[] = [];
    const record = (token: unknown, name: string) => ({ provide: token, useFactory: () => { created.push(name); return {}; } });
    TestBed.configureTestingModule({
      imports: [PaletteWarmupComponent],
      providers: [
        record(DocumentationService, 'documentation'),
        record(CustomMitigationService, 'custom-mitigation'),
        record(AnnotationService, 'annotation'),
        record(UserLayerService, 'user-layer'),
        record(D3fendService, 'd3fend'),
        record(CARService, 'car'),
        record(AtomicService, 'atomic'),
        record(EngageService, 'engage'),
      ],
    });
    const fixture = TestBed.createComponent(PaletteWarmupComponent);
    fixture.detectChanges();
    expect(created).toEqual(['documentation', 'custom-mitigation', 'annotation', 'user-layer', 'd3fend', 'car', 'atomic', 'engage']);
    expect((fixture.nativeElement as HTMLElement).childNodes.length).toBe(0);
  });
});
