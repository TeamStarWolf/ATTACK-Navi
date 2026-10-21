// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { AnnotationService } from '../../services/annotation.service';
import { AtomicService } from '../../services/atomic.service';
import { CARService } from '../../services/car.service';
import { CustomMitigationService } from '../../services/custom-mitigation.service';
import { D3fendService } from '../../services/d3fend.service';
import { DocumentationService } from '../../services/documentation.service';
import { EngageService } from '../../services/engage.service';
import { UserLayerService } from '../../services/user-layer.service';

/**
 * Keeps the boot order of the app's root services now that the command palette
 * (UniversalSearchComponent) loads in a @defer block right after first paint.
 *
 * The palette used to be the first creator of these services: its constructor
 * runs in the app template's creation pass, before the drawer (which sits in an
 * @if block and is created later). D3fendService, CARService, AtomicService and
 * EngageService start their data fetches in their constructors, so creating
 * them later would move those requests behind the ATT&CK bundle request. This
 * component sits where the palette was and creates exactly the eager services
 * the palette's construction created first, in the same order: the ones its
 * ExportActionsService reaches (documentation, custom mitigations, annotations,
 * user layers), then its own D3FEND, CAR, Atomic and Engage. The services only
 * the palette uses (export actions, reports, navigator layer, timeline, ...) are
 * created when its chunk arrives; their constructors do no network work.
 *
 * It renders nothing.
 */
@Component({
  selector: 'app-palette-warmup',
  standalone: true,
  template: '',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PaletteWarmupComponent {
  constructor() {
    inject(DocumentationService);
    inject(CustomMitigationService);
    inject(AnnotationService);
    inject(UserLayerService);
    inject(D3fendService);
    inject(CARService);
    inject(AtomicService);
    inject(EngageService);
  }
}
