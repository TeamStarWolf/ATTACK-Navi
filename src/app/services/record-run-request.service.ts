// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// "Record a run" (RP-F decision 31): the evidence card's action on a range
// telemetry partial. Range telemetry with no alerting detection is never Confirmed
// into self-attested coverage; the card asks for a run instead. It leaves the
// technique here and opens Detect > Validation, whose workbench takes it and opens
// the Record Run form with that technique preselected.
import { Injectable, inject } from '@angular/core';
import { BehaviorSubject, type Observable } from 'rxjs';
import { PanelNavService } from './panel-nav.service';

@Injectable({ providedIn: 'root' })
export class RecordRunRequestService {
  private readonly panelNav = inject(PanelNavService);
  private readonly pending = new BehaviorSubject<string | null>(null);

  /** The pending technique (ATT&CK id), or null; a workbench already on screen takes it as it arrives. */
  readonly requests$: Observable<string | null> = this.pending.asObservable();

  /** Ask the Detection Validation workbench to record a run of `attackId`, and open it. */
  request(attackId: string): void {
    this.pending.next(attackId);
    this.panelNav.open('validation');
  }

  /** The technique a "Record a run" asked for, once (null when none is pending). */
  take(): string | null {
    const id = this.pending.value;
    if (id !== null) this.pending.next(null);
    return id;
  }
}
