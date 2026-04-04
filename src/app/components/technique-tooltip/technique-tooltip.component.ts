import {
  Component,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Technique } from '../../models/technique';

@Component({
  selector: 'app-technique-tooltip',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './technique-tooltip.component.html',
  styleUrl: './technique-tooltip.component.scss',
})
export class TechniqueTooltipComponent {
  technique: Technique | null = null;
  x = 0;
  y = 0;
  mitigationCount = 0;
  threatGroupCount = 0;
  visible = false;

  constructor(private cdr: ChangeDetectorRef) {}

  show(tech: Technique, mitCount: number, groupCount: number, mouseX: number, mouseY: number): void {
    this.technique = tech;
    this.mitigationCount = mitCount;
    this.threatGroupCount = groupCount;
    this.visible = true;
    this.positionAt(mouseX, mouseY);
    this.cdr.markForCheck();
  }

  hide(): void {
    this.visible = false;
    this.technique = null;
    this.cdr.markForCheck();
  }

  private positionAt(mx: number, my: number): void {
    const CARD_W = 320;
    const CARD_H = 180;
    const margin = 12;
    this.x = mx + margin + CARD_W > window.innerWidth ? mx - CARD_W - margin : mx + margin;
    this.y = my + margin + CARD_H > window.innerHeight ? my - CARD_H - margin : my + margin;
    this.cdr.markForCheck();
  }
}
