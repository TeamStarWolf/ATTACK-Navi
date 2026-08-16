// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, ChangeDetectionStrategy, inject } from '@angular/core';

import { FormsModule } from '@angular/forms';
import { PanelNavService } from '../../services/panel-nav.service';

interface QuickStartCard {
  icon: string;
  label: string;
  panel: string;
}

@Component({
  selector: 'app-onboarding',
  standalone: true,
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './onboarding.component.html',
  styleUrl: './onboarding.component.scss',
})
export class OnboardingComponent {
  private readonly STORAGE_KEY = 'onboarding-completed';
  private panelNav = inject(PanelNavService);

  visible = !localStorage.getItem(this.STORAGE_KEY);
  currentStep = 0;
  dontShowAgain = false;

  readonly totalSteps = 3;

  readonly quickCards: QuickStartCard[] = [
    { icon: '\u{1F50D}', label: 'Run Assessment', panel: 'assessment' },
    { icon: '\u{1F4CA}', label: 'View Gaps', panel: 'gap-analysis' },
    { icon: '\u{1F6E1}', label: 'Browse Intel', panel: 'intelligence' },
    { icon: '\u{1F4E6}', label: 'Import Assets', panel: 'assets' },
  ];

  nextStep(): void {
    if (this.currentStep < this.totalSteps - 1) {
      this.currentStep++;
    }
  }

  prevStep(): void {
    if (this.currentStep > 0) {
      this.currentStep--;
    }
  }

  goToStep(step: number): void {
    this.currentStep = step;
  }

  dismiss(): void {
    this.visible = false;
    if (this.dontShowAgain) {
      localStorage.setItem(this.STORAGE_KEY, 'true');
    }
  }

  getStarted(): void {
    localStorage.setItem(this.STORAGE_KEY, 'true');
    this.visible = false;
  }

  openPanel(panel: string): void {
    this.panelNav.open(panel);
    this.getStarted();
  }
}
