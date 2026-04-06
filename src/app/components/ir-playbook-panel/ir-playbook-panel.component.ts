// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component, ChangeDetectionStrategy, ChangeDetectorRef, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { IRPlaybookService, IRPlaybook, PlaybookStep } from '../../services/ir-playbook.service';
import { Technique } from '../../models/technique';
import { Domain } from '../../models/domain';

@Component({
  selector: 'app-ir-playbook-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './ir-playbook-panel.component.html',
  styleUrl: './ir-playbook-panel.component.scss',
})
export class IRPlaybookPanelComponent implements OnInit, OnDestroy {
  visible = false;
  domain: Domain | null = null;
  searchText = '';
  searchResults: Technique[] = [];
  playbook: IRPlaybook | null = null;
  expandedPhases = new Set<string>(['identify', 'contain', 'eradicate', 'recover', 'lessons']);
  copied = false;
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private dataService: DataService,
    private irService: IRPlaybookService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(this.filterService.activePanel$.subscribe(p => {
      this.visible = p === 'ir-playbook';
      this.cdr.markForCheck();
    }));
    this.subs.add(this.dataService.domain$.subscribe(d => {
      this.domain = d;
      this.cdr.markForCheck();
    }));
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  close(): void { this.filterService.setActivePanel(null); }

  onSearch(): void {
    if (!this.domain || this.searchText.length < 2) { this.searchResults = []; return; }
    const q = this.searchText.toLowerCase();
    this.searchResults = this.domain.techniques
      .filter(t => t.attackId.toLowerCase().includes(q) || t.name.toLowerCase().includes(q))
      .slice(0, 12);
    this.cdr.markForCheck();
  }

  selectTechnique(tech: Technique): void {
    if (!this.domain) return;
    this.playbook = this.irService.generatePlaybook(tech, this.domain);
    this.searchText = `${tech.attackId} - ${tech.name}`;
    this.searchResults = [];
    this.expandedPhases = new Set(['identify', 'contain', 'eradicate', 'recover', 'lessons']);
    this.cdr.markForCheck();
  }

  togglePhase(phase: string): void {
    if (this.expandedPhases.has(phase)) this.expandedPhases.delete(phase);
    else this.expandedPhases.add(phase);
    this.cdr.markForCheck();
  }

  getStepsForPhase(phase: string): PlaybookStep[] {
    return this.playbook?.steps.filter(s => s.phase === phase) || [];
  }

  get phaseList() {
    return [
      { id: 'identify', label: 'Identify', icon: '🔍', color: '#2196f3' },
      { id: 'contain', label: 'Contain', icon: '🛑', color: '#ff9800' },
      { id: 'eradicate', label: 'Eradicate', icon: '🗑', color: '#f44336' },
      { id: 'recover', label: 'Recover', icon: '🔄', color: '#4caf50' },
      { id: 'lessons', label: 'Lessons Learned', icon: '📝', color: '#9c27b0' },
    ];
  }

  exportMarkdown(): void {
    if (!this.playbook) return;
    const md = this.irService.exportMarkdown(this.playbook);
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: `ir-playbook-${this.playbook.techniqueId}.md` });
    a.click();
    URL.revokeObjectURL(url);
  }

  exportJson(): void {
    if (!this.playbook) return;
    const json = this.irService.exportJson(this.playbook);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: `ir-playbook-${this.playbook.techniqueId}.json` });
    a.click();
    URL.revokeObjectURL(url);
  }

  copyToClipboard(): void {
    if (!this.playbook) return;
    navigator.clipboard.writeText(this.irService.exportMarkdown(this.playbook));
    this.copied = true;
    setTimeout(() => { this.copied = false; this.cdr.markForCheck(); }, 2000);
    this.cdr.markForCheck();
  }

  copyCommand(cmd: string): void {
    navigator.clipboard.writeText(cmd);
  }

  openTechnique(attackId: string): void {
    if (!this.domain) return;
    const tech = this.domain.techniques.find(t => t.attackId === attackId);
    if (tech) this.filterService.selectTechnique(tech);
  }

  severityColor(sev: string): string {
    return { critical: '#f44336', high: '#ff9800', medium: '#ffc107', low: '#4caf50' }[sev] || '#888';
  }
}
