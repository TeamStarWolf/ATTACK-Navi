// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  ViewChild,
  ElementRef,
} from '@angular/core';
import { CommonModule, AsyncPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Observable, Subscription } from 'rxjs';
import { LayersService, LayerSnapshot } from '../../services/layers.service';
import { FilterService } from '../../services/filter.service';
import { ImplementationService } from '../../services/implementation.service';
import { DocumentationService } from '../../services/documentation.service';

@Component({
  selector: 'app-layers-panel',
  standalone: true,
  imports: [CommonModule, FormsModule, AsyncPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './layers-panel.component.html',
  styleUrl: './layers-panel.component.scss',
})
export class LayersPanelComponent implements OnInit, OnDestroy {
  @ViewChild('fileInput') fileInputRef!: ElementRef<HTMLInputElement>;

  layers$!: Observable<LayerSnapshot[]>;
  open = false;
  newLayerName = '';
  newLayerDesc = '';
  showSaveForm = false;
  importError = '';

  private subs = new Subscription();

  constructor(
    private layersService: LayersService,
    private filterService: FilterService,
    private implService: ImplementationService,
    private docService: DocumentationService,
    private cdr: ChangeDetectorRef,
  ) {
    this.layers$ = this.layersService.layers$;
  }

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.open = p === 'layers';
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void { this.subs.unsubscribe(); }

  save(): void {
    const name = this.newLayerName.trim();
    if (!name) return;
    this.layersService.saveLayer(name, this.newLayerDesc.trim(), this.filterService, this.implService, this.docService);
    this.newLayerName = '';
    this.newLayerDesc = '';
    this.showSaveForm = false;
    this.cdr.markForCheck();
  }

  load(id: string): void {
    this.layersService.loadLayer(id, this.filterService, this.implService, this.docService);
    this.filterService.setActivePanel(null);
  }

  delete(id: string): void {
    this.layersService.deleteLayer(id);
  }

  export(layer: LayerSnapshot): void {
    this.layersService.exportLayer(layer);
  }

  duplicate(id: string): void {
    this.layersService.duplicateLayer(id);
  }

  triggerImport(): void {
    this.fileInputRef?.nativeElement.click();
  }

  onFileImport(event: Event): void {
    this.importError = '';
    const file = (event.target as HTMLInputElement).files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const json = ev.target?.result as string;
      try {
        this.layersService.importLayer(json);
        this.cdr.markForCheck();
      } catch {
        this.importError = 'Failed to import layer — invalid JSON.';
        this.cdr.markForCheck();
      }
    };
    reader.readAsText(file);
    // Reset so the same file can be re-imported
    (event.target as HTMLInputElement).value = '';
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }

  formatDate(iso: string): string {
    try {
      return new Date(iso).toLocaleString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: 'numeric', minute: '2-digit',
      });
    } catch {
      return iso;
    }
  }
}
