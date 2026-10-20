// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  Component,
  EventEmitter,
  Input,
  Output,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { DataService } from '../../services/data.service';
import { FilterService } from '../../services/filter.service';
import { LibraryLayerService, LibraryLayerMeta } from '../../services/library-layer.service';
import { ThreatProfileService } from '../../services/threat-profile.service';
import { ThreatGroup } from '../../models/group';
import { Campaign } from '../../models/campaign';
import { rankGroupsByPrevalence } from '../../models/threat-profile';

type PickerMode = 'profile' | 'single' | 'multi-local';
type Preset = 'top-groups' | 'all' | 'groups' | 'campaigns' | 'library-layer';

interface SectorCategory { readonly label: string; readonly keywords: readonly string[]; }

/** The wizard's sector keyword aid, kept so E2.6 does not lose that capability (assessment-wizard.component.ts:46). */
const SECTOR_CATEGORIES: readonly SectorCategory[] = [
  { label: 'Financial', keywords: ['financial', 'banking', 'payment', 'fin'] },
  { label: 'Government', keywords: ['government', 'military', 'defense', 'intelligence', 'political', 'embassy'] },
  { label: 'Healthcare', keywords: ['health', 'medical', 'hospital', 'pharma'] },
  { label: 'Technology', keywords: ['technology', 'software', 'telecom', 'semiconductor'] },
  { label: 'Energy', keywords: ['energy', 'oil', 'gas', 'utility', 'nuclear', 'power'] },
];

/**
 * The one group/campaign/profile picker E2.6 unifies (design P2-03). It emits STIX ids
 * only, which removes the G####-vs-STIX class of bug by construction (R4 §2). The profile
 * it edits is NOT the matrix group filter; "Use as matrix filter" is an explicit action.
 */
@Component({
  selector: 'app-threat-profile-picker',
  standalone: true,
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './threat-profile-picker.component.html',
  styleUrl: './threat-profile-picker.component.scss',
})
export class ThreatProfilePickerComponent implements OnInit, OnDestroy {
  /** 'profile' edits the shared profile; 'single' emits one group id; 'multi-local' emits a set without touching the service. */
  @Input() mode: PickerMode = 'profile';
  /** Default N for the Top-N preset. */
  @Input() topN = 20;

  /** single mode: the chosen group's STIX id. */
  @Output() groupSelected = new EventEmitter<string>();
  /** multi-local mode: the chosen group STIX ids; never mutates ThreatProfileService. */
  @Output() selectionChange = new EventEmitter<ReadonlySet<string>>();

  readonly sectors = SECTOR_CATEGORIES;
  preset: Preset = 'top-groups';
  searchText = '';
  activeSector: string | null = null;

  groups: ThreatGroup[] = [];
  campaigns: Campaign[] = [];
  layers: LibraryLayerMeta[] = [];

  /** Selected group STIX ids (groups preset, single/multi-local). */
  readonly selectedGroupIds = new Set<string>();
  selectedLayerFile: string | null = null;

  private subs = new Subscription();

  constructor(
    private dataService: DataService,
    private filterService: FilterService,
    private libraryLayers: LibraryLayerService,
    private threatProfile: ThreatProfileService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(this.dataService.domain$.subscribe((domain) => {
      this.groups = domain ? [...domain.groups].sort((a, b) => a.name.localeCompare(b.name)) : [];
      this.campaigns = domain ? [...domain.campaigns].sort((a, b) => a.name.localeCompare(b.name)) : [];
      this.cdr.markForCheck();
    }));
    // Injecting LibraryLayerService triggers its own manifest load; we only subscribe.
    this.subs.add(this.libraryLayers.manifest$.subscribe((manifest) => {
      this.layers = manifest;
      this.cdr.markForCheck();
    }));
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  setPreset(preset: Preset): void {
    this.preset = preset;
    if (this.mode === 'profile' && (preset === 'top-groups' || preset === 'all')) this.applyProfile();
    this.cdr.markForCheck();
  }

  /** Top-N ranked by prevalence, so the preview matches the profile the model builds. */
  get rankedGroups(): readonly ThreatGroup[] {
    const domain = this.dataService.getCurrentDomain();
    return domain ? rankGroupsByPrevalence(domain) : this.groups;
  }

  filteredGroups(): ThreatGroup[] {
    const q = this.searchText.trim().toLowerCase();
    const sector = this.activeSector ? this.sectors.find((s) => s.label === this.activeSector) : null;
    return this.groups.filter((g) => {
      if (q && !(g.name.toLowerCase().includes(q) || g.attackId.toLowerCase().includes(q)
        || g.aliases.some((a) => a.toLowerCase().includes(q)))) return false;
      if (sector) {
        const desc = g.description.toLowerCase();
        if (!sector.keywords.some((kw) => desc.includes(kw))) return false;
      }
      return true;
    });
  }

  toggleSector(label: string): void {
    this.activeSector = this.activeSector === label ? null : label;
    this.cdr.markForCheck();
  }

  /** Emits/mutates per mode. Every id passed here is a STIX id (group.id), never a G#### attackId. */
  selectGroup(g: ThreatGroup): void {
    if (this.mode === 'single') {
      this.groupSelected.emit(g.id);
      return;
    }
    if (this.selectedGroupIds.has(g.id)) this.selectedGroupIds.delete(g.id);
    else this.selectedGroupIds.add(g.id);
    if (this.mode === 'multi-local') {
      this.selectionChange.emit(new Set(this.selectedGroupIds));   // never touches the service
    } else {
      this.preset = 'groups';
      this.applyProfile();
    }
    this.cdr.markForCheck();
  }

  /** Campaign selection mirrors group selection; every id is a STIX campaign id. */
  selectCampaign(c: Campaign): void {
    if (this.mode === 'single') {
      this.groupSelected.emit(c.id);
      return;
    }
    if (this.selectedGroupIds.has(c.id)) this.selectedGroupIds.delete(c.id);
    else this.selectedGroupIds.add(c.id);
    if (this.mode === 'multi-local') {
      this.selectionChange.emit(new Set(this.selectedGroupIds));
    } else {
      this.preset = 'campaigns';
      this.applyProfile();
    }
    this.cdr.markForCheck();
  }

  selectLayer(file: string): void {
    this.selectedLayerFile = file;
    this.preset = 'library-layer';
    if (this.mode === 'profile') this.applyProfile();
    this.cdr.markForCheck();
  }

  /** Push the selected groups into the matrix filter. Deliberately separate from the profile (R4 risk 6). */
  useAsMatrixFilter(): void {
    for (const id of this.selectedGroupIds) this.filterService.toggleThreatGroup(id);
  }

  /** Profile mode only: build the source from the current preset and persist it on the service. */
  private applyProfile(): void {
    if (this.mode !== 'profile') return;
    switch (this.preset) {
      case 'top-groups': this.threatProfile.setSource({ kind: 'top-groups', n: this.topN }); break;
      case 'all': this.threatProfile.setSource({ kind: 'all' }); break;
      case 'groups': this.threatProfile.setSource({ kind: 'groups', ids: [...this.selectedGroupIds] }); break;
      case 'campaigns': this.threatProfile.setSource({ kind: 'campaigns', ids: [...this.selectedGroupIds] }); break;
      case 'library-layer':
        if (this.selectedLayerFile) this.threatProfile.setSource({ kind: 'library-layer', file: this.selectedLayerFile });
        break;
    }
  }
}
