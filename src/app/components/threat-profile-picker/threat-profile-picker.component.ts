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
import { ThreatProfileSource } from '../../models/threat-profile';

type PickerMode = 'profile' | 'single' | 'multi-local';
type Preset = 'top-groups' | 'all' | 'groups' | 'campaigns' | 'library-layer';

interface SectorCategory { readonly label: string; readonly keywords: readonly string[]; }

/**
 * The single source of the sector aid table (P2-10 moved it here and removed the
 * wizard's copy, so the same sector click matches the same groups everywhere).
 * threat-profile-picker.component.spec pins it against its own fixture.
 */
const SECTOR_CATEGORIES: readonly SectorCategory[] = [
  { label: 'Financial', keywords: ['financial', 'banking', 'payment', 'fin'] },
  { label: 'Government', keywords: ['government', 'military', 'defense', 'intelligence', 'political', 'embassy'] },
  { label: 'Healthcare', keywords: ['health', 'hospital', 'medical', 'pharma'] },
  { label: 'Technology', keywords: ['technology', 'software', 'tech', 'telecom', 'it '] },
  { label: 'Energy', keywords: ['energy', 'oil', 'gas', 'nuclear', 'power', 'utility'] },
  { label: 'Education', keywords: ['education', 'university', 'academic', 'research'] },
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

  /** single mode: the chosen group's STIX intrusion-set id (never a campaign). */
  @Output() groupSelected = new EventEmitter<string>();
  /** multi-local mode: the active preset's selected STIX ids; never mutates ThreatProfileService. */
  @Output() selectionChange = new EventEmitter<ReadonlySet<string>>();

  readonly sectors = SECTOR_CATEGORIES;
  preset: Preset = 'top-groups';
  searchText = '';
  activeSector: string | null = null;

  groups: ThreatGroup[] = [];
  campaigns: Campaign[] = [];
  layers: LibraryLayerMeta[] = [];

  /** Group and campaign selections are kept apart so a profile source never mixes id kinds. */
  readonly selectedGroupIds = new Set<string>();
  readonly selectedCampaignIds = new Set<string>();
  selectedLayerFile: string | null = null;

  private subs = new Subscription();
  /**
   * The last source the picker seeded from or applied, as a stable string. A profile$
   * re-emission with the same source (a domain switch, which emits null then the new
   * domain, or a library-layer load finishing) must NOT re-run initFromProfile and reset
   * the user's open tab / selection before they have picked anything.
   */
  private lastSource: string | null = null;

  constructor(
    private dataService: DataService,
    private filterService: FilterService,
    private libraryLayers: LibraryLayerService,
    private threatProfile: ThreatProfileService,
    private cdr: ChangeDetectorRef,
  ) {}

  /** Campaigns, All and Library layer make no sense when the caller wants exactly one group. */
  get showPresetTabs(): boolean { return this.mode !== 'single'; }

  ngOnInit(): void {
    if (this.mode === 'single') {
      this.preset = 'groups';
    } else if (this.mode === 'profile') {
      this.initFromProfile(this.threatProfile.current.source);
      // Stay in sync if the shared profile's SOURCE changes elsewhere, but ignore
      // re-emissions of the same source (domain switch, layer load) so they do not
      // reset the user's open tab before they have applied anything.
      this.subs.add(this.threatProfile.profile$.subscribe((p) => {
        if (this.serializeSource(p.source) === this.lastSource) return;
        this.initFromProfile(p.source);
        this.cdr.markForCheck();
      }));
    }
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

  /** Reflect the stored profile source so the first click does not silently replace it. */
  private initFromProfile(src: ThreatProfileSource): void {
    this.preset = src.kind;
    this.selectedGroupIds.clear();
    this.selectedCampaignIds.clear();
    this.selectedLayerFile = null;
    switch (src.kind) {
      case 'top-groups': this.topN = src.n; break;
      case 'groups': for (const id of src.ids) this.selectedGroupIds.add(id); break;
      case 'campaigns': for (const id of src.ids) this.selectedCampaignIds.add(id); break;
      case 'library-layer': this.selectedLayerFile = src.file; break;
      case 'all': break;
    }
    this.lastSource = this.serializeSource(src);
  }

  /** A stable string for a source, so profile$ re-emissions of the same source compare equal (ids order-independent). */
  private serializeSource(src: ThreatProfileSource): string {
    switch (src.kind) {
      case 'top-groups': return `top-groups:${src.n}`;
      case 'groups': return `groups:${[...src.ids].sort().join(',')}`;
      case 'campaigns': return `campaigns:${[...src.ids].sort().join(',')}`;
      case 'library-layer': return `library-layer:${src.file}`;
      case 'all': return 'all';
    }
  }

  setPreset(preset: Preset): void {
    this.preset = preset;
    // A preset switch clears the other id kind so a source never mixes groups and campaigns.
    if (preset !== 'groups') this.selectedGroupIds.clear();
    if (preset !== 'campaigns') this.selectedCampaignIds.clear();
    if (preset !== 'library-layer') this.selectedLayerFile = null;
    if (this.mode === 'profile' && (preset === 'top-groups' || preset === 'all')) this.applyProfile();
    this.cdr.markForCheck();
  }

  onTopNChange(): void {
    this.topN = this.clampTopN(this.topN);
    if (this.mode === 'profile') this.applyProfile();
    this.cdr.markForCheck();
  }

  // Enforce an integer in [1, 1000] (the stored-source guard's upper bound) only — NEVER the
  // current domain's group count. `groups` is [] while domain$ is null (e.g. mid domain switch),
  // so clamping to groups.length here would persist n=1, and that stored value outlives the
  // switch. resolveProfile clamps to the real group count at resolve time (threat-profile.ts).
  private clampTopN(n: number): number {
    const i = Number.isFinite(n) ? Math.trunc(n) : 1;
    return Math.min(Math.max(i, 1), 1000);
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

  /** Group selection. Every id is a STIX intrusion-set id (group.id), never a G#### attackId. */
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

  /** Campaign selection (STIX campaign ids). Not available in single mode, which emits one group only. */
  selectCampaign(c: Campaign): void {
    if (this.mode === 'single') return;
    if (this.selectedCampaignIds.has(c.id)) this.selectedCampaignIds.delete(c.id);
    else this.selectedCampaignIds.add(c.id);
    if (this.mode === 'multi-local') {
      this.selectionChange.emit(new Set(this.selectedCampaignIds));
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

  /** Push the selected GROUPS into the matrix filter. Deliberately separate from the profile (R4 risk 6). */
  useAsMatrixFilter(): void {
    for (const id of this.selectedGroupIds) this.filterService.toggleThreatGroup(id);
  }

  /** Profile mode only: build the source from the current preset and persist it on the service. */
  private applyProfile(): void {
    if (this.mode !== 'profile') return;
    let src: ThreatProfileSource | null = null;
    switch (this.preset) {
      case 'top-groups': src = { kind: 'top-groups', n: this.clampTopN(this.topN) }; break;
      case 'all': src = { kind: 'all' }; break;
      case 'groups': src = { kind: 'groups', ids: [...this.selectedGroupIds] }; break;
      case 'campaigns': src = { kind: 'campaigns', ids: [...this.selectedCampaignIds] }; break;
      case 'library-layer': if (this.selectedLayerFile) src = { kind: 'library-layer', file: this.selectedLayerFile }; break;
    }
    if (!src) return;
    // Record before setSource: the service re-emits on profile$ synchronously, and the
    // subscription above must treat that echo as the same source, not re-seed over it.
    this.lastSource = this.serializeSource(src);
    this.threatProfile.setSource(src);
  }
}
