// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, combineLatest, map } from 'rxjs';

export interface CloudControl {
  id: string;
  description: string;
  provider: 'aws' | 'azure' | 'gcp';
  mappingType: string;
}

@Injectable({ providedIn: 'root' })
export class CloudControlsService {
  private static readonly AWS_URL =
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/aws/attack-16.1/aws-12.12.2024/enterprise/aws-12.12.2024_attack-16.1-enterprise.json';
  private static readonly AZURE_URL =
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/azure/attack-16.1/azure-04.26.2025/enterprise/azure-04.26.2025_attack-16.1-enterprise.json';
  private static readonly GCP_URL =
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/gcp/attack-16.1/gcp-03.06.2025/enterprise/gcp-03.06.2025_attack-16.1-enterprise.json';

  private byTechniqueId = new Map<string, CloudControl[]>();

  private awsLoadedSubject = new BehaviorSubject<boolean>(false);
  private azureLoadedSubject = new BehaviorSubject<boolean>(false);
  private gcpLoadedSubject = new BehaviorSubject<boolean>(false);

  private awsTotalSubject = new BehaviorSubject<number>(0);
  private azureTotalSubject = new BehaviorSubject<number>(0);
  private gcpTotalSubject = new BehaviorSubject<number>(0);

  awsTotal$ = this.awsTotalSubject.asObservable();
  azureTotal$ = this.azureTotalSubject.asObservable();
  gcpTotal$ = this.gcpTotalSubject.asObservable();

  /** True once all three providers have loaded (or failed). */
  loaded$ = combineLatest([
    this.awsLoadedSubject,
    this.azureLoadedSubject,
    this.gcpLoadedSubject,
  ]).pipe(map(([a, b, c]) => a && b && c));

  constructor(private http: HttpClient) {
    this.loadProvider(CloudControlsService.AWS_URL, 'aws');
    this.loadProvider(CloudControlsService.AZURE_URL, 'azure');
    this.loadProvider(CloudControlsService.GCP_URL, 'gcp');
  }

  private loadProvider(url: string, provider: 'aws' | 'azure' | 'gcp'): void {
    this.http.get<any>(url).subscribe({
      next: (data) => this.parseAndIndex(data, provider),
      error: (err) => {
        console.error(`[CloudControlsService] Failed to load ${provider.toUpperCase()} mapping:`, err);
        this.markLoaded(provider, 0);
      },
    });
  }

  private parseAndIndex(data: any, provider: 'aws' | 'azure' | 'gcp'): void {
    const mappings = data?.mapping_objects ?? [];
    let count = 0;
    for (const m of mappings) {
      if (!m.attack_object_id) continue;
      const techId = m.attack_object_id as string;
      const control: CloudControl = {
        id: m.capability_id ?? '',
        description: m.capability_description ?? '',
        provider,
        mappingType: m.mapping_type ?? 'mitigates',
      };
      if (!this.byTechniqueId.has(techId)) this.byTechniqueId.set(techId, []);
      // Dedup by provider + id
      const existing = this.byTechniqueId.get(techId)!;
      if (!existing.some(c => c.id === control.id && c.provider === control.provider)) {
        existing.push(control);
        count++;
      }
    }
    this.markLoaded(provider, count);
  }

  private markLoaded(provider: 'aws' | 'azure' | 'gcp', count: number): void {
    switch (provider) {
      case 'aws':
        this.awsTotalSubject.next(count);
        this.awsLoadedSubject.next(true);
        break;
      case 'azure':
        this.azureTotalSubject.next(count);
        this.azureLoadedSubject.next(true);
        break;
      case 'gcp':
        this.gcpTotalSubject.next(count);
        this.gcpLoadedSubject.next(true);
        break;
    }
  }

  getControlsForTechnique(attackId: string, provider?: 'aws' | 'azure' | 'gcp'): CloudControl[] {
    const direct = this.byTechniqueId.get(attackId) ?? [];
    // Include subtechnique controls for parent
    let all = direct;
    if (!attackId.includes('.')) {
      const prefix = attackId + '.';
      const fromSubs = [...this.byTechniqueId.entries()]
        .filter(([k]) => k.startsWith(prefix))
        .flatMap(([, v]) => v);
      const seen = new Set<string>();
      all = [...direct, ...fromSubs].filter(c => {
        const key = `${c.provider}:${c.id}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    }
    return provider ? all.filter(c => c.provider === provider) : all;
  }

  isProviderLoaded(provider: 'aws' | 'azure' | 'gcp'): boolean {
    switch (provider) {
      case 'aws':   return this.awsLoadedSubject.value;
      case 'azure': return this.azureLoadedSubject.value;
      case 'gcp':   return this.gcpLoadedSubject.value;
    }
  }

  getProviderTotal(provider: 'aws' | 'azure' | 'gcp'): number {
    switch (provider) {
      case 'aws':   return this.awsTotalSubject.value;
      case 'azure': return this.azureTotalSubject.value;
      case 'gcp':   return this.gcpTotalSubject.value;
    }
  }
}
