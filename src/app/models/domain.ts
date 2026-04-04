import { Tactic } from './tactic';
import { Technique } from './technique';
import { Mitigation, MitigationRelationship } from './mitigation';
import { ThreatGroup } from './group';
import { AttackSoftware } from './software';
import { ProcedureExample } from './procedure';
import { MitreDataSource, MitreDataComponent } from './datasource';
import { Campaign } from './campaign';

export interface TacticColumn {
  tactic: Tactic;
  techniques: Technique[]; // parent techniques only, sorted by attackId
}

export interface Domain {
  name: string;
  attackVersion: string;  // e.g. "16.1"
  attackModified: string; // ISO date from x-mitre-collection
  tactics: Tactic[];
  techniques: Technique[];   // all techniques (parents + subtechniques)
  mitigations: Mitigation[];
  tacticColumns: TacticColumn[];
  mitigationsByTechnique: Map<string, MitigationRelationship[]>; // keyed by technique STIX id
  techniquesByMitigation: Map<string, Technique[]>;              // keyed by mitigation STIX id
  maxMitigationCount: number;
  groups: ThreatGroup[];
  groupsByTechnique: Map<string, ThreatGroup[]>;  // technique STIX id → groups using it
  techniquesByGroup: Map<string, Technique[]>;    // group STIX id → techniques it uses
  software: AttackSoftware[];
  softwareByTechnique: Map<string, AttackSoftware[]>; // technique STIX id → software using it
  techniquesBySoftware: Map<string, Technique[]>;     // software STIX id → techniques it uses
  proceduresByTechnique: Map<string, ProcedureExample[]>; // technique STIX id → procedure examples
  dataSources: MitreDataSource[];
  dataComponents: MitreDataComponent[];
  techniquesByDataComponent: Map<string, Technique[]>; // data component STIX id → techniques it detects
  dataComponentsByTechnique: Map<string, MitreDataComponent[]>; // technique STIX id → data components that detect it
  campaigns: Campaign[];
  campaignsByTechnique: Map<string, Campaign[]>;  // technique STIX id → campaigns using it
  techniquesByCampaign: Map<string, Technique[]>; // campaign STIX id → techniques it uses
}
