// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { PageSectionComponent } from './page-section.component';

@Component({
  standalone: true,
  imports: [PageSectionComponent],
  template: `
    <app-page-section [title]="title" icon="info">
      <button section-actions class="test-action">Act</button>
      <p class="test-body">Body content</p>
    </app-page-section>
  `,
})
class HostComponent {
  title = 'My Section';
}

describe('PageSectionComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [HostComponent] }).compileComponents();
  });

  it('renders title, icon, projected actions, and body content', () => {
    const fixture = TestBed.createComponent(HostComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('.page-section-head h2')?.textContent).toContain('My Section');
    expect(el.querySelector('.page-section-head app-icon svg')).toBeTruthy();
    expect(el.querySelector('.page-section-head .test-action')).toBeTruthy();
    expect(el.querySelector('.page-section-body .test-body')?.textContent).toContain('Body content');
  });

  it('omits the header entirely when no title is given', () => {
    const fixture = TestBed.createComponent(HostComponent);
    fixture.componentInstance.title = '';
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.page-section-head')).toBeNull();
    expect(fixture.nativeElement.querySelector('.page-section-body')).toBeTruthy();
  });
});
