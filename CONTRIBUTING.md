# Contributing to ATTACK-Navi

Thanks for your interest in contributing! This document describes how to set up the development environment, follow code conventions, and extend ATTACK-Navi with new features.

---

## Table of Contents

1. [Development Setup](#1-development-setup)
2. [Code Conventions](#2-code-conventions)
3. [Adding a New Service](#3-adding-a-new-service)
4. [Adding a New Heatmap Mode](#4-adding-a-new-heatmap-mode)
5. [Adding a New Panel](#5-adding-a-new-panel)
6. [Adding a Sidebar Section](#6-adding-a-sidebar-section)
7. [Styling Guide](#7-styling-guide)
8. [Commit Convention](#8-commit-convention)

---

## 1. Development Setup

### Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Node.js | 20+ | LTS recommended |
| npm | 9+ | Comes with Node.js 20 |
| Angular CLI | 19.x | Installed as a dev dependency |
| Git | 2.x+ | For version control |

### Install Dependencies

```bash
git clone <repository-url>
cd mitre-mitigation-navigator
npm ci
```

Use `npm ci` (not `npm install`) for reproducible builds from the lockfile.

### Serve Locally

```bash
npm start
```

This runs `ng serve` and opens the development server at `http://localhost:4200/`. The app hot-reloads on file changes.

### Run Tests

```bash
npm test
```

This runs `ng test` using Karma with Chrome. Tests use Jasmine for assertions.

### Build for Production

```bash
npx ng build
```

Output is written to `dist/mitre-mitigation-navigator/browser/`. For GitHub Pages deployment with a base path:

```bash
npx ng build --base-href /ATTACK-Navi/
```

### Project Structure

```
src/
  app/
    components/         # UI components (one directory per component)
      matrix/           # ATT&CK matrix grid
      sidebar/          # Technique detail sidebar
      nav-rail/         # Left navigation rail
      toolbar/          # Top toolbar
      settings-panel/   # Settings overlay
      ...               # ~35+ panel components
    models/             # TypeScript interfaces (technique, mitigation, group, etc.)
    pipes/              # Angular pipes (attackText, etc.)
    services/           # Injectable services (~40+ services)
    app.component.ts    # Root component
    app.component.html  # Root template
  assets/               # Static assets (bundled STIX data, Navigator layers)
  styles.scss           # Global styles
```

---

## 2. Code Conventions

### Angular 19 Standalone Components

All components use the standalone pattern. There are no NgModules.

```typescript
@Component({
  selector: 'app-my-panel',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './my-panel.component.html',
  styleUrl: './my-panel.component.scss',
})
export class MyPanelComponent implements OnInit, OnDestroy {
  // ...
}
```

Key conventions:
- Every component uses `standalone: true`
- Every component uses `ChangeDetectionStrategy.OnPush` for performance
- Imports are declared per-component in the `imports` array
- The root `AppComponent` imports all panel components directly

### OnPush Change Detection

With `OnPush`, Angular only re-renders a component when:
- An `@Input()` reference changes
- An event fires from the component's template
- `ChangeDetectorRef.markForCheck()` is called explicitly
- An `async` pipe receives a new value

Always inject `ChangeDetectorRef` and call `this.cdr.markForCheck()` after subscription callbacks that modify component state:

```typescript
constructor(private cdr: ChangeDetectorRef) {}

ngOnInit(): void {
  this.subs.add(
    this.someService.data$.subscribe(data => {
      this.localData = data;
      this.cdr.markForCheck();  // Required for OnPush
    }),
  );
}
```

### RxJS Patterns

Services expose state via `BehaviorSubject` with a public `Observable`:

```typescript
private dataSubject = new BehaviorSubject<MyData | null>(null);
data$: Observable<MyData | null> = this.dataSubject.asObservable();
```

Components subscribe in `ngOnInit` and unsubscribe in `ngOnDestroy` using a `Subscription` collector:

```typescript
private subs = new Subscription();

ngOnInit(): void {
  this.subs.add(
    this.myService.data$.subscribe(d => {
      this.data = d;
      this.cdr.markForCheck();
    }),
  );
}

ngOnDestroy(): void {
  this.subs.unsubscribe();
}
```

For combining multiple streams, use `combineLatest`:

```typescript
this.subs.add(
  combineLatest([
    this.filterService.heatmapMode$,
    this.dataService.domain$,
  ]).subscribe(([mode, domain]) => {
    // React to either changing
  }),
);
```

### SCSS Scoping

Each component has its own `.scss` file. Styles are scoped to the component by Angular's view encapsulation. Use the `:host` selector to style the component's root element:

```scss
:host {
  display: block;
  background: rgba(5, 13, 20, 0.82);
}
```

---

## 3. Adding a New Service

Services are the data layer. Each service manages a specific data domain (CVEs, Sigma rules, NIST controls, etc.) and exposes reactive state to components.

### Template

Create a new file at `src/app/services/my-feature.service.ts`:

```typescript
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, catchError, of } from 'rxjs';

export interface MyFeatureData {
  techniqueId: string;
  // ... feature-specific fields
}

@Injectable({ providedIn: 'root' })
export class MyFeatureService {
  private dataSubject = new BehaviorSubject<Map<string, MyFeatureData[]>>(new Map());
  private loadingSubject = new BehaviorSubject<boolean>(false);
  private loadedSubject = new BehaviorSubject<boolean>(false);

  data$: Observable<Map<string, MyFeatureData[]>> = this.dataSubject.asObservable();
  loading$: Observable<boolean> = this.loadingSubject.asObservable();
  loaded$: Observable<boolean> = this.loadedSubject.asObservable();

  constructor(private http: HttpClient) {}

  load(): void {
    if (this.loadedSubject.value || this.loadingSubject.value) return;
    this.loadingSubject.next(true);

    this.http.get<any>('assets/my-feature-data.json').pipe(
      catchError(err => {
        console.error('[MyFeatureService] Failed to load data:', err);
        return of(null);
      }),
    ).subscribe(raw => {
      if (raw) {
        const map = this.parseData(raw);
        this.dataSubject.next(map);
        this.loadedSubject.next(true);
      }
      this.loadingSubject.next(false);
    });
  }

  getForTechnique(techniqueId: string): MyFeatureData[] {
    return this.dataSubject.value.get(techniqueId) ?? [];
  }

  getCount(techniqueId: string): number {
    return this.getForTechnique(techniqueId).length;
  }

  private parseData(raw: any): Map<string, MyFeatureData[]> {
    const map = new Map<string, MyFeatureData[]>();
    // Parse raw data into the map keyed by technique ID
    return map;
  }
}
```

### Key Patterns

1. **Use `providedIn: 'root'`** so the service is a singleton available everywhere without explicit provider registration.

2. **Expose BehaviorSubjects as Observables** to prevent external code from calling `.next()`.

3. **Guard against duplicate loads** by checking `loadedSubject.value` and `loadingSubject.value` before making HTTP calls.

4. **Use `catchError`** to handle network failures gracefully. Log the error and return a safe fallback.

5. **Provide synchronous accessors** like `getForTechnique()` for components that need immediate values without subscribing.

### localStorage Persistence (Optional)

If the service needs to persist user data:

```typescript
private readonly STORAGE_KEY = 'mitre-nav-my-feature-v1';

private load(): Map<string, MyFeatureData[]> {
  try {
    const raw = localStorage.getItem(this.STORAGE_KEY);
    if (!raw) return new Map();
    return new Map(JSON.parse(raw));
  } catch {
    return new Map();
  }
}

private persist(): void {
  try {
    const entries = [...this.dataSubject.value.entries()];
    localStorage.setItem(this.STORAGE_KEY, JSON.stringify(entries));
  } catch { /* quota exceeded */ }
}
```

---

## 4. Adding a New Heatmap Mode

Heatmap modes color the matrix cells based on different data dimensions. The pipeline involves seven steps across four files.

### Step 1: Add the Mode to the HeatmapMode Type

**File:** `src/app/services/filter.service.ts`

Add your mode to the `HeatmapMode` type union:

```typescript
export type HeatmapMode = 'coverage' | 'exposure' | ... | 'my-mode';
```

### Step 2: Compute the Score in MatrixComponent

**File:** `src/app/components/matrix/matrix.component.ts`

Find the method that computes heatmap scores (typically a switch/if block on `this.heatmapMode`). Add a case for your mode:

```typescript
case 'my-mode':
  return this.myFeatureService.getCount(technique.attackId);
```

Inject your service in the component's constructor.

### Step 3: Map Score to Color

**File:** `src/app/components/matrix/matrix.component.ts`

The matrix maps numeric scores to colors using the active color theme. Ensure your score returns a value in the expected range (typically 0 to N where higher means more coverage).

### Step 4: Add the Mode to the Toolbar Selector

**File:** `src/app/components/toolbar/toolbar.component.ts` (or `.html`)

Add an option to the heatmap mode dropdown so users can select your mode from the toolbar.

### Step 5: Update the Legend

**File:** `src/app/components/legend/legend.component.ts`

Add a label and description for your mode so the legend bar explains what the colors mean.

### Step 6: Add Tooltip Text

**File:** `src/app/components/technique-cell/technique-cell.component.ts` or `technique-tooltip/technique-tooltip.component.ts`

Update the tooltip to show your mode's value when hovering over a cell.

### Step 7: Test

1. Select your heatmap mode from the toolbar dropdown.
2. Verify the matrix colors update correctly.
3. Verify the legend shows the correct label.
4. Verify tooltips display the data.
5. Verify the URL hash updates with `heat=my-mode`.
6. Verify the mode persists when sharing the URL.

---

## 5. Adding a New Panel

Panels are full-height views that slide in from the right side of the screen, overlaying part of the matrix.

### Step 1: Create the Component

Generate or create a new component:

```
src/app/components/my-panel/
  my-panel.component.ts
  my-panel.component.html
  my-panel.component.scss
```

Use the standard standalone pattern:

```typescript
import {
  Component,
  OnInit,
  OnDestroy,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';
import { FilterService } from '../../services/filter.service';

@Component({
  selector: 'app-my-panel',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './my-panel.component.html',
  styleUrl: './my-panel.component.scss',
})
export class MyPanelComponent implements OnInit, OnDestroy {
  visible = false;
  private subs = new Subscription();

  constructor(
    private filterService: FilterService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.subs.add(
      this.filterService.activePanel$.subscribe(p => {
        this.visible = p === 'my-panel';
        if (this.visible) {
          // Load data or refresh state when panel opens
        }
        this.cdr.markForCheck();
      }),
    );
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  close(): void {
    this.filterService.setActivePanel(null);
  }
}
```

### Step 2: Add the ActivePanel Type

**File:** `src/app/services/filter.service.ts`

Add your panel ID to the `ActivePanel` type union:

```typescript
export type ActivePanel = 'dashboard' | ... | 'my-panel' | null;
```

### Step 3: Add a Nav Rail Item

**File:** `src/app/components/nav-rail/nav-rail.component.ts`

Add an entry to the `NAV_ITEMS` array in the appropriate group:

```typescript
const NAV_ITEMS: NavItem[] = [
  // ... existing items ...
  { type: 'divider', label: 'Tools' },
  // ... existing tools ...
  { id: 'my-panel', icon: '🔧', label: 'My Panel' },
];
```

The `id` must match the string used in `ActivePanel` and in the panel component's visibility check.

### Step 4: Wire in AppComponent

**File:** `src/app/app.component.ts`

Import the component:

```typescript
import { MyPanelComponent } from './components/my-panel/my-panel.component';
```

Add it to the `imports` array in the `@Component` decorator:

```typescript
imports: [
  // ... existing imports ...
  MyPanelComponent,
],
```

**File:** `src/app/app.component.html`

Add the component tag in the panel area (alongside other panel tags):

```html
<app-my-panel></app-my-panel>
```

The component handles its own visibility internally via the `FilterService.activePanel$` subscription.

---

## 6. Adding a Sidebar Section

The sidebar (`src/app/components/sidebar/`) displays per-technique data in collapsible sections. Each section follows a consistent pattern.

### Step 1: Inject the Service

**File:** `src/app/components/sidebar/sidebar.component.ts`

Import and inject your service:

```typescript
import { MyFeatureService, MyFeatureData } from '../../services/my-feature.service';

// In the constructor:
constructor(
  // ... existing injections ...
  private myFeatureService: MyFeatureService,
) {}
```

### Step 2: Add a Property

Add a property to hold the section's data:

```typescript
myFeatureData: MyFeatureData[] = [];
```

### Step 3: Populate in the Subscription

In the `ngOnInit` subscription where the selected technique changes, populate your data:

```typescript
// Inside the technique selection subscription:
if (technique) {
  this.myFeatureData = this.myFeatureService.getForTechnique(technique.attackId);
}
```

Update the `expandRelevant()` method to collapse your section when it has no data:

```typescript
expandRelevant(): void {
  // ... existing collapses ...
  if (this.myFeatureData.length === 0) this.collapsedSections.add('myfeature');
}
```

Add the section name to the `collapseAll()` sections array:

```typescript
collapseAll(): void {
  const sections = [
    // ... existing sections ...
    'myfeature',
  ];
  // ...
}
```

### Step 4: Add the HTML Section

**File:** `src/app/components/sidebar/sidebar.component.html`

Add a new collapsible section following the established pattern:

```html
<!-- My Feature -->
@if (myFeatureData.length > 0) {
  <div class="sidebar-section">
    <div class="section-heading collapsible-title" (click)="toggleSection('myfeature')">
      <span class="section-icon">🔧</span>
      <span>My Feature</span>
      <span class="count-badge">{{ myFeatureData.length }}</span>
      <span class="collapse-indicator">{{ isSectionCollapsed('myfeature') ? '▸' : '▾' }}</span>
    </div>
    @if (!isSectionCollapsed('myfeature')) {
      <div class="section-body">
        @for (item of myFeatureData; track item.techniqueId) {
          <div class="sidebar-item">
            <!-- Item content -->
          </div>
        }
      </div>
    }
  </div>
}
```

Key patterns:
- Wrap the section in `@if (data.length > 0)` to hide it when empty
- Use the `collapsible-title` class and `toggleSection('name')` click handler
- Include a `count-badge` span showing the item count
- Include the `collapse-indicator` arrow
- Guard the body with `@if (!isSectionCollapsed('name'))`

---

## 7. Styling Guide

### Dark Theme Colors

The application uses a dark theme as the default. Core palette values:

| Element | Value |
|---------|-------|
| Base background | `#070d14` |
| Panel background | `rgba(5, 13, 20, 0.82)` with `backdrop-filter: blur(18px)` |
| Card background | `rgba(255, 255, 255, 0.03)` |
| Border | `rgba(151, 185, 211, 0.12)` |
| Divider | `rgba(255, 255, 255, 0.08)` |
| Primary text | `#e2ecf4` |
| Secondary text | `#8ba3b8` |
| Muted text | `#6e8599` |
| Accent (active items) | `#6fd3ff` |
| Accent background | `rgba(111, 211, 255, 0.14)` |
| Accent border | `rgba(111, 211, 255, 0.24)` |
| Hover background | `rgba(255, 255, 255, 0.06)` |
| Hover border | `rgba(255, 255, 255, 0.08)` |
| Success | `#4ade80` |
| Warning | `#fbbf24` |
| Danger | `#f87171` |

### Panel Styling Pattern

All panels follow a consistent structure:

```scss
:host {
  display: block;
}

.panel {
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.02), transparent),
    rgba(5, 13, 20, 0.95);
  border-left: 1px solid rgba(151, 185, 211, 0.12);
  padding: 20px;
  height: 100%;
  overflow-y: auto;
}

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}

.panel-title {
  font-size: 16px;
  font-weight: 700;
  color: #e2ecf4;
}

.close-btn {
  background: none;
  border: none;
  color: #6e8599;
  font-size: 18px;
  cursor: pointer;
  padding: 4px 8px;
  border-radius: 6px;
}

.close-btn:hover {
  background: rgba(255, 255, 255, 0.06);
  color: #e2ecf4;
}
```

### Section Card Pattern

```scss
.section-card {
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(151, 185, 211, 0.08);
  border-radius: 10px;
  padding: 14px;
  margin-bottom: 12px;
}
```

### Button Patterns

```scss
// Primary action button
.btn-primary {
  background: rgba(111, 211, 255, 0.14);
  color: #6fd3ff;
  border: 1px solid rgba(111, 211, 255, 0.24);
  border-radius: 8px;
  padding: 8px 16px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s;
}

.btn-primary:hover {
  background: rgba(111, 211, 255, 0.22);
  border-color: rgba(111, 211, 255, 0.35);
}

// Secondary/muted button
.btn-secondary {
  background: rgba(255, 255, 255, 0.04);
  color: #8ba3b8;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 8px;
  padding: 8px 16px;
  cursor: pointer;
}
```

### Badge Pattern

```scss
.count-badge {
  background: rgba(111, 211, 255, 0.15);
  color: #6fd3ff;
  font-size: 10px;
  font-weight: 700;
  padding: 2px 7px;
  border-radius: 8px;
  margin-left: 6px;
}
```

### Mobile Breakpoints

The primary mobile breakpoint is `768px`. The nav rail collapses to a bottom bar at this width.

```scss
@media (max-width: 768px) {
  // Stack layout vertically
  // Reduce padding and font sizes
  // Hide non-essential elements
}
```

For panels:
```scss
@media (max-width: 768px) {
  .panel {
    position: fixed;
    inset: 0;
    z-index: 300;
    padding: 16px;
  }
}
```

### Typography Scale

| Element | Size | Weight |
|---------|------|--------|
| Panel title | 16px | 700 |
| Section heading | 13px | 700 |
| Body text | 12px | 400 |
| Labels | 10-11px | 600 |
| Badges | 10px | 700 |
| Nav rail labels | 8px | 600 |
| Divider labels | 9px | 700 |

### Scrollbar Styling

```scss
.scroll-container {
  scrollbar-width: thin;
  scrollbar-color: rgba(88, 166, 255, 0.25) transparent;
}

.scroll-container::-webkit-scrollbar {
  width: 6px;
}

.scroll-container::-webkit-scrollbar-thumb {
  background: rgba(88, 166, 255, 0.25);
  border-radius: 3px;
}
```

---

## 8. Commit Convention

### Message Format

Use imperative mood, present tense. Keep the first line under 72 characters.

**Format:**
```
<type>: <short description>

<optional longer description>

Co-Authored-By: <name> <email>
```

**Types:**

| Type | Description |
|------|-------------|
| `feat` | New feature or panel |
| `fix` | Bug fix |
| `refactor` | Code restructuring without behavior change |
| `style` | CSS/SCSS changes, formatting |
| `docs` | Documentation changes |
| `test` | Adding or updating tests |
| `chore` | Build, dependencies, tooling |
| `perf` | Performance improvement |

**Examples:**

```
feat: add YARA rule generation panel

Add a new panel that generates YARA rules from ATT&CK technique
metadata, supporting file-based and network-based detection signatures.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

```
fix: correct EPSS score display in sidebar CVE section

The EPSS pill was showing the raw probability instead of the
percentage. Multiply by 100 and round to 1 decimal place.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

```
refactor: extract heatmap color logic into SettingsService

Move getCoverageColors() from MatrixComponent into SettingsService
so all components can access the active color theme consistently.
```

### Co-Authored-By

When Claude assists with a commit, include the Co-Authored-By trailer:

```
Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

### Branch Naming

Use descriptive branch names with a type prefix:

```
feat/yara-panel
fix/epss-display
refactor/heatmap-colors
docs/configuration-guide
```

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
