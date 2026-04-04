# Architecture

## Overview

The app is organized around a small set of central UI pieces:

- [`src/app/app.component.ts`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/app.component.ts) is the composition root for the application shell.
- [`src/app/services/filter.service.ts`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/services/filter.service.ts) is the shared UI state store for filters, selection, panels, and URL sync.
- [`src/app/components/matrix/matrix.component.ts`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/components/matrix/matrix.component.ts) renders the ATT&CK matrix and handles most exploration behavior.
- [`src/app/components/sidebar/sidebar.component.ts`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/components/sidebar/sidebar.component.ts) shows rich details for the currently selected technique.

## App Shell

[`src/app/app.component.ts`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/app.component.ts) wires together the toolbar, nav rail, matrix, overlay panels, exports/imports, and global keyboard shortcuts.

Its main responsibilities are:

- Subscribing to `DataService` for the active ATT&CK domain, loading state, and errors
- Routing panel open and close behavior through `FilterService`
- Delegating bulk actions to `MatrixComponent`
- Handling domain switching
- Running export and import flows

[`src/app/app.component.html`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/app.component.html) lays out the top-level UI:

- top toolbar
- left nav rail
- matrix workspace
- sidebar overlay
- feature panels
- bulk action bar
- toast notifications

## Shared Filter State

[`src/app/services/filter.service.ts`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/services/filter.service.ts) is the central state container for user interaction state. It uses `BehaviorSubject`s for mutable state and exposes derived `Observable`s to the rest of the app.

It manages:

- selected technique
- active mitigation filters
- free-text technique query
- search mode and search scope
- platform filters
- hidden tactic columns
- threat group, software, campaign, and data source filters
- active overlay panel
- heatmap mode
- implementation-status filter
- matrix-local search text
- CVE-driven highlighted techniques
- URL hash persistence and restoration

This service is what keeps the toolbar, nav rail, matrix, and detail panels synchronized.

## Matrix View

[`src/app/components/matrix/matrix.component.ts`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/components/matrix/matrix.component.ts) is the main exploration surface.

It is responsible for:

- transforming `domain.tacticColumns` into filtered and sorted display columns
- keyboard navigation across the matrix
- toggling sub-technique expansion
- rendering local matrix search, zoom, minimap, and column visibility controls
- applying highlight and dimming rules from shared filter state
- supporting multi-select and bulk actions
- computing scores for the active heatmap mode

The template in [`src/app/components/matrix/matrix.component.html`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/components/matrix/matrix.component.html) renders:

- a search and control bar
- tactic headers
- technique and sub-technique cells
- bulk selection controls
- a minimap overlay
- hover tooltip support

## Sidebar View

[`src/app/components/sidebar/sidebar.component.ts`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/components/sidebar/sidebar.component.ts) reacts to `FilterService.selectedTechnique$` and hydrates the detail drawer for the current technique.

It aggregates related information from multiple services, including:

- mitigations
- threat groups
- software
- campaigns
- procedures
- data components
- D3FEND mappings
- Engage activities
- CAR analytics
- Atomic Red Team tests
- CVE mappings
- NIST, CIS, and cloud controls
- VERIS actions
- custom mitigations
- notes, annotations, tags, and watchlist state

It also supports editing and persistence for technique notes, mitigation documentation, annotations, tags, and implementation status.

## Runtime Data Flow

The main runtime flow is:

1. `DataService` loads the active ATT&CK domain.
2. `AppComponent` receives the domain and passes it to `MatrixComponent`.
3. `FilterService` publishes selection, filter, and panel state.
4. `MatrixComponent` combines domain data with filter state to determine visible cells, highlighting, dimming, and heatmap values.
5. Selecting a technique updates `FilterService.selectedTechnique$`.
6. `SidebarComponent` reacts to that selection and loads detailed context for the selected technique.

## Exports And Imports

Current export flows in [`src/app/app.component.ts`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/app.component.ts) include:

- technique coverage CSV
- tactic coverage CSV
- mitigation implementation plan CSV
- full report CSV
- XLSX workbook export
- HTML coverage report
- matrix PNG export
- application state JSON
- ATT&CK Navigator layer JSON

Current import flows include:

- application state JSON
- ATT&CK Navigator layer JSON

## Where To Start

If you are new to the codebase, read these files in order:

1. [`src/app/app.component.ts`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/app.component.ts)
2. [`src/app/services/filter.service.ts`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/services/filter.service.ts)
3. [`src/app/components/matrix/matrix.component.ts`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/components/matrix/matrix.component.ts)
4. [`src/app/components/sidebar/sidebar.component.ts`](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/components/sidebar/sidebar.component.ts)

That path gives the clearest view of how the app is composed, how state moves, and where user interactions are implemented.
