// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';

export type LedgerKind = 'route' | 'lens' | 'journey';
export type LedgerContents = Record<LedgerKind, Record<string, number>>;
const KEY = 'mitre-nav-usage-ledger-v1';

/**
 * Opt-in, local-only usage ledger (plan decision D7, E0.4 stub). Off by default;
 * counts only while enabled, keeps the counts in this browser's localStorage and
 * has no code path that sends them anywhere. Wiring and the settings view are P1.
 */
@Injectable({ providedIn: 'root' })
export class UsageLedgerService {
  get enabled(): boolean { return this.read() !== null; }
  enable(): void { if (!this.enabled) this.write({ route: {}, lens: {}, journey: {} }); }
  /** Turning the ledger off deletes everything it held. */
  disable(): void { try { localStorage.removeItem(KEY); } catch { /* storage blocked */ } }
  /** Exactly what the ledger holds, for display; null while off. */
  contents(): LedgerContents | null { return this.read(); }
  record(kind: LedgerKind, name: string): void {
    const c = this.read();
    if (!c) return;
    const counts = c[kind] ?? {};
    c[kind] = { ...counts, [name]: (Object.hasOwn(counts, name) ? counts[name] : 0) + 1 };
    this.write(c);
  }
  private read(): LedgerContents | null {
    try {
      const raw = localStorage.getItem(KEY);
      return raw ? (JSON.parse(raw) as LedgerContents) : null;
    } catch { return null; }
  }
  private write(c: LedgerContents): void {
    try { localStorage.setItem(KEY, JSON.stringify(c)); } catch { /* storage blocked */ }
  }
}
