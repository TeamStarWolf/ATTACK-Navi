// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { BehaviorSubject, Observable, of, throwError } from 'rxjs';
import { map, catchError, tap } from 'rxjs/operators';
import { retryWithBackoff } from '../utils/retry';
import { StixCollectionService, ImportSummary } from './stix-collection.service';

// ─── Interfaces ────────────────────────────────────────────────────────────────

export interface TaxiiServerConfig {
  id: string;
  name: string;
  url: string;
  username: string;
  password: string;
  enabled: boolean;
}

export interface TaxiiDiscovery {
  title: string;
  description?: string;
  contact?: string;
  default?: string;
  api_roots?: string[];
}

export interface TaxiiApiRoot {
  title: string;
  description?: string;
  versions?: string[];
  max_content_length?: number;
}

export interface TaxiiCollection {
  id: string;
  title: string;
  description?: string;
  can_read: boolean;
  can_write: boolean;
  media_types?: string[];
}

interface TaxiiStoragePayload {
  servers: TaxiiServerConfig[];
}

const STORAGE_KEY = 'mitre-nav-taxii-v1';

// ─── Service ───────────────────────────────────────────────────────────────────

@Injectable({ providedIn: 'root' })
export class TaxiiService {

  private serversSubject = new BehaviorSubject<TaxiiServerConfig[]>([]);
  servers$ = this.serversSubject.asObservable();

  private loadingSubject = new BehaviorSubject<boolean>(false);
  loading$ = this.loadingSubject.asObservable();

  constructor(
    private http: HttpClient,
    private stixCollectionService: StixCollectionService,
  ) {
    this.loadFromStorage();
  }

  // ─── Server management ────────────────────────────────────────────────────

  getServers(): TaxiiServerConfig[] {
    return this.serversSubject.value;
  }

  addServer(config: Omit<TaxiiServerConfig, 'id'>): TaxiiServerConfig {
    const server: TaxiiServerConfig = {
      ...config,
      id: this.uuid(),
    };
    const servers = [...this.serversSubject.value, server];
    this.saveToStorage(servers);
    this.serversSubject.next(servers);
    return server;
  }

  updateServer(id: string, changes: Partial<TaxiiServerConfig>): void {
    const servers = this.serversSubject.value.map(s =>
      s.id === id ? { ...s, ...changes } : s,
    );
    this.saveToStorage(servers);
    this.serversSubject.next(servers);
  }

  removeServer(id: string): void {
    const servers = this.serversSubject.value.filter(s => s.id !== id);
    this.saveToStorage(servers);
    this.serversSubject.next(servers);
  }

  // ─── TAXII 2.1 API calls ─────────────────────────────────────────────────

  testConnection(config: TaxiiServerConfig): Observable<boolean> {
    const url = this.normalizeUrl(config.url);
    return this.http.get<TaxiiDiscovery>(
      `${url}/taxii2/`,
      { headers: this.buildHeaders(config) },
    ).pipe(
      retryWithBackoff(2, 1000),
      map(resp => !!(resp && resp.title)),
      catchError(() => of(false)),
    );
  }

  discoverApiRoots(config: TaxiiServerConfig): Observable<string[]> {
    const url = this.normalizeUrl(config.url);
    this.loadingSubject.next(true);
    return this.http.get<TaxiiDiscovery>(
      `${url}/taxii2/`,
      { headers: this.buildHeaders(config) },
    ).pipe(
      retryWithBackoff(2, 1000),
      map(resp => resp.api_roots ?? []),
      tap(() => this.loadingSubject.next(false)),
      catchError(err => {
        this.loadingSubject.next(false);
        return throwError(() => err);
      }),
    );
  }

  getCollections(config: TaxiiServerConfig, apiRoot: string): Observable<TaxiiCollection[]> {
    const rootUrl = this.normalizeUrl(apiRoot);
    this.loadingSubject.next(true);
    return this.http.get<{ collections: TaxiiCollection[] }>(
      `${rootUrl}/collections/`,
      { headers: this.buildHeaders(config) },
    ).pipe(
      retryWithBackoff(2, 1000),
      map(resp => (resp.collections ?? []).filter(c => c.can_read)),
      tap(() => this.loadingSubject.next(false)),
      catchError(err => {
        this.loadingSubject.next(false);
        return throwError(() => err);
      }),
    );
  }

  fetchCollection(config: TaxiiServerConfig, apiRoot: string, collectionId: string): Observable<any> {
    const rootUrl = this.normalizeUrl(apiRoot);
    this.loadingSubject.next(true);
    return this.http.get<any>(
      `${rootUrl}/collections/${collectionId}/objects/`,
      { headers: this.buildHeaders(config) },
    ).pipe(
      retryWithBackoff(2, 2000),
      tap(() => this.loadingSubject.next(false)),
      catchError(err => {
        this.loadingSubject.next(false);
        return throwError(() => err);
      }),
    );
  }

  importCollection(bundle: any): ImportSummary {
    return this.stixCollectionService.importCollection(bundle);
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  private buildHeaders(config: TaxiiServerConfig): HttpHeaders {
    let headers = new HttpHeaders({
      'Accept': 'application/taxii+json;version=2.1',
    });
    if (config.username && config.password) {
      const encoded = btoa(`${config.username}:${config.password}`);
      headers = headers.set('Authorization', `Basic ${encoded}`);
    }
    return headers;
  }

  private normalizeUrl(url: string): string {
    return url.replace(/\/+$/, '');
  }

  private loadFromStorage(): void {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const payload: TaxiiStoragePayload = JSON.parse(raw);
        this.serversSubject.next(payload.servers ?? []);
      }
    } catch {
      // Corrupted storage, reset
      this.serversSubject.next([]);
    }
  }

  private saveToStorage(servers: TaxiiServerConfig[]): void {
    const payload: TaxiiStoragePayload = { servers };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
  }

  private uuid(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }
}
