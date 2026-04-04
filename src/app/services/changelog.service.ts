import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';

export interface AttackRelease {
  tag: string;
  name: string;
  publishedAt: string;
  body: string;
  url: string;
}

@Injectable({ providedIn: 'root' })
export class ChangelogService {
  private readonly RELEASES_URL = 'https://api.github.com/repos/mitre-attack/attack-stix-data/releases?per_page=5';

  private releasesSubject = new BehaviorSubject<AttackRelease[]>([]);
  releases$ = this.releasesSubject.asObservable();

  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$ = this.loadedSubject.asObservable();

  constructor(private http: HttpClient) {
    this.load();
  }

  private load(): void {
    this.http.get<any[]>(this.RELEASES_URL).subscribe({
      next: (data) => {
        const releases = data.map(r => ({
          tag: r.tag_name as string,
          name: r.name as string,
          publishedAt: r.published_at as string,
          body: r.body as string,
          url: r.html_url as string,
        }));
        this.releasesSubject.next(releases);
        this.loadedSubject.next(true);
      },
      error: () => this.loadedSubject.next(false),
    });
  }
}
