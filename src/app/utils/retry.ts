// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Observable, timer } from 'rxjs';
import { retry } from 'rxjs/operators';

/**
 * Retry an observable with exponential backoff.
 * Default: 3 retries, starting at 1s delay, doubling each time.
 */
export function retryWithBackoff<T>(
  maxRetries = 3,
  initialDelay = 1000,
): (source: Observable<T>) => Observable<T> {
  return (source: Observable<T>) =>
    source.pipe(
      retry({
        count: maxRetries,
        delay: (error, retryCount) => timer(initialDelay * Math.pow(2, retryCount - 1)),
      }),
    );
}
