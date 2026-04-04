import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class BrowserFileService {
  downloadBlob(blob: Blob, filename: string): void {
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    URL.revokeObjectURL(link.href);
  }

  downloadText(content: string, filename: string, type = 'text/plain;charset=utf-8'): void {
    this.downloadBlob(new Blob([content], { type }), filename);
  }

  downloadJson(value: unknown, filename: string): void {
    this.downloadText(JSON.stringify(value, null, 2), filename, 'application/json');
  }

  pickTextFile(accept = '.json'): Promise<string | null> {
    return new Promise((resolve) => {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = accept;
      input.onchange = (event) => {
        const file = (event.target as HTMLInputElement).files?.[0];
        if (!file) {
          resolve(null);
          return;
        }
        const reader = new FileReader();
        reader.onload = (loadEvent) => resolve((loadEvent.target?.result as string | undefined) ?? null);
        reader.onerror = () => resolve(null);
        reader.readAsText(file);
      };
      input.click();
    });
  }
}
