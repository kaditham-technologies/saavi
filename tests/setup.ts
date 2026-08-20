// Minimal browser surface for the core modules under Node: an in-memory
// localStorage (the keystore) and a `window` global (the Tauri probe).
class MemoryStorage implements Storage {
  private m = new Map<string, string>();
  get length(): number { return this.m.size; }
  clear(): void { this.m.clear(); }
  getItem(k: string): string | null { return this.m.has(k) ? this.m.get(k)! : null; }
  key(i: number): string | null { return [...this.m.keys()][i] ?? null; }
  removeItem(k: string): void { this.m.delete(k); }
  setItem(k: string, v: string): void { this.m.set(k, String(v)); }
}
(globalThis as unknown as { localStorage: Storage }).localStorage = new MemoryStorage();
(globalThis as unknown as { window: unknown }).window = globalThis;
