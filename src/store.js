import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

/** One JSON file, written atomically (temp file then rename) so a crash never leaves a half-written state. */
export class Store {
  constructor(file) { this.file = file; this.timer = null; this.pending = null; this.writing = Promise.resolve(); }

  async load() {
    try { return JSON.parse(await readFile(this.file, 'utf8')); }
    catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  }

  /** Queue a save; bursts of changes collapse into one write. */
  save(getState, delayMs = 150) {
    this.pending = getState;
    if (this.timer) return;
    this.timer = setTimeout(() => { this.timer = null; this.writing = this.writing.then(() => this.#write()); }, delayMs);
  }

  async flush() {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; this.writing = this.writing.then(() => this.#write()); }
    await this.writing;
  }

  async #write() {
    if (!this.pending) return;
    const state = this.pending(); this.pending = null;
    await mkdir(dirname(this.file), { recursive: true });
    const tmp = this.file + '.tmp';
    await writeFile(tmp, JSON.stringify(state), { mode: 0o600 });
    await rename(tmp, this.file);
  }
}
