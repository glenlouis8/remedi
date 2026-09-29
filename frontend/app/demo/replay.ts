// Replays a recorded scan (public/demo_run.json, made by scripts/record_demo.py)
// as the same stream of text lines the dashboard reads from /api/run-agent.
// No backend involved. The recording is split at the approval gate: playback
// stops there until the visitor clicks Approve.
//
// Keep this file to erasable TypeScript (no enums, no parameter properties) so
// tests/replay.test.mjs can import it directly with node's type stripping.

export interface RecordedLine {
  t_ms: number;
  line: string;
}

export interface Recording {
  version: number;
  scan_id: string;
  pre_gate: RecordedLine[];
  post_gate: RecordedLine[];
}

export const GATE_LINE = '[ACTION_REQUIRED] WAITING_FOR_APPROVAL';

// Startup chatter the UI never parses; skipped so it doesn't show in a log view.
const HIDDEN_LINES = [/^\[DB\] /, /^Processing request of type /];

export interface ReplayOptions {
  /** Resolves when the visitor clicks Approve. Called once, after the gate line. */
  waitForApproval: () => Promise<void>;
  signal?: AbortSignal;
  /** Idle gaps in the recording (mostly waiting on the LLM) are cut to this. */
  maxGapMs?: number;
  /** Stretches the capped gaps so a ~30s run doesn't feel rushed. */
  timeScale?: number;
  /** Floor between lines so bursts of output still animate. */
  minLineGapMs?: number;
  /** Injectable for tests. */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
}

export const DEFAULT_MAX_GAP_MS = 4000;
export const DEFAULT_TIME_SCALE = 1.4;
export const DEFAULT_MIN_LINE_GAP_MS = 20;

export function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const done = () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal?.addEventListener('abort', done);
  });
}

function isLineArray(v: unknown): v is RecordedLine[] {
  return (
    Array.isArray(v) &&
    v.every((e) => e && typeof e.t_ms === 'number' && typeof e.line === 'string')
  );
}

export async function loadRecording(
  url = '/demo_run.json',
  signal?: AbortSignal,
): Promise<Recording> {
  const res = await fetch(url, { signal });
  if (!res.ok) throw new Error(`Could not load the recording (${res.status}).`);
  const data = await res.json();
  if (data?.version !== 1 || !isLineArray(data.pre_gate) || !isLineArray(data.post_gate)) {
    throw new Error('The recording is not in the expected format.');
  }
  return data as Recording;
}

/**
 * Yields the recorded lines with the original pacing (capped and stretched).
 * After the gate line it waits for the visitor's approval, then continues with
 * the post-gate lines. Ends early, without throwing, if the signal aborts.
 */
export async function* replay(rec: Recording, opts: ReplayOptions): AsyncGenerator<string> {
  const maxGap = opts.maxGapMs ?? DEFAULT_MAX_GAP_MS;
  const scale = opts.timeScale ?? DEFAULT_TIME_SCALE;
  const minGap = opts.minLineGapMs ?? DEFAULT_MIN_LINE_GAP_MS;
  const sleep = opts.sleep ?? defaultSleep;
  const { signal } = opts;

  // Times in each segment are relative to that segment's start (the post-gate
  // clock restarts at the approval), so both use the same gap logic.
  async function* segment(lines: RecordedLine[]): AsyncGenerator<string> {
    let prevT = 0;
    let carry = 0; // pacing owed by hidden lines, paid by the next visible one
    for (const { t_ms, line } of lines) {
      const gap = Math.max(0, t_ms - prevT);
      prevT = t_ms;
      carry += Math.min(gap, maxGap) * scale;
      if (HIDDEN_LINES.some((re) => re.test(line))) continue;
      await sleep(Math.max(carry, minGap), signal);
      carry = 0;
      if (signal?.aborted) return;
      yield line;
    }
  }

  for await (const line of segment(rec.pre_gate)) yield line;
  if (signal?.aborted) return;

  // The recorded gate line is the last pre-gate line; wait for the real click.
  let aborted: Promise<void> | undefined;
  if (signal) {
    aborted = new Promise<void>((resolve) => {
      if (signal.aborted) return resolve();
      signal.addEventListener('abort', () => resolve(), { once: true });
    });
  }
  await Promise.race([opts.waitForApproval(), ...(aborted ? [aborted] : [])]);
  if (signal?.aborted) return;

  for await (const line of segment(rec.post_gate)) yield line;
}
