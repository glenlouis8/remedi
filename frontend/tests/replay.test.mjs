// Run with: npm run test:replay  (node strips the types from replay.ts itself)
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { replay, loadRecording, GATE_LINE } from '../app/demo/replay.ts';

const instant = async () => {};
const rec = (pre, post) => ({ version: 1, scan_id: 'S', pre_gate: pre, post_gate: post });
const L = (t_ms, line) => ({ t_ms, line });

function deferred() {
  let resolve;
  const promise = new Promise((r) => (resolve = r));
  return { promise, resolve };
}

test('pauses at the gate until approval, then plays the rest', async () => {
  const approval = deferred();
  const gen = replay(
    rec([L(0, 'a'), L(10, GATE_LINE)], [L(5, 'b'), L(9, 'c')]),
    { sleep: instant, waitForApproval: () => approval.promise },
  );
  assert.equal((await gen.next()).value, 'a');
  assert.equal((await gen.next()).value, GATE_LINE);

  let settled = false;
  const pending = gen.next().then((r) => { settled = true; return r; });
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(settled, false, 'must not continue before approval');

  approval.resolve();
  assert.equal((await pending).value, 'b');
  assert.equal((await gen.next()).value, 'c');
  assert.equal((await gen.next()).done, true);
});

test('skips startup noise but keeps its pacing', async () => {
  const waits = [];
  const lines = [];
  for await (const l of replay(
    rec([L(100, '[DB] Initializing PostgreSQL database...'), L(300, 'Processing request of type ListToolsRequest'), L(400, GATE_LINE)], []),
    { sleep: async (ms) => { waits.push(ms); }, waitForApproval: async () => {}, timeScale: 1 },
  )) lines.push(l);
  assert.deepEqual(lines, [GATE_LINE]);
  assert.deepEqual(waits, [400]); // 100 + 200 + 100 carried into the first visible line
});

test('caps long idle gaps, then stretches them', async () => {
  const waits = [];
  for await (const _ of replay(
    rec([L(0, 'a'), L(60000, GATE_LINE)], []),
    { sleep: async (ms) => { waits.push(ms); }, waitForApproval: async () => {}, maxGapMs: 4000, timeScale: 1.5 },
  )) void _;
  assert.equal(Math.max(...waits), 6000);
});

test('abort while waiting at the gate ends playback without throwing', async () => {
  const ac = new AbortController();
  const gen = replay(rec([L(0, GATE_LINE)], [L(1, 'never')]), {
    sleep: instant,
    signal: ac.signal,
    waitForApproval: () => new Promise(() => {}), // visitor never clicks
  });
  assert.equal((await gen.next()).value, GATE_LINE);
  const next = gen.next();
  ac.abort();
  assert.equal((await next).done, true);
});

test('loadRecording rejects malformed data', async () => {
  const realFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => ({ ok: true, json: async () => ({ version: 2 }) });
    await assert.rejects(loadRecording(), /expected format/);
    globalThis.fetch = async () => ({ ok: false, status: 404 });
    await assert.rejects(loadRecording(), /404/);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('the real recording replays end to end in a sensible time', async () => {
  const data = JSON.parse(readFileSync(new URL('../public/demo_run.json', import.meta.url)));
  let total = 0;
  const lines = [];
  for await (const l of replay(data, {
    sleep: async (ms) => { total += ms; },
    waitForApproval: async () => {},
  })) lines.push(l);

  assert.equal(lines.filter((l) => l.includes(GATE_LINE)).length, 1);
  assert.equal(lines.filter((l) => l.includes('[EXEC] Calling')).length, 9);
  assert.match(lines.at(-4), /MISSION ACCOMPLISHED/);
  assert.ok(total >= 15_000 && total <= 40_000, `replay would take ${Math.round(total / 1000)}s`);
  console.log(`replay length: ${(total / 1000).toFixed(1)}s, ${lines.length} lines`);
});
