import { createHmac, createHash, timingSafeEqual, randomBytes } from 'node:crypto';
import * as snarkjs from 'snarkjs';
import { getStore } from '@netlify/blobs';
import { WASM_B64, ZKEY_B64 } from './circuits.js';

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const WASM = new Uint8Array(Buffer.from(WASM_B64, 'base64'));
const ZKEY = new Uint8Array(Buffer.from(ZKEY_B64, 'base64'));

let sigFormat = 'hex'; // detected from the platform's inbound signatures
const seen = new Map(); // proofTx -> task_id (in-memory fast path)
const seenPractice = new Set();

// Durable state (Netlify Blobs): the in-memory seen-set dies on every cold
// start, which is how a PROOF_REUSED trap can slip through as a false
// APPROVE. Blobs give the seen-set + a per-task envelope log persistence
// across instances.
//
// ROUND 6 LESSON (2026-11-19): the original helpers failed SOFT and
// SILENT — a transient Blobs error dropped the write with no retry, no
// log, nothing. 3 of 8 Round 6 envelopes never landed, including the one
// wrong APPROVE, so the trap could not be diagnosed. Every op below is
// therefore retried, verified by read-back, and a persistent failure is
// logged LOUDLY (console.error) instead of swallowed. The envelope is
// also pre-logged BEFORE the (slow) Groth16 prove, so the diagnostic
// payload survives even if proving or the final write fails.
let _store = null;
function gkStore() {
  if (!_store) _store = getStore({ name: 'gk-state', consistency: 'strong' });
  return _store;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const seenKey = (proofTx) => 'seen/' + createHash('sha256').update(proofTx).digest('hex');
// One Blobs op with bounded retries. Returns { ok, value }; a persistent
// failure is logged loudly — never swallowed.
async function blobOp(label, fn, attempts = 3) {
  let lastErr = null;
  for (let i = 0; i < attempts; i++) {
    try { return { ok: true, value: await fn() }; }
    catch (e) { lastErr = e; if (i < attempts - 1) await sleep(150 * (i + 1)); }
  }
  console.error(`[gk] BLOBS FAILED ${label}:`, lastErr && lastErr.message ? lastErr.message : String(lastErr));
  return { ok: false, value: null };
}
// Set + read-back verify. Returns true only when the value is confirmed
// stored; false means the caller must assume the write did NOT land.
async function durableSetVerified(label, key, value, isJSON) {
  const w = await blobOp(label, () => (isJSON ? gkStore().setJSON(key, value) : gkStore().set(key, value)));
  if (!w.ok) return false;
  const back = await blobOp(label + ' read-back', () => (isJSON ? gkStore().get(key, { type: 'json' }) : gkStore().get(key)));
  if (!back.ok || back.value == null) { console.error(`[gk] BLOBS READ-BACK FAILED ${label} key=${key}`); return false; }
  const same = isJSON ? JSON.stringify(back.value) === JSON.stringify(value) : String(back.value) === String(value);
  if (!same) { console.error(`[gk] BLOBS READ-BACK MISMATCH ${label} key=${key}`); return false; }
  return true;
}
// Tri-state read: { ok, value }. ok=false means the read failed after
// retries (already logged loudly); value is then null but must NOT be
// treated as "absent" — a reuse record may exist that we simply could
// not see, so callers must not overwrite the seen-slot on !ok.
async function durableSeenTaskId(proofTx) {
  return blobOp('seen-get', () => gkStore().get(seenKey(proofTx)));
}
async function durableMarkSeen(proofTx, taskId) {
  return durableSetVerified('mark-seen', seenKey(proofTx), String(taskId), false);
}
async function durableLogTask(taskId, record) {
  return durableSetVerified('log-task', 'task/' + String(taskId), record, true);
}

function hmac(body, format) {
  const mac = createHmac('sha256', SECRET).update(body);
  return format === 'base64' ? mac.digest('base64') : mac.digest('hex');
}
function verifySig(rawBody, header) {
  if (!SECRET || !header) return false;
  let h = String(header).trim();
  if (h.startsWith('sha256=')) h = h.slice(7);
  const formats = /^[0-9a-f]{64}$/i.test(h) ? ['hex'] : ['base64', 'hex'];
  for (const f of formats) {
    const expected = hmac(rawBody, f);
    const a = Buffer.from(expected), b = Buffer.from(h);
    if (a.length === b.length && timingSafeEqual(a, b)) { sigFormat = f; return true; }
  }
  return false;
}
function signBody(body) { return hmac(body, sigFormat); }

const big = (v) => {
  if (typeof v === 'number') return BigInt(v).toString();
  const s = String(v).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s).toString();
  if (/^[0-9]+$/.test(s)) return BigInt(s).toString();
  return s;
};
function taskIdField(task_id) {
  const s = String(task_id ?? '0').trim();
  if (/^[0-9]+$/.test(s)) return s;
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s).toString();
  // fallback: sha256 of the string as a field element (validated in practice)
  return BigInt('0x' + createHash('sha256').update(s).digest('hex')).toString();
}

async function decide(env) {
  const inp = env.input || {};
  const mode = env.mode || 'competition';
  const proofTx = String(inp.proof_tx || '').toLowerCase();
  // PROOF_REUSED: same proof_tx presented under a DIFFERENT task_id before.
  // Competition checks durable state (survives cold starts); a re-send of
  // the very same task (same task_id) is a retry, not reuse.
  let reused = false;
  let storedTask = null;
  let storedReadOk = true;
  if (proofTx && mode === 'competition') {
    const memTask = seen.get(proofTx);
    if (memTask && memTask !== env.task_id) {
      reused = true;
    } else {
      const r = await durableSeenTaskId(proofTx);
      storedReadOk = r.ok;
      storedTask = r.value;
      if (r.ok && r.value && r.value !== String(env.task_id)) reused = true;
    }
  } else if (proofTx) {
    reused = seenPractice.has(proofTx);
  }
  const checks = {
    vk: big(inp.proof_vk) === big(inp.registered_vk),
    threshold: BigInt(big(inp.public_balance)) >= BigInt(big(inp.minimum)),
    expiry: BigInt(big(inp.current_block)) <= BigInt(big(inp.expiry_block)),
    recipient: big(inp.recipient) === big(inp.condition_recipient),
    amount: BigInt(big(inp.amount)) <= BigInt(big(inp.max_transfer)),
    reused,
  };
  let reason = 'VALID_CONDITION';
  if (!checks.vk) reason = 'VK_SUBSTITUTION';
  else if (!checks.threshold) reason = 'THRESHOLD_MISMATCH';
  else if (!checks.expiry) reason = 'EXPIRED_CONDITION';
  else if (!checks.recipient) reason = 'RECIPIENT_MISMATCH';
  else if (!checks.amount) reason = 'AMOUNT_OVERFLOW';
  else if (checks.reused) reason = 'PROOF_REUSED';
  const approve = reason === 'VALID_CONDITION';

  // Record the presentation BEFORE proving: pre-log the envelope and claim
  // the durable seen-slot now, so a concurrent repeat cannot slip through
  // during the slow prove and the envelope survives a prove/write failure.
  // The seen-slot is claimed only on a PROVEN-empty durable read
  // (storedReadOk && !storedTask): claiming blind after a failed read could
  // overwrite another task's reuse record and turn its retry into a false
  // PROOF_REUSED.
  if (proofTx && mode === 'competition') {
    if (!seen.has(proofTx)) seen.set(proofTx, env.task_id);
    if (!reused && storedReadOk && !storedTask) await durableMarkSeen(proofTx, env.task_id);
    await durableLogTask(env.task_id, {
      at: new Date().toISOString(), mode, input: inp,
      decision: 'PENDING', reason_code: 'PENDING',
    });
  }

  const out = { decision: approve ? 'APPROVE' : 'REJECT', reason_code: reason, proof_tx: inp.proof_tx };
  // PROOF_REUSED tasks carry no proof (excluded by the rules); all other
  // decisions get a Groth16 proof of the decision with decision = 1/0.
  if (reason !== 'PROOF_REUSED') {
    const input = {
      registeredVkHash: big(inp.registered_vk),
      proofVkHash: big(inp.proof_vk),
      minimum: big(inp.minimum),
      publicBalance: big(inp.public_balance),
      expiryBlock: big(inp.expiry_block),
      currentBlock: big(inp.current_block),
      recipient: big(inp.recipient),
      conditionRecipient: big(inp.condition_recipient),
      amount: big(inp.amount),
      maxTransfer: big(inp.max_transfer),
      decision: approve ? '1' : '0',
      taskId: taskIdField(env.task_id),
      salt: BigInt('0x' + randomBytes(31).toString('hex')).toString(),
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    out.proof = proof;
    out.public_signals = publicSignals;
  }
  // Final record: overwrite the PENDING pre-log with the real decision.
  // If this write fails after retries, the PENDING envelope is still
  // durable, the failure is in the function log (console.error above),
  // and the JSON line below is a second, dashboard-visible channel.
  if (proofTx && mode === 'competition') {
    const record = {
      at: new Date().toISOString(), mode, input: inp,
      decision: out.decision, reason_code: out.reason_code,
    };
    await durableLogTask(env.task_id, record);
    console.log('[gk-log] ' + JSON.stringify({ task_id: env.task_id, ...record }));
  }
  if (approve && proofTx && mode !== 'competition') { seenPractice.add(proofTx); }
  return out;
}

export default async (req) => {
  if (req.method === 'GET' || req.method === 'HEAD') {
    return new Response(JSON.stringify({ ok: true, service: 'proof-gatekeeper' }), {
      status: 200, headers: { 'content-type': 'application/json' },
    });
  }
  if (req.method !== 'POST') return new Response('', { status: 405 });
  const raw = await req.text();
  const send = (code, obj) => {
    const body = JSON.stringify(obj);
    return new Response(body, {
      status: code,
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': signBody(body) },
    });
  };
  if (!verifySig(raw, req.headers.get('x-agent-games-signature'))) {
    console.log('[gk] bad signature, len', raw.length);
    return new Response(JSON.stringify({ error: 'invalid signature' }), {
      status: 401, headers: { 'content-type': 'application/json' },
    });
  }
  let env;
  try { env = JSON.parse(raw); } catch { return new Response('{}', { status: 400 }); }
  try {
    if (env.type === 'agent-games.preflight.v1') {
      console.log('[gk] preflight ok');
      return send(200, { ok: true, protocolVersion: 'v1' });
    } else if (env.type === 'agent-games.proof-gatekeeper.v1') {
      const t0 = Date.now();
      const out = await decide(env);
      console.log(`[gk] task ${env.task_id} mode=${env.mode} -> ${out.decision}/${out.reason_code} proof=${!!out.proof} ${Date.now() - t0}ms`);
      return send(200, out);
    }
    console.log('[gk] unknown type', env.type);
    return send(400, { error: 'unknown envelope type' });
  } catch (e) {
    console.error('[gk] error', e);
    // fail closed: reject without proof rather than time out
    return send(200, { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', proof_tx: env?.input?.proof_tx });
  }
};
