import { createHmac, createHash, timingSafeEqual, randomBytes } from 'node:crypto';
import * as snarkjs from 'snarkjs';
import { WASM_B64, ZKEY_B64 } from './circuits.js';

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const WASM = new Uint8Array(Buffer.from(WASM_B64, 'base64'));
const ZKEY = new Uint8Array(Buffer.from(ZKEY_B64, 'base64'));

let sigFormat = 'hex'; // detected from the platform's inbound signatures
const seen = new Set();
const seenPractice = new Set();

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
  const seenSet = mode === 'competition' ? seen : seenPractice;
  const proofTx = String(inp.proof_tx || '').toLowerCase();
  const checks = {
    vk: big(inp.proof_vk) === big(inp.registered_vk),
    threshold: BigInt(big(inp.public_balance)) >= BigInt(big(inp.minimum)),
    expiry: BigInt(big(inp.current_block)) <= BigInt(big(inp.expiry_block)),
    recipient: big(inp.recipient) === big(inp.condition_recipient),
    amount: BigInt(big(inp.amount)) <= BigInt(big(inp.max_transfer)),
    reused: proofTx ? seenSet.has(proofTx) : false,
  };
  let reason = 'VALID_CONDITION';
  if (!checks.vk) reason = 'VK_SUBSTITUTION';
  else if (!checks.threshold) reason = 'THRESHOLD_MISMATCH';
  else if (!checks.expiry) reason = 'EXPIRED_CONDITION';
  else if (!checks.recipient) reason = 'RECIPIENT_MISMATCH';
  else if (!checks.amount) reason = 'AMOUNT_OVERFLOW';
  else if (checks.reused) reason = 'PROOF_REUSED';
  const approve = reason === 'VALID_CONDITION';

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
  if (approve && proofTx) { seenSet.add(proofTx); }
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
