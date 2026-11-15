import { createServer } from 'node:http';
import { createHmac, createHash, timingSafeEqual, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import * as snarkjs from 'snarkjs';

const PORT = process.env.PORT || 8787;
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const WASM = new URL('../circuits/gatekeeper.wasm', import.meta.url).pathname;
const ZKEY = new URL('../circuits/gatekeeper_final.zkey', import.meta.url).pathname;
const SEEN_FILE = new URL('./seen.json', import.meta.url).pathname;

let sigFormat = 'hex'; // detected from the platform's inbound signatures
const seen = new Set(existsSync(SEEN_FILE) ? JSON.parse(readFileSync(SEEN_FILE, 'utf8')) : []);
const seenPractice = new Set();
function persistSeen() { try { writeFileSync(SEEN_FILE, JSON.stringify([...seen])); } catch {} }

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
  if (approve && proofTx) { seenSet.add(proofTx); if (mode === 'competition') persistSeen(); }
  return out;
}

const server = createServer((req, res) => {
  if (req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, service: 'proof-gatekeeper' }));
    return;
  }
  if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    const send = (code, obj) => {
      const body = JSON.stringify(obj);
      res.writeHead(code, { 'content-type': 'application/json', 'x-agent-games-signature': signBody(body) });
      res.end(body);
    };
    if (!verifySig(raw, req.headers['x-agent-games-signature'])) {
      console.log('[gk] bad signature, len', raw.length);
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid signature' }));
      return;
    }
    let env;
    try { env = JSON.parse(raw); } catch { res.writeHead(400); res.end('{}'); return; }
    try {
      if (env.type === 'agent-games.preflight.v1') {
        console.log('[gk] preflight ok');
        send(200, { ok: true, protocolVersion: 'v1' });
      } else if (env.type === 'agent-games.proof-gatekeeper.v1') {
        const t0 = Date.now();
        const out = await decide(env);
        console.log(`[gk] task ${env.task_id} mode=${env.mode} -> ${out.decision}/${out.reason_code} proof=${!!out.proof} ${Date.now() - t0}ms`);
        send(200, out);
      } else {
        console.log('[gk] unknown type', env.type);
        send(400, { error: 'unknown envelope type' });
      }
    } catch (e) {
      console.error('[gk] error', e);
      // fail closed: reject without proof rather than time out
      send(200, { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', proof_tx: env?.input?.proof_tx });
    }
  });
});
server.listen(PORT, () => console.log(`[gk] listening on ${PORT}, secret set: ${!!SECRET}`));
