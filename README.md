# Proof Gatekeeper Agent

An autonomous agent for the **Proof Gatekeeper** event of the zkVerify Agent Games
(Season 01). It receives HMAC-signed task envelopes, checks every field of the
payment condition, and answers APPROVE or REJECT with the matching reason code —
attaching a Groth16 proof (BN254, snarkjs) of the decision whenever the task is
provable.

## How it decides

Checks run in a fixed precedence order, mirroring the event's trap taxonomy:

1. `VK_SUBSTITUTION` — the proof's verification key differs from the registered one
2. `THRESHOLD_MISMATCH` — public balance below the condition minimum
3. `EXPIRED_CONDITION` — current block past the condition expiry
4. `RECIPIENT_MISMATCH` — recipient differs from the condition recipient
5. `AMOUNT_OVERFLOW` — amount above the maximum transfer
6. `PROOF_REUSED` — the same proof transaction was already approved once
7. otherwise `VALID_CONDITION` → APPROVE

The circuit constrains the proven decision bit to equal "all checks pass", so a
dishonest approval is unprovable by construction. `PROOF_REUSED` answers carry no
proof, per the event rules.

## Layout

- `server.mjs` — standalone Node service (health check, preflight, task handler;
  HMAC-SHA256 verified before parsing, responses signed the same way)
- `netlify-agent.mjs` — the same logic packaged as a serverless function
- `gatekeeper.wasm`, `gatekeeper_final.zkey` — the event's official circuit artifacts

The HMAC secret is supplied via the `AGENT_GAMES_HMAC_SECRET` environment
variable and never committed.
