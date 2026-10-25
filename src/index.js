// tithonus.org v2 — time + proof for agents.
// Every feature works with one plain GET on a path (no query strings: some fetch tools drop them).
// Signing rule: sig = Ed25519 (base64url, no padding) over the exact bytes before the "sig " line.
// Lines after sig are unsigned hints (receipt link, salt, new/found flags).
// Expected "no" answers are 200 with an "err <code>: <plain English>" line, so fetch tools show them.
// POST /mcp is a zero-dependency MCP server (streamable HTTP, stateless, JSON responses).

const V = "tithonus2";
const VERSION = "3.6.0";
const KEY_ID = "1";
const ORIGIN = "https://tithonus.org";
const HEX64 = /^[0-9a-f]{64}$/;
const NONCE = /^[A-Za-z0-9_-]{1,64}$/;
const GENESIS = 1791244800; // 2026-10-06T00:00:00Z — first beacon round
const MAX_TEXT_URL = 2000; // /stamp/<text> over GET
const MAX_TEXT_MCP = 100000; // tithonus_stamp over MCP

const MANUAL = `tithonus.org  time + proof for agents. plain text. every feature is one GET on a path; no query strings needed.
/now                 signed current time, with the latest drand round in it: provably made after that round.
/now/<anything>      same, with your nonce signed. a fresh nonce beats fetch caches.
/stamp/<text>        notarise text (percent-encode it). server salts + hashes it; text is never stored or logged. returns a receipt link.
/ts/<sha256hex>      notarise a hash you made yourself. repeats return the first receipt.
/v/<sha256hex>       earliest receipt for a hash. never creates.
/r/<receipt>         check a receipt link. append /<text> to also check it matches your text.
                     receipts come as "link" (short, checked against the store) and "proof" (long, verifies offline).
url length: some fetch tools refuse urls over ~255 chars. keep /stamp text under ~150 chars and /r checks under ~180. longer: /mcp, or hash it yourself and use /ts.
/beacon              latest public randomness from drand (League of Entropy). tithonus relays it; nobody can predict or choose it.
/beacon/<round>      one drand quicknet round (one every 3 s). its "token" line goes in text you stamp.
/keys                signing keys
/ots/<sha256hex>     OpenTimestamps proof for a stamp, anchored in Bitcoin in hourly batches. any OTS tool verifies it without tithonus. save it once anchored: it outlives tithonus.
/batches             signed list of recent batches: count, merkle root, nonce, submitted digest, bitcoin block. copied hourly by an outside witness.
/stats               signed self-test: 4 checks, each with its measurement, limit and pass/fail. refreshed every 10 minutes.
/canary              every hour tithonus stamps its own signed stats statement like any stamp. this is the newest.
/canary/<sha256hex>  one canary. sha256 of its bytes through the sig line is its hash; /ots/<hash> proves it in bitcoin.
/a2a                 A2A agent (POST, JSON-RPC, A2A 1.0 and 0.3). send one text command: now, stamp <text>, check <link> <text>, beacon, or any path here. card: /.well-known/agent-card.json
/mcp                 MCP server (POST, streamable HTTP). tools: tithonus_now, tithonus_stamp, tithonus_check, tithonus_lookup, tithonus_beacon
/openapi.json        OpenAPI 3.1 spec for function calling
discovery: /.well-known/api-catalog, /.well-known/mcp/server-card.json, /.well-known/agent-card.json, /.well-known/agent-skills/index.json, /sitemap.xml, /auth.md (no account or key needed)
stale answer? fetch tools cache by url for hours. put /~<anything>/ in front of any path for a fresh one: /~a7/beacon, /~a7/v/<hash>
verify: sig is ed25519 base64url over the exact bytes before the "sig " line (utf-8, \\n endings). lines after sig are unsigned hints.
beacon: x = drand randomness = sha256(drand bls signature); verify with drand's public key, no tithonus needed. unix-second rounds 1791244800 to 1796083200 are the retired key-based beacon: still checkable, but the operator could compute them.
not before: put a /beacon token (drand-<round>-<hex>) in your text, then stamp it. the receipt then bounds it both ways: written after the drand round, existed by the stamp time.
stamp: hash = sha256("<salt>:<text>"). a receipt link carrying the salt lets anyone who has the text check it.
limits: stamps only, about 20 a minute per address. reading, checking and time are never limited.
"no" answers are 200 with an err line. trust: one operator key until a stamp is anchored in Bitcoin (hourly, then minutes to hours); after that, nobody. no stamp is ever deleted.
key leak: if key 1 ever leaks, /keys will say so. stamps anchored in bitcoin before then stay proven; unanchored receipts and /now statements from that key prove nothing. the key itself is anchored hourly in /stats canaries.
security reports: /.well-known/security.txt
logs: day, verb, vendor. no ip, no hash, no content.
`;

// Allow everything: agent fetch tools obey robots.txt, so a Disallow locks out the weakest agents.
// Content-Signal (contentsignals.org): agents may search, use as input, and train on this. Change ai-train to "no" to opt out.
const ROBOTS = `User-agent: *
Content-Signal: search=yes, ai-input=yes, ai-train=yes
Allow: /

Sitemap: ${"https://tithonus.org"}/sitemap.xml
`;

// RFC 9116. Reports go to GitHub private vulnerability reporting on the code repository. Renew Expires yearly.
const SECURITY_TXT = `Contact: https://github.com/llamr/tithonus.org/security/advisories/new
Expires: 2027-10-24T00:00:00Z
Preferred-Languages: en
Canonical: https://tithonus.org/.well-known/security.txt
Policy: https://github.com/llamr/tithonus.org
`;

// Discovery files. Static, cheap, standard.
const SITEMAP_PATHS = ["/", "/llms.txt", "/openapi.json", "/keys", "/beacon", "/now"];
const SITEMAP =
  `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
  SITEMAP_PATHS.map((p) => `  <url><loc>https://tithonus.org${p}</loc></url>`).join("\n") +
  `\n</urlset>\n`;

// RFC 9727 API catalog (application/linkset+json).
const API_CATALOG = JSON.stringify({
  linkset: [
    {
      anchor: "https://tithonus.org/",
      "service-desc": [{ href: "https://tithonus.org/openapi.json", type: "application/json" }],
      "service-doc": [{ href: "https://tithonus.org/", type: "text/plain" }],
      "agent-skills": [{ href: "https://tithonus.org/.well-known/agent-skills/index.json", type: "application/json" }],
      "mcp-server-card": [{ href: "https://tithonus.org/.well-known/mcp/server-card.json", type: "application/json" }],
    },
  ],
});

const AUTH_MD = `# tithonus.org auth.md

Audience: any AI agent or program. There is no human sign-up either.

## Registration

None. No account, no registration endpoint, no approval step.

## Supported methods

anonymous: every endpoint is public. No identity, token or API key is requested or accepted.

## Credentials

None. Authorization headers are ignored. Plain GET on any path in the manual at https://tithonus.org/ works as-is, and MCP at https://tithonus.org/mcp needs no auth either.
`;

// Sent on every response so header-reading agents find the spec, manual and catalog without being told.
const LINK_HEADER = [
  '</openapi.json>; rel="service-desc"; type="application/json"',
  '</>; rel="service-doc"; type="text/plain"',
  '</.well-known/api-catalog>; rel="api-catalog"',
  '</.well-known/agent-skills/index.json>; rel="agent-skills"; type="application/json"',
  '</.well-known/mcp/server-card.json>; rel="mcp-server-card"; type="application/json"',
].join(", ");

// ---------- helpers ----------

const enc = new TextEncoder();
const iso = (ms) => new Date(ms).toISOString().slice(0, 19) + "Z";

function b64url(buf) {
  let s = "";
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64url(s) {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

async function sha256hex(data) {
  const buf = typeof data === "string" ? enc.encode(data) : data;
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(n) {
  return [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

let keyCache = null; // per isolate
async function getKey(env) {
  if (keyCache) return keyCache;
  if (!env.SIGNING_KEY) throw new Error("no key");
  const jwk = JSON.parse(env.SIGNING_KEY);
  const priv = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]);
  const pub = await crypto.subtle.importKey("raw", unb64url(jwk.x), { name: "Ed25519" }, false, ["verify"]);
  keyCache = { priv, pub, x: jwk.x };
  return keyCache;
}

async function signRaw(env, msg) {
  const { priv } = await getKey(env);
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, priv, enc.encode(msg)));
}

async function checkSig(env, msg, sigB64) {
  try {
    const { pub } = await getKey(env);
    return await crypto.subtle.verify({ name: "Ed25519" }, pub, unb64url(sigB64), enc.encode(msg));
  } catch (_) {
    return false;
  }
}

// A result is { body, status, cache }. HTTP and MCP both render it.
const result = (body, status = 200, cache = "no-store") => ({ body, status, cache });
const errResult = (code, msg, status = 200) => result(`err ${code}: ${msg}\n`, status);

// Signed block: signed lines, then "sig", then unsigned hint lines.
async function signedBlock(env, signedLines, hints = []) {
  const head = signedLines.join("\n") + "\n";
  const sig = b64url(await signRaw(env, head));
  return { text: head + `sig ${sig}\n` + hints.map((h) => h + "\n").join(""), sig };
}

function normHash(s) {
  let h = String(s || "").trim().toLowerCase();
  if (h.startsWith("sha256:")) h = h.slice(7);
  if (h.startsWith("0x")) h = h.slice(2);
  return h;
}

function badHash(h) {
  const why = h.length === 64 ? "hex digits only (0-9 a-f)" : `need 64 hex digits, got ${h.length}`;
  return errResult("badinput", `${why}. if you can't hash, use /stamp/<text> and the server hashes for you.`);
}

// Canonical receipt body for hash h first stamped at t (ISO). Deterministic, so /ts, /v and /r agree.
const receiptLines = (h, t) => [
  `${V} ts - signed statement: data with sha256 ${h} existed by ${t}`,
  `hash ${h}`,
  `time ${t}`,
  `key ${KEY_ID}`,
];

// Two receipt forms:
//   link  = /r/<first 20 hex of hash>[.<salt>]      short (~60 chars): fits fetch tools that cap urls near 255,
//                                                      leaving room to append /<text>. checked against the store.
//   proof = /r/<hash>.<unix>.<sig>[.<salt>]          self-verifying (~220 chars): checkable offline, no store needed.
const SHORT = 20;
const shortLink = (h, salt) => `${ORIGIN}/r/${h.slice(0, SHORT)}${salt ? "." + salt : ""}`;

function proofLink(h, t, sig, salt) {
  const unix = Math.floor(Date.parse(t) / 1000);
  return `${ORIGIN}/r/${h}.${unix}.${sig}${salt ? "." + salt : ""}`;
}

const receiptHints = (h, t, sig, salt) => [`link ${shortLink(h, salt)}`, `proof ${proofLink(h, t, sig, salt)}`];

// ---------- Bitcoin anchoring via OpenTimestamps (stage 1 of the trustless plan) ----------
// Every hour (scheduled handler) all unbatched stamps are folded into one Merkle tree. Its root, blinded with a
// random nonce, is submitted to several independent OpenTimestamps calendars, which aggregate it into a Bitcoin
// transaction. Later runs fetch the completed proofs. /ots/<hash> then serves a standard .ots file that any
// OpenTimestamps tool verifies against Bitcoin alone: no tithonus key, server or domain involved.
// Format follows python-opentimestamps (the reference implementation).

const CALENDARS = [
  "https://alice.btc.calendar.opentimestamps.org",
  "https://bob.btc.calendar.opentimestamps.org",
  "https://finney.calendar.eternitywall.com",
];
const OTS_MAGIC = new Uint8Array([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72,
  0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);
const ATT_PENDING = "83dfe30d2ef90c8e";
const ATT_BITCOIN = "0588960d73d71901";
const OP_SHA256 = 0x08, OP_APPEND = 0xf0, OP_PREPEND = 0xf1;
const MAX_BATCH = 1000; // keeps each hourly run, and each /ots rebuild, well inside a free-plan CPU budget
const UPGRADE_BATCHES_PER_RUN = 12; // 12 x 3 calendars + a new batch stays under the free plan's 50 subrequests

const toHex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
const concatBytes = (...arrs) => {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) (out.set(a, o), (o += a.length));
  return out;
};
const toB64 = (b) => btoa(String.fromCharCode(...b));
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const sha256 = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));

function varuint(n) {
  const out = [];
  do {
    let b = n & 0x7f;
    n = Math.floor(n / 128);
    if (n > 0) b |= 0x80;
    out.push(b);
  } while (n > 0);
  return new Uint8Array(out);
}
const varbytes = (b) => concatBytes(varuint(b.length), b);

// Timestamp tree: { atts: [{tag:hex, payload:Uint8Array}], ops: [{tag:number, arg:Uint8Array|null, child}] }
const node = () => ({ atts: [], ops: [] });

function otsParse(bytes) {
  let p = 0;
  const byte = () => {
    if (p >= bytes.length) throw new Error("truncated proof");
    return bytes[p++];
  };
  const take = (n) => {
    if (p + n > bytes.length) throw new Error("truncated proof");
    return bytes.slice(p, (p += n));
  };
  const uint = () => {
    let v = 0, s = 1, b;
    do {
      b = byte();
      v += (b & 0x7f) * s;
      s *= 128;
    } while (b & 0x80);
    return v;
  };
  const vbytes = () => take(uint());
  const ts = (depth) => {
    if (depth > 256) throw new Error("proof too deep");
    const n = node();
    const one = (t) => {
      if (t === 0x00) n.atts.push({ tag: toHex(take(8)), payload: vbytes() });
      else if (t === OP_APPEND || t === OP_PREPEND) n.ops.push({ tag: t, arg: vbytes(), child: ts(depth + 1) });
      else if ([0x02, 0x03, 0x08, 0x67, 0xf2, 0xf3].includes(t)) n.ops.push({ tag: t, arg: null, child: ts(depth + 1) });
      else throw new Error("unknown op " + t);
    };
    let t = byte();
    while (t === 0xff) {
      one(byte());
      t = byte();
    }
    one(t);
    return n;
  };
  return ts(0);
}

function otsSerialize(n) {
  const parts = [];
  const att = (a) => concatBytes(fromHex(a.tag), varbytes(a.payload));
  const op = (o) => concatBytes(new Uint8Array([o.tag]), o.arg ? varbytes(o.arg) : new Uint8Array(0));
  const walk = (n) => {
    if (!n.atts.length && !n.ops.length) throw new Error("empty timestamp");
    n.atts.slice(0, -1).forEach((a) => parts.push(new Uint8Array([0xff, 0x00]), att(a)));
    if (!n.ops.length) parts.push(new Uint8Array([0x00]), att(n.atts[n.atts.length - 1]));
    else {
      if (n.atts.length) parts.push(new Uint8Array([0xff, 0x00]), att(n.atts[n.atts.length - 1]));
      n.ops.forEach((o, i) => {
        if (i < n.ops.length - 1) parts.push(new Uint8Array([0xff]));
        parts.push(op(o));
        walk(o.child);
      });
    }
  };
  walk(n);
  return concatBytes(...parts);
}

async function applyOp(o, msg) {
  if (o.tag === OP_SHA256) return sha256(msg);
  if (o.tag === OP_APPEND) return concatBytes(msg, o.arg);
  if (o.tag === OP_PREPEND) return concatBytes(o.arg, msg);
  if (o.tag === 0x02) return new Uint8Array(await crypto.subtle.digest("SHA-1", msg));
  if (o.tag === 0xf2) return msg.slice().reverse();
  if (o.tag === 0xf3) return new TextEncoder().encode(toHex(msg));
  throw new Error("op not supported here: " + o.tag); // ripemd160/keccak: not used by Bitcoin calendars
}

// Walk the tree from msg; collect attestations with the message they commit to.
async function otsAttestations(n, msg, out = []) {
  for (const a of n.atts) out.push({ tag: a.tag, payload: a.payload, msg });
  for (const o of n.ops) await otsAttestations(o.child, await applyOp(o, msg), out);
  return out;
}

function readVaruint(b) {
  let v = 0, s = 1, i = 0, x;
  do {
    x = b[i++];
    v += (x & 0x7f) * s;
    s *= 128;
  } while (x & 0x80);
  return v;
}

// Attach an upgraded subtree at the node whose message equals `commitment`.
async function otsGraft(n, msg, commitmentHex, up) {
  if (toHex(msg) === commitmentHex) {
    n.atts.push(...up.atts);
    n.ops.push(...up.ops);
    return true;
  }
  for (const o of n.ops) if (await otsGraft(o.child, await applyOp(o, msg), commitmentHex, up)) return true;
  return false;
}

// Merkle tree over 32-byte leaves (sorted). Odd node at a level is carried up unchanged.
async function merkleLevels(leaves) {
  const levels = [leaves];
  while (levels[levels.length - 1].length > 1) {
    const cur = levels[levels.length - 1], next = [];
    for (let i = 0; i < cur.length; i += 2) next.push(i + 1 < cur.length ? await sha256(concatBytes(cur[i], cur[i + 1])) : cur[i]);
    levels.push(next);
  }
  return levels;
}

function merklePath(levels, idx) {
  const steps = [];
  for (let l = 0; l < levels.length - 1; l++) {
    const cur = levels[l];
    if (idx % 2 === 0) {
      if (idx + 1 < cur.length) steps.push({ tag: OP_APPEND, arg: cur[idx + 1] });
    } else steps.push({ tag: OP_PREPEND, arg: cur[idx - 1] });
    idx = Math.floor(idx / 2);
  }
  return steps;
}

async function calendarFetch(url, init) {
  const res = await fetch(url, {
    ...init,
    headers: { accept: "application/vnd.opentimestamps.v1", "user-agent": "tithonus.org (+https://tithonus.org/)", ...(init && init.headers) },
  });
  const body = new Uint8Array(await res.arrayBuffer());
  if (body.length > 10000) throw new Error("calendar response too large");
  return { status: res.status, body };
}

async function submitBatch(env, id, digestHex) {
  const digest = fromHex(digestHex);
  const results = await Promise.allSettled(
    CALENDARS.map(async (url) => {
      const r = await calendarFetch(url + "/digest", { method: "POST", body: digest });
      if (r.status !== 200) throw new Error("status " + r.status);
      const tree = otsParse(r.body);
      const pend = (await otsAttestations(tree, digest)).find((a) => a.tag === ATT_PENDING);
      if (!pend) throw new Error("no pending attestation");
      return { url, ts: toB64(r.body), c: toHex(pend.msg), up: null };
    }),
  );
  const cals = results.filter((r) => r.status === "fulfilled").map((r) => r.value);
  await env.DB.prepare("UPDATE batches SET cals = ?1, status = ?2 WHERE id = ?3")
    .bind(JSON.stringify(cals), cals.length ? "pending" : "unsent", id)
    .run();
  return cals.length;
}

async function upgradeBatch(env, b) {
  const cals = JSON.parse(b.cals || "[]");
  let height = null;
  for (const cal of cals) {
    if (!cal.up) {
      try {
        const r = await calendarFetch(cal.url + "/timestamp/" + cal.c);
        if (r.status !== 200) continue; // 404 = not in a Bitcoin block yet
        const up = otsParse(r.body);
        if (!(await otsAttestations(up, fromHex(cal.c))).some((a) => a.tag === ATT_BITCOIN)) continue;
        cal.up = toB64(r.body);
      } catch (_) {
        continue;
      }
    }
    for (const a of await otsAttestations(otsParse(fromB64(cal.up)), fromHex(cal.c))) {
      if (a.tag === ATT_BITCOIN) {
        const h = readVaruint(a.payload);
        height = height === null ? h : Math.min(height, h);
      }
    }
  }
  const status = height === null ? "pending" : "complete";
  try {
    // anchored = when this job first saw the batch in a Bitcoin block (hourly checks, so accurate to about an hour)
    await env.DB.prepare("UPDATE batches SET cals = ?1, status = ?2, height = ?3, anchored = CASE WHEN ?2 = 'complete' AND anchored IS NULL THEN ?5 ELSE anchored END WHERE id = ?4")
      .bind(JSON.stringify(cals), status, height, b.id, iso(Date.now()))
      .run();
  } catch (_) {
    // database not yet migrated (no anchored column): keep anchoring working, just without the timestamp
    await env.DB.prepare("UPDATE batches SET cals = ?1, status = ?2, height = ?3 WHERE id = ?4").bind(JSON.stringify(cals), status, height, b.id).run();
  }
}

// Public, signed self-test. Instead of asserting "health ok", /stats shows four measurements, each with its
// published limit and pass/fail, so any agent can recompute the verdict. The evidence is a canary: every hour the
// scheduled job signs the current stats statement and stamps its sha256 through the same batch -> calendars ->
// Bitcoin pipeline as everyone else's stamps. /canary/<hash> serves that statement; /ots/<hash> proves it in
// Bitcoin. So the pipeline's liveness is checkable without trusting tithonus, and each canary carries the previous
// one's hash: tithonus's own health history is chained and anchored, and cannot be rewritten later.
// Request counts are deliberately not published: operator information, not trust evidence.
const STATS_TTL = 600;
const HOUR = 3600000;
const LIMIT_CANARY = 2 * HOUR; // the hourly job ran (one missed run tolerated)
const LIMIT_CANARY_BTC = 24 * HOUR; // the pipeline reached Bitcoin end to end
const LIMIT_BATCH = 24 * HOUR; // no batch is left behind
const LIMIT_STAMP = 2 * HOUR; // no stamp is left unbatched
const CANARY_MIN_GAP = 30 * 60000; // a doubled cron run doesn't make two canaries

function fmtDuration(ms) {
  const m = Math.max(0, Math.round(ms / 60000));
  return m < 60 ? `${m}m` : `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

function median(xs) {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b), mid = s.length >> 1;
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

// Run by the hourly job, so no manual migration is needed: adds the canary table and the batches.anchored column.
async function ensureSchema(env) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS canaries (h TEXT PRIMARY KEY, t TEXT NOT NULL, body TEXT NOT NULL)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS canaries_t ON canaries(t)").run();
  try {
    await env.DB.prepare("SELECT anchored FROM batches LIMIT 0").all();
  } catch (_) {
    await env.DB.prepare("ALTER TABLE batches ADD COLUMN anchored TEXT").run();
  }
}

// The signed lines of a stats statement at time `now`. Throws if storage is unavailable.
async function healthLines(env, now) {
  const one = (sql, ...a) => env.DB.prepare(sql).bind(...a).first();
  const { x: pub } = await getKey(env);
  const [waiting, oldBatch] = await Promise.all([
    one("SELECT COUNT(*) AS n, MIN(t) AS oldest FROM stamps WHERE batch IS NULL"),
    one("SELECT MIN(created) AS c FROM batches WHERE status IN ('unsent','pending')"),
  ]);
  let newest = null, inBtc = null, first = null, recent = [];
  try {
    [newest, inBtc, first] = await Promise.all([
      one("SELECT h, t FROM canaries ORDER BY t DESC LIMIT 1"),
      one("SELECT c.h AS h, c.t AS t, b.height AS height FROM canaries c JOIN stamps s ON s.h = c.h JOIN batches b ON b.id = s.batch WHERE b.status = 'complete' ORDER BY c.t DESC LIMIT 1"),
      one("SELECT MIN(t) AS t FROM canaries"),
    ]);
  } catch (_) {} // no canary table until the first hourly run
  try {
    recent = (await env.DB.prepare("SELECT created, anchored FROM batches WHERE anchored IS NOT NULL AND anchored >= ?1").bind(iso(now - 7 * 86400000)).all()).results;
  } catch (_) {} // not migrated until the first hourly run

  const age = (t) => now - Date.parse(t);
  const checks = [];
  const check = (pass, text) => checks.push({ pass, text });
  if (newest) check(age(newest.t) <= LIMIT_CANARY, `newest canary stamped ${fmtDuration(age(newest.t))} ago (limit 2h)`);
  else check(false, `newest canary stamped: none yet, the hourly run makes the first (limit 2h)`);
  if (inBtc) check(age(inBtc.t) <= LIMIT_CANARY_BTC, `newest canary in bitcoin stamped ${fmtDuration(age(inBtc.t))} ago, block ${inBtc.height} (limit 24h)`);
  else if (first && first.t) check(age(first.t) <= LIMIT_CANARY_BTC, `newest canary in bitcoin: none yet, first canary stamped ${fmtDuration(age(first.t))} ago (limit 24h)`);
  else check(false, `newest canary in bitcoin: none yet (limit 24h)`);
  if (oldBatch && oldBatch.c) check(age(oldBatch.c) <= LIMIT_BATCH, `oldest batch not yet in bitcoin created ${fmtDuration(age(oldBatch.c))} ago (limit 24h)`);
  else check(true, `oldest batch not yet in bitcoin: none (limit 24h)`);
  if (waiting.n && waiting.oldest) check(age(waiting.oldest) <= LIMIT_STAMP, `oldest stamp waiting for a batch ${fmtDuration(age(waiting.oldest))} (${waiting.n} waiting; limit 2h)`);
  else check(true, `oldest stamp waiting for a batch: none (limit 2h)`);

  const passed = checks.filter((c) => c.pass).length;
  const failing = checks.filter((c) => !c.pass).map((c) => c.text);
  const t = iso(now);
  const tail = failing.length ? `; failing: ${failing.join("; ")}` : inBtc ? `; newest canary in bitcoin block ${inBtc.height}` : "";
  const delays = recent.map((x) => Date.parse(x.anchored) - Date.parse(x.created)).filter((x) => x >= 0);
  const med = median(delays);
  return {
    inBtc,
    lines: [
      `${V} stats - signed statement: as of ${t}, tithonus.org passed ${passed} of ${checks.length} self-checks${tail}`,
      `time ${t}`,
      ...checks.map((c) => `${c.pass ? "pass" : "fail"} ${c.text}`),
      `canary rule: every hour tithonus stamps sha256 of its own signed stats statement (every byte through the sig line), through the same pipeline as every stamp`,
      `canary newest ${newest ? newest.h : "none"}`,
      `canary in bitcoin ${inBtc ? inBtc.h : "none"}`,
      `median time from batch to bitcoin ${med === null ? "no data yet" : `${fmtDuration(med)} (last 7 days, ${delays.length} batch${delays.length === 1 ? "" : "es"}; checked hourly)`}`,
      `public key ${KEY_ID} ed25519 ${pub} (each canary anchors it in bitcoin)`,
      `version ${VERSION}`,
      `key ${KEY_ID}`,
    ],
  };
}

async function doStats(env) {
  const cache = globalThis.caches && globalThis.caches.default;
  const key = new Request(`${ORIGIN}/__stats_cache_v3`);
  if (cache) {
    const hit = await cache.match(key);
    if (hit) return result(await hit.text(), 200, `public, max-age=${STATS_TTL}`);
  }
  let h;
  try {
    h = await healthLines(env, Date.now());
  } catch (_) {
    return errResult("busy", "storage unavailable. retry in a minute.", 503);
  }
  const hints = [];
  if (h.inBtc) hints.push(`check it: /canary/${h.inBtc.h} is that statement; /ots/${h.inBtc.h} proves it in bitcoin with any OpenTimestamps tool`);
  hints.push("batch roots: /batches. outside copy: github.com/llamr/tithonus.org-witness");
  const body = (await signedBlock(env, h.lines, hints)).text;
  if (cache) {
    try {
      await cache.put(key, new Response(body, { headers: { "cache-control": `public, max-age=${STATS_TTL}` } }));
    } catch (_) {}
  }
  return result(body, 200, `public, max-age=${STATS_TTL}`);
}

// Hourly: sign the current stats statement and stamp its hash like any other stamp (it joins this run's batch).
async function makeCanary(env) {
  const now = Date.now();
  const last = await env.DB.prepare("SELECT t FROM canaries ORDER BY t DESC LIMIT 1").first();
  if (last && now - Date.parse(last.t) < CANARY_MIN_GAP) return null;
  const body = (await signedBlock(env, (await healthLines(env, now)).lines)).text;
  const h = await sha256hex(body);
  const t = iso(now);
  await env.DB.prepare("INSERT INTO stamps (h, t) VALUES (?1, ?2) ON CONFLICT(h) DO NOTHING").bind(h, t).run();
  await env.DB.prepare("INSERT INTO canaries (h, t, body) VALUES (?1, ?2, ?3) ON CONFLICT(h) DO NOTHING").bind(h, t, body).run();
  return h;
}

// /canary (newest) or /canary/<hash>: the exact signed statement, then unsigned hints with its anchor status.
async function doCanary(env, raw) {
  const h = raw ? normHash(raw) : null;
  if (h !== null && !HEX64.test(h)) return badHash(h);
  let row = null;
  try {
    row = h
      ? await env.DB.prepare("SELECT h, t, body FROM canaries WHERE h = ?1").bind(h).first()
      : await env.DB.prepare("SELECT h, t, body FROM canaries ORDER BY t DESC LIMIT 1").first();
  } catch (_) {} // no canary table until the first hourly run
  if (!row) return errResult("notfound", h ? `no canary with sha256 ${h}. /canary is the newest.` : "no canary yet. the hourly run makes the first one.");
  const hints = [`canary ${row.h}`, "rule canary = sha256(every byte above, through the sig line)", ...(await anchorLines(env, row.h))];
  return result(row.body + hints.map((l) => l + "\n").join(""), 200, "public, max-age=300");
}

// Public, signed batch list. Lets anyone (and the outside witness) check that a stamp's batch was published
// and that published roots never change afterwards. Last 7 days of batches, plus any still pending.
async function doBatches(env) {
  let rows;
  try {
    rows = (await env.DB.prepare(
      "SELECT id, created, n, root, nonce, digest, status, height FROM batches WHERE status != 'building' AND (id > (SELECT COALESCE(MAX(id), 0) - 168 FROM batches) OR status != 'complete') ORDER BY id"
    ).all()).results;
  } catch (_) {
    return errResult("busy", "storage unavailable. retry in a minute.", 503);
  }
  const t = iso(Date.now());
  const lines = [`${V} batches - signed statement: the anchoring batches tithonus.org has published, as of ${t}`, `time ${t}`];
  for (const b of rows) {
    lines.push(`batch ${b.id} created ${b.created} n ${b.n} root ${b.root} nonce ${b.nonce} digest ${b.digest} status ${b.status}${b.height ? " block " + b.height : ""}`);
  }
  lines.push(`key ${KEY_ID}`);
  return result((await signedBlock(env, lines)).text + "rule digest = sha256(root || nonce); each stamp's .ots proof leads to its batch's digest\n");
}

// The scheduled job. Safe to run any number of times: every step picks up where the last left off.
async function anchorRun(env) {
  const report = { retried: 0, upgraded: 0, batched: 0, canary: null };
  try {
    await ensureSchema(env);
  } catch (_) {}
  for (const b of (await env.DB.prepare("SELECT id, digest FROM batches WHERE status = 'unsent' ORDER BY id LIMIT 1").all()).results) {
    report.retried += await submitBatch(env, b.id, b.digest);
  }
  const pending = (await env.DB.prepare(`SELECT id, cals FROM batches WHERE status = 'pending' ORDER BY id LIMIT ${UPGRADE_BATCHES_PER_RUN}`).all()).results;
  for (const b of pending) {
    await upgradeBatch(env, b);
    report.upgraded++;
  }
  try {
    report.canary = await makeCanary(env); // after upgrades, so it reports fresh anchoring; before batching, so it joins this batch
  } catch (_) {}
  const waiting = await env.DB.prepare("SELECT COUNT(*) AS n FROM stamps WHERE batch IS NULL").first();
  if (!waiting || !waiting.n) return report;
  const ins = await env.DB.prepare("INSERT INTO batches (created, status) VALUES (?1, 'building')").bind(iso(Date.now())).run();
  const id = ins.meta.last_row_id;
  // at most MAX_BATCH stamps per hour, oldest first but the canary always in, so a flood can't stall the job.
  // anything left over joins the next run, and /stats shows it waiting.
  await env.DB.prepare("UPDATE stamps SET batch = ?1 WHERE h IN (SELECT h FROM stamps WHERE batch IS NULL ORDER BY (h = ?2) DESC, t LIMIT ?3)")
    .bind(id, report.canary || "", MAX_BATCH)
    .run();
  const hs = (await env.DB.prepare("SELECT h FROM stamps WHERE batch = ?1 ORDER BY h").bind(id).all()).results.map((r) => r.h);
  const levels = await merkleLevels(hs.map(fromHex));
  const root = levels[levels.length - 1][0];
  const nonce = crypto.getRandomValues(new Uint8Array(16)); // blinds the root, as the reference client does
  const digest = await sha256(concatBytes(root, nonce));
  await env.DB.prepare("UPDATE batches SET n = ?1, root = ?2, nonce = ?3, digest = ?4, status = 'unsent' WHERE id = ?5")
    .bind(hs.length, toHex(root), toHex(nonce), toHex(digest), id)
    .run();
  await submitBatch(env, id, toHex(digest));
  report.batched = hs.length;
  return report;
}

// Plain-English anchor status for a stamp: hint lines under a receipt (unsigned; the proof itself is the evidence).
async function anchorLines(env, h) {
  try {
    const r = await env.DB.prepare("SELECT s.batch AS batch, b.status AS status, b.height AS height FROM stamps s LEFT JOIN batches b ON b.id = s.batch WHERE s.h = ?1").bind(h).first();
    if (!r) return [];
    if (r.batch === null || r.batch === undefined) return ["anchor queued: joins the next hourly batch, then Bitcoin via OpenTimestamps"];
    if (r.status === "complete") return [`anchor bitcoin block ${r.height}: checkable without tithonus`, `ots ${ORIGIN}/ots/${h}`, "save that .ots file: it is your permanent proof and needs nothing from tithonus"];
    return [`anchor pending: batch ${r.batch} sent to OpenTimestamps; Bitcoin confirmation usually within hours`, `ots ${ORIGIN}/ots/${h}`, "once anchored, save that .ots file: it is your permanent proof and outlives tithonus"];
  } catch (_) {
    return [];
  }
}

// Builds the standard .ots file for one stamp: leaf -> Merkle path -> nonce -> calendar proofs (upgraded where ready).
async function otsFileFor(env, h) {
  const r = await env.DB.prepare("SELECT s.batch AS batch, b.status AS status, b.nonce AS nonce, b.digest AS digest, b.cals AS cals FROM stamps s LEFT JOIN batches b ON b.id = s.batch WHERE s.h = ?1").bind(h).first();
  if (!r) return { err: errResult("notfound", `no stamp for sha256 ${h}. /ts/${h} creates one.`) };
  if (r.batch === null || r.batch === undefined || !r.cals || r.status === "unsent" || r.status === "building") {
    return { err: errResult("notyet", `stamp ${h} is queued for the next hourly batch. ask again after it has been sent to OpenTimestamps.`) };
  }
  const hs = (await env.DB.prepare("SELECT h FROM stamps WHERE batch = ?1 ORDER BY h").bind(r.batch).all()).results.map((x) => x.h);
  const levels = await merkleLevels(hs.map(fromHex));
  const steps = merklePath(levels, hs.indexOf(h));
  const top = node();
  let cur = top;
  const push = (tag, arg) => {
    const child = node();
    cur.ops.push({ tag, arg, child });
    cur = child;
  };
  for (const s of steps) (push(s.tag, s.arg), push(OP_SHA256, null));
  push(OP_APPEND, fromHex(r.nonce));
  push(OP_SHA256, null); // cur is now the submitted digest
  const digest = fromHex(r.digest);
  for (const cal of JSON.parse(r.cals)) {
    const t = otsParse(fromB64(cal.ts));
    if (cal.up) await otsGraft(t, digest, cal.c, otsParse(fromB64(cal.up)));
    cur.atts.push(...t.atts);
    cur.ops.push(...t.ops);
  }
  const file = concatBytes(OTS_MAGIC, varuint(1), new Uint8Array([OP_SHA256]), fromHex(h), otsSerialize(top));
  return { file, complete: r.status === "complete" };
}

// ---------- drand: public randomness from the League of Entropy (quicknet) ----------
// Each round's randomness is sha256 of a BLS threshold signature made jointly by independent organisations every 3 s.
// Nobody, tithonus included, can predict or choose it, and anyone can verify it against drand's public key.
// tithonus uses it twice: /beacon relays it (replacing the old key-based beacon), and a drand "token" inside stamped
// text proves the text was written after that round, so a receipt bounds it both ways.
const DRAND = {
  chain: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
  genesis: 1692803367,
  period: 3,
  scheme: "bls-unchained-g1-rfc9380",
  publicKey: "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
};
const DRAND_RELAYS = ["https://drand.cloudflare.com", "https://api.drand.sh", "https://api2.drand.sh"];
const LEGACY_BEACON_END = 1796083200; // 2026-12-01T00:00:00Z: the old key-based beacon is served for rounds up to here, never after
const DRAND_TOKEN = /\bdrand-([0-9]{1,12})-([0-9a-f]{16,64})\b/;
const drandRoundAt = (unix) => Math.floor((unix - DRAND.genesis) / DRAND.period) + 1;
const drandTime = (round) => DRAND.genesis + (round - 1) * DRAND.period;
const drandToken = (b) => `drand-${b.round}-${b.randomness.slice(0, 16)}`;

// One round from the first relay that answers with a self-consistent beacon (randomness = sha256(signature)).
// Past rounds never change, so the edge caches them for a year. The BLS signature itself is left to the reader to
// verify against DRAND.publicKey: tithonus is a relay here, not the source of trust.
async function drandFetch(round) {
  for (const base of DRAND_RELAYS) {
    try {
      const res = await fetch(`${base}/${DRAND.chain}/public/${round}`, {
        headers: { accept: "application/json" },
        cf: { cacheTtlByStatus: { "200-299": 31536000, "300-599": 0 } },
        signal: AbortSignal.timeout(1500),
      });
      if (res.status !== 200) continue;
      const j = await res.json();
      if (j.round !== round || !/^[0-9a-f]{64}$/.test(j.randomness) || !/^[0-9a-f]{96}$/.test(j.signature)) continue;
      if ((await sha256hex(fromHex(j.signature))) !== j.randomness) continue;
      return { round, randomness: j.randomness, signature: j.signature };
    } catch (_) {}
  }
  return null;
}

// The newest round that is surely published (one period of slack for clock skew).
async function drandLatest() {
  const r = drandRoundAt(Math.floor(Date.now() / 1000)) - 1;
  return (await drandFetch(r)) || (await drandFetch(r - 1));
}

// If text carries a drand token, check it: a match proves the text was written after that round.
async function drandAfter(text) {
  const m = DRAND_TOKEN.exec(text || "");
  if (!m) return null;
  const round = Number(m[1]);
  if (round < 1 || drandTime(round) > Date.now() / 1000) return { ok: false, line: `drand token: round ${round} is not published yet, so it proves nothing` };
  const b = await drandFetch(round);
  if (!b) return { ok: false, line: `drand token: round ${round} could not be fetched just now; check it at api.drand.sh/${DRAND.chain}/public/${round}` };
  if (!b.randomness.startsWith(m[2])) return { ok: false, line: `drand token does not match round ${round}: no "written after" proof` };
  const at = iso(drandTime(round) * 1000);
  return { ok: true, at, line: `written after ${at}: the text carries drand round ${round}, which nobody could know before then` };
}

// ---------- write limit ----------
// Only stamps write to storage, so only stamps are limited: connecting, listing tools, time, checks and lookups never
// are, so directories and agents that probe tithonus are never shut out. Per address, approximate (Cloudflare's
// Workers rate limiting binding, counted per location). No binding configured: no limit.
async function writeLimit(env, req) {
  if (!env.WRITE_LIMIT || !req) return null;
  try {
    const ip = req.headers.get("cf-connecting-ip") || "unknown";
    const { success } = await env.WRITE_LIMIT.limit({ key: "stamp:" + ip });
    return success ? null : errResult("slowdown", "too many stamps from your address in the last minute; nothing was stamped. wait a minute and retry. reads are never limited.");
  } catch (_) {
    return null; // the limiter failing must never stop the service
  }
}

// ---------- core actions (shared by HTTP and MCP) ----------

async function doNow(env, rawNonce) {
  const t = iso(Date.now());
  let nonce = null;
  if (rawNonce !== undefined && rawNonce !== null && rawNonce !== "") {
    nonce = NONCE.test(rawNonce) ? rawNonce : "sha256:" + (await sha256hex(String(rawNonce)));
  }
  const b = await drandLatest();
  const lines = [`${V} now - signed statement: the time at tithonus.org was ${t}`, `time ${t}`];
  if (nonce) lines.push(`nonce ${nonce}`);
  if (b) lines.push(`after drand round ${b.round} at ${iso(drandTime(b.round) * 1000)} randomness ${b.randomness}`);
  lines.push(`key ${KEY_ID}`);
  const hints = b
    ? [`rule: time is at or after the drand round's time. nobody knew that randomness earlier, so this statement was made after it.`, `token ${drandToken(b)}`]
    : ["drand unreachable just now: this statement has no outside lower bound"];
  return result((await signedBlock(env, lines, hints)).text);
}

async function stampHash(env, h, salt, extra = []) {
  const t = iso(Date.now());
  let isNew = false;
  let first = t;
  try {
    const ins = await env.DB.prepare("INSERT INTO stamps (h, t) VALUES (?1, ?2) ON CONFLICT(h) DO NOTHING").bind(h, t).run();
    isNew = ins.meta.changes === 1;
    if (!isNew) first = (await env.DB.prepare("SELECT t FROM stamps WHERE h = ?1").bind(h).first()).t;
  } catch (_) {
    return errResult("busy", "storage unavailable, nothing was stamped. retry in a minute.", 503);
  }
  const { text, sig } = await signedBlock(env, receiptLines(h, first));
  const hints = [];
  if (salt) hints.push(`salt ${salt}`, `rule hash = sha256("<salt>:<text>")`);
  hints.push(isNew ? "new 1 (first stamp of this hash)" : `new 0 (already stamped at ${first}; this is that receipt)`);
  hints.push(...extra, ...receiptHints(h, first, sig, salt), ...(await anchorLines(env, h)));
  return result(text + hints.map((l) => l + "\n").join(""));
}

async function doStampHash(env, raw) {
  const h = normHash(raw);
  if (!HEX64.test(h)) return badHash(h);
  return stampHash(env, h, null);
}

async function doStampText(env, text, max) {
  if (!text) return errResult("badinput", "no text. put it after /stamp/ (percent-encoded).");
  if (text.length > max) return errResult("toolong", `text is ${text.length} chars, max ${max} here. hash it yourself and use /ts/<sha256hex>.`);
  const salt = randomHex(8); // 64 bits: enough to stop guessing, short enough for urls
  const h = await sha256hex(`${salt}:${text}`);
  const after = await drandAfter(text);
  return stampHash(env, h, salt, after ? [after.line] : []);
}

async function doLookup(env, raw) {
  const h = normHash(raw);
  if (!HEX64.test(h)) return badHash(h);
  let row;
  try {
    row = await env.DB.prepare("SELECT t FROM stamps WHERE h = ?1").bind(h).first();
  } catch (_) {
    return errResult("busy", "storage unavailable. retry in a minute.", 503);
  }
  if (!row) return errResult("notfound", `no stamp for sha256 ${h}. /ts/${h} creates one.`);
  const { text, sig } = await signedBlock(env, receiptLines(h, row.t));
  return result(text + `found 1\n` + [...receiptHints(h, row.t, sig), ...(await anchorLines(env, h))].join("\n") + "\n", 200, "public, max-age=300");
}

const SALT = /^[0-9a-f]{16,32}$/;

// Accepts a short link (<20hex>[.<salt>]) or a proof (<hash>.<unix>.<sig>[.<salt>]), bare or as a full url,
// optionally followed by /<text>. text can also be passed separately (MCP).
async function doCheck(env, token, text) {
  let tok = String(token || "").trim();
  const at = tok.indexOf("/r/");
  if (at >= 0) tok = tok.slice(at + 3);
  if (text === undefined && tok.includes("/")) {
    const i = tok.indexOf("/");
    text = decodeSafe(tok.slice(i + 1));
    tok = tok.slice(0, i);
  }
  const parts = tok.split(".");
  let h, t, salt;

  if (parts.length <= 2 && new RegExp(`^[0-9a-f]{${SHORT}}$`).test(parts[0].toLowerCase())) {
    // short link: find the stamp by hash prefix, then re-sign it
    salt = parts[1];
    if (salt && !SALT.test(salt)) return errResult("badinput", "receipt is malformed (copy the whole link, including the . part).");
    const p = parts[0].toLowerCase();
    let rows;
    try {
      rows = (await env.DB.prepare("SELECT h, t FROM stamps WHERE h >= ?1 AND h < ?2 LIMIT 2").bind(p, p + "g").all()).results;
    } catch (_) {
      return errResult("busy", "storage unavailable. retry in a minute, or check the proof link instead (works without storage).", 503);
    }
    if (!rows.length) return result(`invalid: no stamp starts with ${p}. this link was not issued by tithonus.org.\n`);
    if (rows.length > 1) return errResult("ambiguous", "two stamps share this prefix. use the proof link or /v/<full hash>.");
    ({ h, t } = rows[0]);
  } else if (parts.length === 3 || parts.length === 4) {
    // proof: self-verifying, no storage
    const [hRaw, unixStr, sig] = parts;
    salt = parts[3];
    h = normHash(hRaw);
    if (!HEX64.test(h) || !/^[0-9]{1,12}$/.test(unixStr) || !/^[A-Za-z0-9_-]{86}$/.test(sig) || (salt && !SALT.test(salt))) {
      return errResult("badinput", "receipt is malformed (copy the whole link, including every . segment).");
    }
    t = iso(Number(unixStr) * 1000);
    if (!(await checkSig(env, receiptLines(h, t).join("\n") + "\n", sig))) {
      return result(`invalid: this receipt was not signed by tithonus.org key ${KEY_ID}. do not trust it.\n`);
    }
  } else {
    return errResult("badinput", "a receipt looks like https://tithonus.org/r/<20 hex>[.<salt>] or https://tithonus.org/r/<hash>.<unix>.<sig>[.<salt>].");
  }

  const receipt = `receipt: genuine, signed by tithonus.org key ${KEY_ID}; data with sha256 ${h} existed by ${t}.`;
  // No text given: the receipt is the whole question.
  if (text === undefined || text === "") {
    const anchor = await anchorLines(env, h);
    return result(`valid: ${receipt.slice(9)}\n` + anchor.map((l) => l + "\n").join(""), 200, anchor.length ? "public, max-age=300" : "public, max-age=86400");
  }
  // Text given: the agent is asking about its text, so the verdict on the text leads. Summarisers keep first lines;
  // a leading "valid" followed by "no match" reads as a contradiction.
  const matched = salt ? (await sha256hex(`${salt}:${text}`)) === h : (await sha256hex(text)) === h;
  const verdict = matched
    ? `match: your text existed by ${t}. it is exactly what this receipt covers.`
    : `no match: your text is NOT what this receipt covers. this receipt proves nothing about your text.`;
  const anchor = await anchorLines(env, h);
  const extra = [];
  if (matched) {
    const after = await drandAfter(text);
    if (after) {
      extra.push(after.line);
      if (after.ok && Date.parse(after.at) > Date.parse(t)) extra.push("warning: the receipt time is earlier than the drand round, which is impossible. do not trust this receipt.");
    }
  }
  return result(`${verdict}\n${receipt}\n` + [...extra, ...anchor].map((l) => l + "\n").join(""), 200, anchor.length || extra.length ? "public, max-age=300" : "public, max-age=86400");
}

async function doBeacon(env, roundRaw) {
  const nowS = Math.floor(Date.now() / 1000);
  const specific = roundRaw !== undefined && roundRaw !== null && roundRaw !== "";
  let r;
  if (specific) {
    const s = String(roundRaw).trim();
    if (!/^[0-9]{1,12}$/.test(s)) return errResult("badinput", "round is a drand quicknet round number, digits only. /beacon for the latest.");
    r = Number(s);
    if (r >= GENESIS) return legacyBeacon(env, r, nowS);
    if (r < 1) return errResult("badinput", "drand rounds start at 1. /beacon for the latest.");
    if (r >= drandRoundAt(nowS)) {
      const at = drandTime(r);
      return errResult("future", `drand round ${r} is published at ${iso(at * 1000)}, in about ${Math.max(1, at - nowS + DRAND.period)}s. ask again then.`);
    }
  }
  const b = specific ? await drandFetch(r) : await drandLatest();
  if (!b) return errResult("busy", "drand relays unreachable just now. retry in a minute.", 503);
  const t = iso(drandTime(b.round) * 1000);
  const lines = [
    `${V} beacon - signed statement: drand quicknet round ${b.round} (${t}) randomness is ${b.randomness}`,
    `round ${b.round}`,
    `time ${t}`,
    `x ${b.randomness}`,
    `drand signature ${b.signature}`,
    `drand chain ${DRAND.chain}`,
    `key ${KEY_ID}`,
  ];
  const hints = [
    `token ${drandToken(b)}`,
    `use: put the token in text before you stamp it. the receipt then proves the text was written after ${t}.`,
    `source: drand quicknet (League of Entropy). x = sha256(drand signature). verify the signature with drand's public key at https://api.drand.sh/${DRAND.chain}/info; tithonus cannot predict or choose it.`,
  ];
  return result((await signedBlock(env, lines, hints)).text, 200, specific ? "public, max-age=86400" : "no-store");
}

// The retired key-based beacon (rounds are unix seconds). Served unchanged for rounds it already covered, so old
// draws stay checkable; it never issues rounds after LEGACY_BEACON_END.
async function legacyBeacon(env, r, nowS) {
  if (r > LEGACY_BEACON_END) return errResult("retired", `the key-based beacon ended at ${iso(LEGACY_BEACON_END * 1000)}. /beacon gives drand randomness, which nobody can predict.`);
  if (r > nowS) return errResult("future", `round ${r} is available at ${iso(r * 1000)}, in ${r - nowS}s. ask again then.`);
  const t = iso(r * 1000);
  const seed = await signRaw(env, `tithonus1 beacon ${r}`); // v1 continuity: same per-round value as before
  const x = await sha256hex(seed);
  const lines = [
    `${V} beacon - signed statement: randomness for round ${r} (${t}) is ${x}`,
    `round ${r}`,
    `time ${t}`,
    `x ${x}`,
    `seed ${b64url(seed)}`,
    `key ${KEY_ID}`,
  ];
  const hints = ["legacy: x = sha256(seed); seed = ed25519 sig over \"tithonus1 beacon <round>\". the operator could compute any round. new draws: /beacon (drand)."];
  return result((await signedBlock(env, lines, hints)).text, 200, "public, max-age=86400");
}

async function doKeys(env) {
  const { x } = await getKey(env);
  return result(`ok keys\nkey ${KEY_ID} ed25519 ${x}\nrevoked none\n`, 200, "public, max-age=3600");
}

function decodeSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch (_) {
    return s;
  }
}

// ---------- MCP (stateless streamable HTTP, JSON responses, no dependencies) ----------

const MCP_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const TOOLS = [
  {
    name: "tithonus_now",
    description: "Get a signed statement of the current UTC time from tithonus.org. It includes the latest drand round, so anyone can see it was made after that moment. Use when you need trustworthy current time, or proof of when you asked. Pass a fresh nonce to bind the answer to your request.",
    inputSchema: { type: "object", properties: { nonce: { type: "string", description: "Optional. Any string; long or unusual ones are signed as their sha256." } } },
    annotations: { title: "Signed current time", readOnlyHint: true, openWorldHint: false },
    run: (env, a) => doNow(env, a.nonce),
  },
  {
    name: "tithonus_stamp",
    description: "Notarise something so you can later prove it existed (or that you knew or said it) by now. Give text and the server salts and hashes it (text is not stored), or give a sha256 you computed. Returns a receipt link anyone can check. Stamping the same hash again returns the original receipt.",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string", description: "The claim, prediction or data to notarise. Keep it exact; you need the identical text to prove a match later." },
        sha256: { type: "string", description: "Alternative to text: a 64-hex sha256 you computed (salt guessable content first)." },
      },
    },
    annotations: { title: "Notarise", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    run: async (env, a, req) => (await writeLimit(env, req)) || (a.text ? doStampText(env, String(a.text), MAX_TEXT_MCP) : a.sha256 ? doStampHash(env, a.sha256) : errResult("badinput", "give text or sha256.")),
  },
  {
    name: "tithonus_check",
    description: "Check a tithonus receipt link: is it genuine, and when was it stamped? Optionally give the text to confirm it is exactly what was stamped.",
    inputSchema: {
      type: "object",
      properties: {
        receipt: { type: "string", description: "The receipt link (https://tithonus.org/r/...) or its token." },
        text: { type: "string", description: "Optional. The text you believe was stamped." },
      },
      required: ["receipt"],
    },
    annotations: { title: "Check receipt", readOnlyHint: true, openWorldHint: false },
    run: (env, a) => doCheck(env, a.receipt, a.text === undefined ? undefined : String(a.text)),
  },
  {
    name: "tithonus_lookup",
    description: "Find the earliest receipt for a sha256 hash, if it was ever stamped. Never creates a stamp.",
    inputSchema: { type: "object", properties: { sha256: { type: "string", description: "64 hex digits." } }, required: ["sha256"] },
    annotations: { title: "Look up stamp", readOnlyHint: true, openWorldHint: false },
    run: (env, a) => doLookup(env, a.sha256),
  },
  {
    name: "tithonus_beacon",
    description: "Get public randomness from drand (League of Entropy), relayed and signed by tithonus. Nobody, tithonus included, can predict or choose it. Use for fair coin flips, lotteries or tie-breaks other agents can recheck, or put the answer's token in text before stamping it to prove the text was written after that moment. Omit round for the latest.",
    inputSchema: { type: "object", properties: { round: { type: "integer", description: "Optional. drand quicknet round number (one every 3 seconds)." } } },
    annotations: { title: "Randomness beacon", readOnlyHint: true, openWorldHint: false },
    run: (env, a) => doBeacon(env, a.round),
  },
];

const TOOL_BY_NAME = Object.fromEntries(TOOLS.map((t) => [t.name, t]));
const TOOL_LIST = TOOLS.map(({ run, ...t }) => t);

async function mcpOne(env, msg, req) {
  const isReq = msg && typeof msg === "object" && msg.id !== undefined && msg.id !== null;
  const reply = (r) => ({ jsonrpc: "2.0", id: msg.id, result: r });
  const fail = (code, message) => ({ jsonrpc: "2.0", id: isReq ? msg.id : null, error: { code, message } });
  if (!msg || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") return fail(-32600, "invalid request");
  if (!isReq) return null; // notification (e.g. notifications/initialized): no response
  if (req) {
    const tn = msg.method === "tools/call" && msg.params && TOOL_BY_NAME[msg.params.name] ? msg.params.name.replace(/^tithonus_/, "") : null;
    count(env, tn ? "mcp:" + tn : ["initialize", "tools/list", "ping", "tools/call"].includes(msg.method) ? "mcp:" + msg.method : "mcp:other", req);
  }
  switch (msg.method) {
    case "initialize": {
      const asked = msg.params && msg.params.protocolVersion;
      return reply({
        protocolVersion: MCP_VERSIONS.includes(asked) ? asked : MCP_VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "tithonus", version: VERSION },
        instructions: "Signed time, notarisation and public randomness. tithonus_stamp to prove something existed by now; tithonus_check to verify a receipt link.",
      });
    }
    case "ping":
      return reply({});
    case "tools/list":
      return reply({ tools: TOOL_LIST });
    case "tools/call": {
      const p = msg.params || {};
      const tool = TOOL_BY_NAME[p.name];
      if (!tool) return fail(-32602, `unknown tool ${p.name}. tools: ${TOOLS.map((t) => t.name).join(", ")}`);
      const r = await tool.run(env, p.arguments || {}, req);
      const isError = r.status >= 500 || r.body.startsWith("err ") || r.body.startsWith("invalid:");
      return reply({ content: [{ type: "text", text: r.body }], isError });
    }
    default:
      return fail(-32601, `method not found: ${msg.method}`);
  }
}

async function mcp(req, env) {
  let payload;
  try {
    payload = await req.json();
  } catch (_) {
    return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }, 400);
  }
  if (Array.isArray(payload)) {
    const out = (await Promise.all(payload.map((m) => mcpOne(env, m, req)))).filter(Boolean);
    return out.length ? json(out) : new Response(null, { status: 202, headers: cors() });
  }
  const out = await mcpOne(env, payload, req);
  return out ? json(out) : new Response(null, { status: 202, headers: cors() });
}

// MCP server card (SEP-1649 draft). Carries both the registry-style top-level fields and serverInfo,
// since early validators disagree on which they read. Extra fields are ignored by readers that don't need them.
const SERVER_CARD = () =>
  JSON.stringify({
    $schema: "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json",
    name: "org.tithonus/mcp",
    version: VERSION,
    title: "tithonus",
    description: "Signed time, notarisation and public randomness for agents. No auth.",
    protocolVersion: MCP_VERSIONS[0],
    serverInfo: { name: "tithonus", title: "tithonus", version: VERSION },
    remotes: [{ type: "streamable-http", url: "https://tithonus.org/mcp" }],
    transport: { type: "streamable-http", endpoint: "/mcp" },
    authentication: { required: false },
    capabilities: { tools: { listChanged: false } },
    tools: TOOL_LIST.map(({ name, description }) => ({ name, description })),
  });

// Agent skill: a SKILL.md that teaches any agent to use tithonus, plus a discovery index (agentskills.io 0.2.0).
const SKILL_MD = `---
name: tithonus
description: Use when you need trustworthy current time, proof that you knew or said something by a certain time (notarisation), a way to check such a proof, or fair public randomness other agents can recheck. Free, no account, works with plain GET.
---

# tithonus.org

Signed time, notarisation and public randomness. No account, no key. Every action is one GET on a path.
If you can connect MCP servers, https://tithonus.org/mcp (streamable HTTP) has the same five tools.\nA2A agents: card at https://tithonus.org/.well-known/agent-card.json, endpoint https://tithonus.org/a2a; send commands like "now" or "stamp <text>".

## Do this

- Current time: GET https://tithonus.org/now/<fresh-random-word>
- Prove you knew/said something by now: GET https://tithonus.org/stamp/<percent-encoded text>
  Keep the exact text. Save the "link" line from the answer; that link is your receipt.
- Check a receipt: GET the link. Append /<percent-encoded text> to check the text matches.
- Notarise data you hashed yourself: GET https://tithonus.org/ts/<sha256 hex>. Salt guessable content first.
- Look up a hash: GET https://tithonus.org/v/<sha256 hex> (never creates a stamp).
- Bitcoin proof: GET https://tithonus.org/ots/<sha256 hex> once the receipt says "anchor pending" or "anchor bitcoin block". It is a standard OpenTimestamps file; verify it with any OTS tool, no tithonus needed. For /stamp the stamped bytes are "<salt>:<text>".
- Fair randomness: GET https://tithonus.org/beacon for the latest drand round, or /beacon/<round> for a past one. Nobody can predict or choose it.
- Prove something was written after a moment: put the "token" line from /beacon (drand-<round>-<hex>) in your text, then stamp it. Checking the receipt with the text reports "written after <time>".
- Keep your proof: once a receipt says "anchor bitcoin block", save the .ots file from /ots/<hash>. It needs nothing from tithonus.
- Is tithonus working? GET https://tithonus.org/stats: four checks, each pass or fail against a stated limit. The canary hash it names has a Bitcoin proof at /ots/<hash>.

## Reading answers

- The first line says what was signed, in plain words. "err <code>: ..." lines are normal "no" answers, not failures.
- Lines before "sig " are signed. Verify: ed25519 (key from /keys, base64url) over those exact bytes.
- Lines after "sig " are hints: salt, link (short receipt), proof (long receipt that verifies offline).

## Gotchas

- Fetch tools cache by URL for hours. For a fresh answer put /~<anything>/ before the path: /~a7/beacon.
- Some fetch tools refuse URLs over ~255 characters. Keep /stamp text under ~150 characters, or use MCP.
- Query strings are optional everywhere; some tools drop them, so nothing depends on them.
- Trust: the operator key alone until a stamp is anchored in Bitcoin (hourly batches, then minutes to hours). After that the .ots proof needs nobody. Beacon randomness comes from drand, not the operator.
`;

let skillsIndexCache = null;
async function skillsIndex() {
  if (!skillsIndexCache) {
    skillsIndexCache = JSON.stringify({
      $schema: "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
      skills: [
        {
          name: "tithonus",
          type: "skill-md",
          description: "Use when you need trustworthy current time, proof that you knew or said something by a certain time, a check of such a proof, or fair public randomness. Free, no account, plain GET.",
          url: "/.well-known/agent-skills/tithonus/SKILL.md",
          digest: "sha256:" + (await sha256hex(SKILL_MD)),
        },
      ],
    });
  }
  return skillsIndexCache;
}

// ---------- OpenAPI ----------

const op = (id, summary, params = []) => ({
  get: {
    operationId: id,
    summary,
    parameters: params.map(([name, description]) => ({ name, in: "path", required: true, description, schema: { type: "string" } })),
    responses: { 200: { description: "Plain-text answer. Lines before 'sig ' are signed; 'err <code>: ...' means a no-answer.", content: { "text/plain": { schema: { type: "string" } } } } },
  },
});

const OPENAPI = JSON.stringify({
  openapi: "3.1.0",
  info: { title: "tithonus", version: VERSION, description: "Signed time, notarisation and public randomness for agents. All GET, plain text." },
  servers: [{ url: ORIGIN }],
  paths: {
    "/now": op("now", "Signed current UTC time, with the latest drand round as an outside lower bound."),
    "/now/{nonce}": op("nowNonce", "Signed current time with your nonce bound in.", [["nonce", "Any string; a fresh one beats caches."]]),
    "/stamp/{text}": op("stampText", "Notarise text; server salts and hashes it. Returns a receipt link.", [["text", "Percent-encoded text, up to 2000 chars."]]),
    "/ts/{sha256}": op("stampHash", "Notarise a sha256 you computed. Repeats return the first receipt.", [["sha256", "64 hex digits."]]),
    "/v/{sha256}": op("lookup", "Earliest receipt for a hash. Never creates.", [["sha256", "64 hex digits."]]),
    "/r/{receipt}": op("check", "Check a receipt link is genuine.", [["receipt", "<hash>.<unix>.<sig>[.<salt>]"]]),
    "/r/{receipt}/{text}": op("checkText", "Check a receipt and that it matches your text.", [["receipt", "<hash>.<unix>.<sig>[.<salt>]"], ["text", "Percent-encoded text."]]),
    "/beacon": op("beacon", "Latest drand randomness (League of Entropy), relayed and signed. Includes a token to put in text before stamping."),
    "/beacon/{round}": op("beaconRound", "drand randomness for a past round.", [["round", "drand quicknet round number (one every 3 s)."]]),
    "/keys": op("keys", "Signing public keys."),
    "/stats": op("stats", "Signed self-test: four checks, each with measurement, limit and pass/fail, plus the canary stamp that evidences them."),
    "/canary": op("canary", "Newest canary: tithonus's own signed stats statement, stamped hourly through the normal Bitcoin pipeline."),
    "/canary/{sha256}": op("canaryByHash", "One canary statement. Its sha256 (bytes through the sig line) has a Bitcoin proof at /ots/{sha256}.", [["sha256", "64 hex digits."]]),
    "/batches": op("batches", "Signed list of recent anchoring batches: stamp count, Merkle root, nonce, digest, Bitcoin block."),
    "/ots/{sha256}": op("otsProof", "OpenTimestamps proof file for a stamp, anchored in Bitcoin; verifiable without tithonus.", [["sha256", "64 hex digits."]]),
  },
});

// ---------- A2A (Agent2Agent): agent card + JSON-RPC endpoint ----------
// Agents and crawlers look for /.well-known/agent-card.json (A2A 0.3+) and /.well-known/agent.json (older). The card
// declares /a2a for A2A 1.0 and 0.3 over JSON-RPC. Every message is answered at once with a Message (no tasks, no
// streaming). A message is one text command, a tithonus path, or a data part {"tool": ..., "arguments": {...}} that
// mirrors the MCP tools. Answers are the same signed plain text as everywhere else.
const A2A_URL = `${ORIGIN}/a2a`;
const A2A_HELP =
  'tithonus: send one command as text. now [nonce] | stamp <text> | ts <sha256> | check <receipt link> [text] | lookup <sha256> | beacon [round] | stats | keys | batches | canary [sha256] | help. ' +
  'a tithonus.org path also works, e.g. /now/abc or /stamp/hello. answers are plain text; lines before "sig " are signed (ed25519, key at /keys).';
const A2A_SKILLS = [
  ["now", "Signed time", "Signed current UTC time, including the latest drand round, so it provably was made after it.", ["time", "clock", "signed", "drand"], ["now", "now my-nonce-123"]],
  ["stamp", "Notarise", "Prove text existed by now. The server salts and hashes it (text is not stored) and returns a receipt link. Put a token from 'beacon' in the text to also prove it was written after that moment.", ["notarise", "timestamp", "proof", "receipt", "bitcoin"], ["stamp my prediction: X wins", "ts 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]],
  ["check", "Check a receipt", "Is a receipt genuine, and is your text exactly what it covers? Plain match or no match.", ["verify", "receipt", "proof"], ["check https://tithonus.org/r/abcdef0123456789abcd.0123456789abcdef my prediction: X wins"]],
  ["lookup", "Look up a hash", "Earliest receipt for a sha256 and its Bitcoin anchoring status. Never creates a stamp.", ["lookup", "hash", "receipt"], ["lookup 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]],
  ["beacon", "Public randomness", "drand randomness (League of Entropy), relayed and signed. Nobody can predict or choose it. Includes a token for 'written after' proofs.", ["randomness", "drand", "fair", "lottery"], ["beacon", "beacon 33314113"]],
];
const AGENT_CARD = () =>
  JSON.stringify({
    name: "tithonus",
    description: "Signed time, Bitcoin-anchored notarisation and drand randomness for agents. No account, no key. Send one command as text: now, stamp <text>, check <link> <text>, lookup <sha256>, beacon.",
    supportedInterfaces: [
      { url: A2A_URL, protocolBinding: "JSONRPC", protocolVersion: "1.0" },
      { url: A2A_URL, protocolBinding: "JSONRPC", protocolVersion: "0.3" },
    ],
    provider: { organization: "tithonus.org", url: `${ORIGIN}/` },
    version: VERSION,
    documentationUrl: `${ORIGIN}/`,
    capabilities: { streaming: false, pushNotifications: false, extendedAgentCard: false },
    defaultInputModes: ["text/plain", "application/json"],
    defaultOutputModes: ["text/plain"],
    skills: A2A_SKILLS.map(([id, name, description, tags, examples]) => ({ id, name, description, tags, examples })),
    // A2A 0.3 clients read these top-level fields instead of supportedInterfaces
    protocolVersion: "0.3.0",
    url: A2A_URL,
    preferredTransport: "JSONRPC",
  });

// One command -> { verb, r }. Text form "verb rest" or a path ("/verb/rest", with or without the origin).
async function a2aRun(env, req, input) {
  let t = String(input || "").trim();
  t = t.replace(/^https?:\/\/(www\.)?tithonus\.org/i, "");
  let verb, arg, path = false;
  if (t.startsWith("/")) {
    let parts = t.split("/").filter(Boolean);
    if (parts[0] && parts[0].startsWith("~")) parts = parts.slice(1);
    verb = (parts[0] || "").toLowerCase();
    arg = decodeSafe(parts.slice(1).join("/"));
    path = true;
  } else {
    const m = t.match(/^(\S+)(?:\s+([\s\S]*))?$/);
    verb = m ? m[1].toLowerCase() : "";
    arg = m && m[2] !== undefined ? m[2] : "";
  }
  const run = async () => {
    switch (verb) {
      case "now":
        return doNow(env, arg || undefined);
      case "stamp":
        return (await writeLimit(env, req)) || doStampText(env, arg, MAX_TEXT_MCP);
      case "ts":
        return (await writeLimit(env, req)) || doStampHash(env, arg);
      case "check":
      case "r": {
        if (path) return doCheck(env, arg);
        const m = arg.match(/^(\S+)(?:\s+([\s\S]*))?$/);
        if (!m) return errResult("badinput", "check needs a receipt link: check <link> [text]");
        return doCheck(env, m[1], m[2] === undefined || m[2] === "" ? undefined : m[2]);
      }
      case "lookup":
      case "v":
        return doLookup(env, arg);
      case "beacon":
        return doBeacon(env, arg || undefined);
      case "stats":
        return doStats(env);
      case "keys":
        return doKeys(env);
      case "batches":
        return doBatches(env);
      case "canary":
        return doCanary(env, arg || null);
      case "":
      case "help":
        return result(A2A_HELP + "\n");
      default:
        return errResult("badinput", `unknown command "${verb.slice(0, 40)}". ${A2A_HELP}`);
    }
  };
  return { verb: ["now", "stamp", "ts", "check", "r", "lookup", "v", "beacon", "stats", "keys", "batches", "canary", "help"].includes(verb) ? verb : "other", r: await run() };
}

async function a2a(req, env) {
  let p;
  try {
    p = await req.json();
  } catch (_) {
    return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
  }
  const id = p && typeof p === "object" && !Array.isArray(p) && p.id !== undefined ? p.id : null;
  const fail = (code, message) => json({ jsonrpc: "2.0", id, error: { code, message } });
  if (!p || typeof p !== "object" || Array.isArray(p) || p.jsonrpc !== "2.0" || typeof p.method !== "string") return fail(-32600, "invalid request (one JSON-RPC 2.0 object, no batches)");
  const ver = (req.headers.get("a2a-version") || "").trim();
  if (ver && !["0.3", "1.0"].includes(ver.split(".").slice(0, 2).join("."))) return fail(-32009, `A2A version ${ver} is not supported. supported: 1.0, 0.3`);
  switch (p.method) {
    case "SendMessage":
    case "message/send": {
      const msg = p.params && p.params.message;
      if (!msg || !Array.isArray(msg.parts)) return fail(-32602, "params.message.parts is required");
      const dataPart = msg.parts.find((x) => x && x.data && typeof x.data === "object" && !Array.isArray(x.data));
      const text = msg.parts.filter((x) => x && typeof x.text === "string").map((x) => x.text).join("\n");
      let verb, r;
      if (dataPart && typeof dataPart.data.tool === "string") {
        const name = dataPart.data.tool.startsWith("tithonus_") ? dataPart.data.tool : "tithonus_" + dataPart.data.tool;
        const tool = TOOL_BY_NAME[name];
        verb = tool ? name.replace(/^tithonus_/, "") : "other";
        r = tool ? await tool.run(env, dataPart.data.arguments || {}, req) : errResult("badinput", `unknown tool "${String(dataPart.data.tool).slice(0, 40)}". tools: now, stamp, check, lookup, beacon.`);
      } else {
        ({ verb, r } = await a2aRun(env, req, dataPart && typeof dataPart.data.command === "string" ? dataPart.data.command : text));
      }
      count(env, "a2a:" + verb, req);
      const messageId = crypto.randomUUID();
      const ctx = typeof msg.contextId === "string" ? { contextId: msg.contextId } : {};
      const result =
        p.method === "message/send"
          ? { kind: "message", messageId, role: "agent", parts: [{ kind: "text", text: r.body }], ...ctx }
          : { message: { messageId, role: "ROLE_AGENT", parts: [{ text: r.body }], ...ctx } };
      return json({ jsonrpc: "2.0", id, result });
    }
    case "SendStreamingMessage":
    case "message/stream":
      return fail(-32004, "streaming is not supported. use SendMessage (message/send): every answer is immediate.");
    case "GetTask":
    case "tasks/get":
    case "ListTasks":
    case "tasks/list":
    case "CancelTask":
    case "tasks/cancel":
    case "SubscribeToTask":
    case "tasks/resubscribe":
      return fail(-32001, "task not found. tithonus answers every message immediately and keeps no tasks.");
    case "GetExtendedAgentCard":
    case "agent/getAuthenticatedExtendedCard":
      return fail(-32007, "no extended agent card. the public card is at /.well-known/agent-card.json");
    default:
      if (/push/i.test(p.method)) return fail(-32003, "push notifications are not supported.");
      return fail(-32601, `method not found: ${p.method.slice(0, 60)}. use SendMessage (A2A 1.0) or message/send (0.3).`);
  }
}

// ---------- HTTP ----------

function cors() {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, HEAD, POST, OPTIONS",
    "access-control-allow-headers": "content-type, accept, mcp-protocol-version, mcp-session-id, a2a-version, a2a-extensions",
  };
}

function text(r) {
  return new Response(r.body, {
    status: r.status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": r.cache, "x-content-type-options": "nosniff", ...cors() },
  });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...cors() } });
}

// Stats: Analytics Engine, fire-and-forget. Only runs if a STATS binding exists in wrangler.toml.
function vendor(ua) {
  ua = (ua || "").toLowerCase();
  if (/claude|anthropic/.test(ua)) return "anthropic";
  if (/openai|chatgpt|gptbot|oai-/.test(ua)) return "openai";
  if (/google|gemini/.test(ua)) return "google";
  if (/perplexity/.test(ua)) return "perplexity";
  if (/meta-|facebook/.test(ua)) return "meta";
  if (/mistral/.test(ua)) return "mistral";
  if (/bytespider|bytedance/.test(ua)) return "bytedance";
  if (/curl|wget|httpie/.test(ua)) return "cli";
  if (/python|node|go-http|axios|undici|okhttp|java/.test(ua)) return "code";
  if (/mozilla/.test(ua)) return "browser-like";
  return "other";
}

// Only known services are recorded by name; anything else (scanner probes for .env, wp-admin, ...) is "unknown",
// so stats stay readable and no attacker-chosen string is stored.
const KNOWN = new Set(["manual", "llms.txt", "robots.txt", "sitemap.xml", "openapi.json", "auth.md", ".well-known", "now", "stamp", "ts", "v", "r", "beacon", "keys", "ots", "batches", "stats", "canary", "mcp", "a2a"]);

function count(env, verb, req) {
  if (!env.STATS) return;
  if (!verb.startsWith("mcp:") && !verb.startsWith("a2a:") && !KNOWN.has(verb)) verb = "unknown";
  try {
    env.STATS.writeDataPoint({ blobs: [verb, vendor(req.headers.get("user-agent"))], doubles: [1], indexes: [verb] });
  } catch (_) {}
}

async function route(req, env, url) {
  let parts = url.pathname.split("/").filter(Boolean);
  if (parts[0] && parts[0].startsWith("~")) parts = parts.slice(1); // cache-buster prefix, ignored
  const verb = parts[0] || "";
  const rest = parts.slice(1).join("/"); // keeps text/nonces that contained "/"
  const q = url.searchParams; // optional fallbacks only; nothing depends on them

  switch (verb) {
    case "":
    case "llms.txt":
      return result(MANUAL, 200, "public, max-age=3600");
    case "robots.txt":
      return result(ROBOTS, 200, "public, max-age=86400");
    case "openapi.json":
      return { raw: OPENAPI, type: "application/json" };
    case "sitemap.xml":
      return { raw: SITEMAP, type: "application/xml" };
    case "auth.md":
      return { raw: AUTH_MD, type: "text/markdown; charset=utf-8" };
    case ".well-known":
      if (rest === "api-catalog") return { raw: API_CATALOG, type: 'application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"' };
      if (rest === "mcp/server-card.json" || rest === "mcp.json") return { raw: SERVER_CARD(), type: "application/json" };
      if (rest === "agent-skills/index.json") return { raw: await skillsIndex(), type: "application/json" };
      if (rest === "agent-skills/tithonus/SKILL.md") return { raw: SKILL_MD, type: "text/markdown; charset=utf-8" };
      if (rest === "security.txt") return { raw: SECURITY_TXT, type: "text/plain; charset=utf-8" };
      if (rest === "agent-card.json" || rest === "agent.json") return { raw: AGENT_CARD(), type: "application/json" };
      return result(`err path: unknown /.well-known/${rest}. try /.well-known/api-catalog or the manual at /\n`, 404);
    case "now":
      return doNow(env, rest ? decodeSafe(rest) : q.get("nonce") || undefined);
    case "stamp":
      return (await writeLimit(env, req)) || doStampText(env, rest ? decodeSafe(rest) : q.get("text") || "", MAX_TEXT_URL);
    case "ts":
      return (await writeLimit(env, req)) || doStampHash(env, decodeSafe(rest));
    case "v":
      return doLookup(env, decodeSafe(rest));
    case "r":
      return doCheck(env, rest);
    case "beacon":
      return doBeacon(env, rest || undefined);
    case "keys":
      return doKeys(env);
    case "stats":
      return doStats(env);
    case "batches":
      return doBatches(env);
    case "canary":
      return doCanary(env, rest ? decodeSafe(rest) : null);
    case "ots": {
      const h = normHash(decodeSafe(rest).replace(/\.ots$/, ""));
      if (!HEX64.test(h)) return badHash(h);
      let o;
      try {
        o = await otsFileFor(env, h);
      } catch (_) {
        return errResult("busy", "storage unavailable. retry in a minute.", 503);
      }
      if (o.err) return o.err;
      return { bin: o.file, name: `${h}.ots`, cache: o.complete ? "public, max-age=86400" : "no-store" };
    }
    case "a2a":
      return result("a2a: this is an A2A agent endpoint. POST JSON-RPC 2.0 (SendMessage for A2A 1.0, message/send for 0.3). agent card: https://tithonus.org/.well-known/agent-card.json. without A2A, every command is also a plain GET: see /\n");
    case "mcp":
      return result("mcp: this is an MCP server. connect your MCP client to https://tithonus.org/mcp (POST, streamable HTTP). without MCP, every tool is also a plain GET: see /\n");
    default:
      return result(`err path: unknown path /${verb}. the manual is at /\n`, 404);
  }
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(anchorRun(env));
  },

  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors() });

    if (url.pathname === "/mcp" || url.pathname === "/mcp/") {
      if (req.method === "POST") {
        try {
          return await mcp(req, env);
        } catch (_) {
          return json({ jsonrpc: "2.0", id: null, error: { code: -32603, message: "server error, retry shortly" } }, 500);
        }
      }
      // MCP clients opening an SSE stream get 405 (spec). Anything else gets an explanation.
      if ((req.headers.get("accept") || "").includes("text/event-stream")) {
        return new Response(null, { status: 405, headers: { allow: "POST", ...cors() } });
      }
    }

    if ((url.pathname === "/a2a" || url.pathname === "/a2a/") && req.method === "POST") {
      try {
        return await a2a(req, env);
      } catch (_) {
        return json({ jsonrpc: "2.0", id: null, error: { code: -32603, message: "server error, retry shortly" } }, 500);
      }
    }

    if (req.method !== "GET" && req.method !== "HEAD") return text(errResult("method", "GET only (POST only on /mcp and /a2a).", 405));

    let r;
    try {
      r = await route(req, env, url);
    } catch (_) {
      r = errResult("server", "retry shortly.", 500);
    }
    count(env, url.pathname.split("/").filter((p) => p && !p.startsWith("~"))[0] || "manual", req);
    const res = r.bin
      ? new Response(r.bin, { headers: { "content-type": "application/vnd.opentimestamps.v1", "content-disposition": `attachment; filename="${r.name}"`, "cache-control": r.cache, ...cors() } })
      : r.raw
        ? new Response(r.raw, { headers: { "content-type": r.type, "cache-control": "public, max-age=3600", ...cors() } })
        : text(r);
    res.headers.set("link", LINK_HEADER);
    return req.method === "HEAD" ? new Response(null, { status: res.status, headers: res.headers }) : res;
  },
};
