export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    // PUBLIC
    if (path === "/api/creator-request" && request.method === "POST") {
      return handleCreatorRequest(request, env);
    }
    // SUBMIT AUTH
    if (path === "/api/submit/login" && request.method === "POST") {
      return handleSubmitLogin(request, env);
    }
    if (path === "/api/submit" && request.method === "POST") {
      return handleSubmit(request, env);
    }
    // READ: LUMEN VIDEOS (NEW)
    if (path === "/api/videos/lumen" && request.method === "GET") {
      return handleLumenVideos(env);
    }
    // SUBMIT SESSION / ME
    if (path === "/api/submit/session" && request.method === "GET") {
      return handleSubmitSession(request, env);
    }
    if (path === "/api/submit/me" && request.method === "GET") {
      return handleSubmitMe(request, env);
    }
    // ADMIN (protected by Cloudflare Access)
    if (path === "/admin/api/creators" && request.method === "GET") {
      return adminListCreators(env);
    }
    if (path === "/admin/api/creators/update-state" && request.method === "POST") {
      return adminUpdateCreatorState(request, env);
    }
    if (path === "/admin/api/creators/delete" && request.method === "POST") {
      return adminDeleteCreator(request, env);
    }
    if (path === "/admin/api/creators/issue-token" && request.method === "POST") {
      return adminIssueToken(request, env);
    }
    if (path === "/admin/api/creators/automation-config" && request.method === "POST") {
      return adminSetAutomationConfig(request, env);
    }
    if (path === "/admin/api/creators/automation-grant" && request.method === "POST") {
      return adminGrantAutomation(request, env);
    }
    if (path === "/admin/api/creators/automation-revoke" && request.method === "POST") {
      return adminRevokeAutomation(request, env);
    }
    // ADMIN: CREATOR VIDEOS (scoped list)
    {
      const m = path.match(/^\/admin\/api\/creators\/([^/]+)\/videos$/);
      if (m && request.method === "GET") {
        return adminListCreatorVideos(env, m[1]);
      }
    }
    // ADMIN: DELETE VIDEO
    if (path === "/admin/api/videos/delete" && request.method === "POST") {
      return adminDeleteVideo(request, env);
    }
    // HEALTH
    if (path === "/api/health") return json({ ok: true });
    return new Response("Not found", { status: 404 });
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runAutomationTick(env));
  },
};
/* ================= LIMITS ================= */
const LIMITS = {
  DISPLAY_NAME: 80,
  EMAIL: 254,
  YOUTUBE_CHANNEL: 200,
  NOTES: 2000,
  YOUTUBE_URL: 2048,
  GAME_TAG: 64,
  SUBMIT_TOKEN: 128,
  YOUTUBE_CHANNEL_ID: 128,
};
/* ================= HELPERS ================= */
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...headers,
    },
  });
}
function bad(message, status = 400) {
  return json({ ok: false, error: message }, status);
}
function nowIso() {
  return new Date().toISOString();
}
function addDaysIso(days) {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString();
}
async function sha256Hex(input) {
  const enc = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", enc);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
function cookie(name, value, maxAgeSeconds) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSeconds}`;
}
function parseCookies(header = "") {
  const out = {};
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const idx = trimmed.indexOf("=");
    if (idx === -1) continue;
    const k = trimmed.slice(0, idx).trim();
    const v = trimmed.slice(idx + 1);
    if (!k) continue;
    out[k] = v;
  }
  return out;
}
function toStr(v) {
  if (typeof v === "string") return v;
  if (v === null || v === undefined) return "";
  return String(v);
}
function tooLong(s, max) {
  return typeof s === "string" && s.length > max;
}
async function readJsonObject(request) {
  try {
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return { ok: false, body: {} };
    }
    return { ok: true, body };
  } catch {
    return { ok: false, body: {} };
  }
}
function extractYouTubeVideoId(urlStr) {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.replace(/^www\./, "");
    if (!["youtube.com", "m.youtube.com", "youtu.be"].includes(host)) return null;
    if (host === "youtu.be") return u.pathname.slice(1) || null;
    if (u.pathname === "/watch") return u.searchParams.get("v");
    const shorts = u.pathname.match(/^\/shorts\/([^/]+)/);
    if (shorts) return shorts[1];
    const live = u.pathname.match(/^\/live\/([^/]+)/);
    if (live) return live[1];
    return null;
  } catch {
    return null;
  }
}
/* ================= SUBMIT ME ================= */
async function handleSubmitMe(request, env) {
  const cookies = parseCookies(request.headers.get("cookie"));
  if (!cookies.alyxar_submit) {
    return json({ ok: false }, 401);
  }
  const session_hash = await sha256Hex(cookies.alyxar_submit);
  const creator = await env.DB.prepare(
    `SELECT display_name
     FROM creators
     WHERE submit_session_hash = ?
       AND submit_session_expires_at > ?`
  )
    .bind(session_hash, nowIso())
    .first();
  if (!creator) {
    return json({ ok: false }, 401);
  }
  return json({
    ok: true,
    display_name: creator.display_name,
  });
}
/* ================= AUTOMATION ================= */
async function listAutomationEligibleCreators(env) {
  const rows = await env.DB.prepare(
    `SELECT
       id,
       automation_channel_id,
       automation_game_tag
     FROM creators
     WHERE
       state = 'approved'
       AND automation_enabled = 1
       AND automation_expires_at > ?`
  )
    .bind(nowIso())
    .all();
  return rows.results || [];
}
async function runAutomationTick(env) {
  const creators = await listAutomationEligibleCreators(env);
  for (const c of creators) {
    try {
      await processAutomationForCreator(env, c);
    } catch (err) {
      // fail calmly for users; log for ops visibility
      console.error("automation_tick_error", { creator_id: c?.id }, err);
    }
  }
}
/* ================= PUBLIC ================= */
async function handleCreatorRequest(request, env) {
  let form = {};
  const isJson = request.headers.get("content-type")?.includes("json");
  if (isJson) {
    const parsed = await readJsonObject(request);
    if (!parsed.ok) return bad("Invalid JSON");
    form = parsed.body;
  } else {
    form = Object.fromEntries((await request.formData()).entries());
  }
  const display_name = toStr(form.name).trim();
  const email = toStr(form.email).trim();
  const youtube_channel = toStr(form.channel).trim();
  const notes = toStr(form.notes).trim();
  if (!display_name || !email || !youtube_channel) {
    return bad("Missing required fields");
  }
  if (
    tooLong(display_name, LIMITS.DISPLAY_NAME) ||
    tooLong(email, LIMITS.EMAIL) ||
    tooLong(youtube_channel, LIMITS.YOUTUBE_CHANNEL) ||
    tooLong(notes, LIMITS.NOTES)
  ) {
    return bad("Invalid fields");
  }
  try {
    await env.DB.prepare(
      `INSERT INTO creators (id, display_name, email, youtube_channel, notes, state, created_at)
       VALUES (?, ?, ?, ?, ?, 'pending', ?)`
    )
      .bind(
        crypto.randomUUID(),
        display_name,
        email,
        youtube_channel,
        notes || null,
        nowIso()
      )
      .run();
  } catch {
    // fail silently (idempotent-ish); don't leak DB behavior
    return json({ ok: true });
  }
  return json({ ok: true });
}
/* ================= SUBMIT LOGIN ================= */
async function handleSubmitLogin(request, env) {
  const parsed = await readJsonObject(request);
  if (!parsed.ok) return bad("Invalid JSON");
  const token = toStr(parsed.body.token).trim();
  if (!token) return bad("Missing token", 401);
  if (tooLong(token, LIMITS.SUBMIT_TOKEN)) return bad("Invalid token", 401);
  const token_hash = await sha256Hex(token);
  const creator = await env.DB.prepare(`SELECT id, state FROM creators WHERE submit_token_hash = ?`)
    .bind(token_hash)
    .first();
  if (!creator) return bad("Invalid token", 401);
  if (creator.state !== "approved") return bad("Not approved", 403);
  const session = crypto.randomUUID();
  const session_hash = await sha256Hex(session);
  const expires = addDaysIso(7);
  await env.DB.prepare(
    `UPDATE creators
     SET submit_session_hash = ?, submit_session_expires_at = ?
     WHERE id = ?`
  )
    .bind(session_hash, expires, creator.id)
    .run();
  return json({ ok: true }, 200, {
    "set-cookie": cookie("alyxar_submit", session, 60 * 60 * 24 * 7),
  });
}
/* ================= SUBMIT ================= */
async function handleSubmit(request, env) {
  const parsed = await readJsonObject(request);
  if (!parsed.ok) return bad("Invalid JSON");
  const youtube_url = toStr(parsed.body.youtube_url).trim();
  const game_tag = toStr(parsed.body.game_tag).trim();
  if (!youtube_url || !game_tag) return bad("Missing fields");
  if (tooLong(youtube_url, LIMITS.YOUTUBE_URL) || tooLong(game_tag, LIMITS.GAME_TAG)) {
    return bad("Invalid fields");
  }
  const youtube_video_id = extractYouTubeVideoId(youtube_url);
  if (!youtube_video_id) return bad("Invalid YouTube URL");
  const cookies = parseCookies(request.headers.get("cookie"));
  let creator = null;
  if (cookies.alyxar_submit) {
    const session_hash = await sha256Hex(cookies.alyxar_submit);
    creator = await env.DB.prepare(
      `SELECT id, state FROM creators
       WHERE submit_session_hash = ?
       AND submit_session_expires_at > ?`
    )
      .bind(session_hash, nowIso())
      .first();
  }
  if (!creator) return bad("Not authenticated", 401);
  if (creator.state !== "approved") return bad("Not approved", 403);
  const submitted_at = nowIso();
  const expires_at = addDaysIso(7);
  // Idempotent insert: do not create duplicates for the same creator + video while active
  await env.DB.prepare(
    `INSERT INTO videos
     (id, creator_id, youtube_url, youtube_video_id, game_tag, submitted_at, expires_at, status)
     SELECT ?, ?, ?, ?, ?, ?, ?, 'active'
     WHERE NOT EXISTS (
       SELECT 1
       FROM videos
       WHERE creator_id = ?
         AND youtube_video_id = ?
         AND status = 'active'
         AND expires_at > ?
     )`
  )
    .bind(
      crypto.randomUUID(),
      creator.id,
      youtube_url,
      youtube_video_id,
      game_tag,
      submitted_at,
      expires_at,
      creator.id,
      youtube_video_id,
      submitted_at
    )
    .run();
  // enforce cap = 10 active
  await env.DB.prepare(
    `DELETE FROM videos
     WHERE id IN (
       SELECT id FROM videos
       WHERE creator_id = ? AND status='active'
       ORDER BY submitted_at DESC
       LIMIT -1 OFFSET 10
     )`
  )
    .bind(creator.id)
    .run();
  return json({ ok: true });
}
/* ================= READ: LUMEN ================= */
async function handleLumenVideos(env) {
  const rows = await env.DB.prepare(
    `SELECT
      v.youtube_video_id,
      v.youtube_url,
      v.game_tag,
      v.submitted_at,
      c.display_name AS creator_display_name
     FROM videos v
     JOIN creators c ON c.id = v.creator_id
     WHERE
       v.status = 'active'
       AND v.expires_at > ?
       AND c.state = 'approved'
     ORDER BY v.submitted_at DESC
     LIMIT 50`
  )
    .bind(nowIso())
    .all();
  const out = (rows.results || []).map((v) => ({
    youtube_id: v.youtube_video_id,
    title: "", // title resolved client-side by YouTube thumbnail
    thumbnail_url: `https://i.ytimg.com/vi/${v.youtube_video_id}/hqdefault.jpg`,
    creator_display_name: v.creator_display_name,
    submitted_at: v.submitted_at,
    game_tag: v.game_tag,
  }));
  return json(out, 200, {
    "cache-control": "public, max-age=3600",
  });
}
async function handleSubmitSession(request, env) {
  const cookies = parseCookies(request.headers.get("cookie"));
  if (!cookies.alyxar_submit) {
    return json({ ok: false });
  }
  const session_hash = await sha256Hex(cookies.alyxar_submit);
  const creator = await env.DB.prepare(
    `SELECT id
     FROM creators
     WHERE submit_session_hash = ?
       AND submit_session_expires_at > ?`
  )
    .bind(session_hash, nowIso())
    .first();
  return json({ ok: !!creator });
}
/* ================= ADMIN ================= */
async function adminListCreators(env) {
  const rows = await env.DB.prepare(
    `SELECT
      c.id,
      c.display_name,
      c.email,
      c.youtube_channel,
      c.state,
      c.automation_enabled,
      c.automation_expires_at,
      c.automation_channel_id,
      c.automation_game_tag,
      (SELECT COUNT(*)
       FROM videos v
       WHERE v.creator_id = c.id
         AND v.status = 'active') AS active_videos,
      (SELECT COUNT(*)
       FROM videos v
       WHERE v.creator_id = c.id) AS total_submissions,
      (SELECT MIN(v.submitted_at)
       FROM videos v
       WHERE v.creator_id = c.id) AS first_submission_at,
      (SELECT MAX(v.submitted_at)
       FROM videos v
       WHERE v.creator_id = c.id) AS last_submission_at
     FROM creators c
     ORDER BY c.created_at DESC`
  ).all();
  return json({ ok: true, creators: rows.results || [] });
}
async function adminUpdateCreatorState(request, env) {
  const parsed = await readJsonObject(request);
  if (!parsed.ok) return bad("Invalid JSON");
  const id = toStr(parsed.body.id).trim();
  const state = toStr(parsed.body.state).trim();
  if (!id || !["pending", "approved", "suspended", "banned"].includes(state)) {
    return bad("Invalid request");
  }
  await env.DB.prepare(
    `UPDATE creators
     SET state = ?, approved_at = COALESCE(approved_at, ?)
     WHERE id = ?`
  )
    .bind(state, state === "approved" ? nowIso() : null, id)
    .run();
  // HARD DELETE videos on suspend OR ban
  if (state === "suspended" || state === "banned") {
    await env.DB.prepare(`DELETE FROM videos WHERE creator_id = ?`).bind(id).run();
  }
  return json({ ok: true });
}
async function adminDeleteCreator(request, env) {
  const parsed = await readJsonObject(request);
  if (!parsed.ok) return bad("Invalid JSON");
  const id = toStr(parsed.body.id).trim();
  if (!id) return bad("Missing id");
  // Ensure no orphans / avoid FK issues regardless of schema configuration
  await env.DB.prepare(`DELETE FROM videos WHERE creator_id = ?`).bind(id).run();
  await env.DB.prepare(`DELETE FROM creators WHERE id = ?`).bind(id).run();
  return json({ ok: true });
}
async function adminIssueToken(request, env) {
  const parsed = await readJsonObject(request);
  if (!parsed.ok) return bad("Invalid JSON");
  const id = toStr(parsed.body.id).trim();
  if (!id) return bad("Missing id");
  const token = `alyxar_${crypto.randomUUID().replace(/-/g, "")}`;
  const token_hash = await sha256Hex(token);
  await env.DB.prepare(
    `UPDATE creators
     SET
       submit_token_hash = ?,
       submit_token_issued_at = ?,
       submit_session_hash = NULL,
       submit_session_expires_at = NULL
     WHERE id = ?`
  )
    .bind(token_hash, nowIso(), id)
    .run();
  return json({ ok: true, token });
}
async function adminListCreatorVideos(env, creatorId) {
  if (!creatorId) return bad("Missing creator id");
  const rows = await env.DB.prepare(
    `SELECT
      v.id,
      v.youtube_video_id,
      v.youtube_url,
      v.game_tag,
      v.submitted_at
     FROM videos v
     WHERE
       v.creator_id = ?
       AND v.status = 'active'
       AND v.expires_at > ?
     ORDER BY v.submitted_at DESC
     LIMIT 10`
  )
    .bind(creatorId, nowIso())
    .all();
  const videos = (rows.results || []).map((v) => ({
    id: v.id,
    youtube_id: v.youtube_video_id,
    youtube_url: v.youtube_url,
    game_tag: v.game_tag,
    submitted_at: v.submitted_at,
    thumbnail_url: `https://i.ytimg.com/vi/${v.youtube_video_id}/hqdefault.jpg`,
    title: "", // consistent with your lumen output
  }));
  return json({ ok: true, creator_id: creatorId, videos });
}
async function adminDeleteVideo(request, env) {
  const parsed = await readJsonObject(request);
  if (!parsed.ok) return bad("Invalid JSON");
  const id = toStr(parsed.body.id).trim();
  if (!id) return bad("Missing id");
  await env.DB.prepare(`DELETE FROM videos WHERE id = ?`).bind(id).run();
  return json({ ok: true });
}
async function fetchLatestYouTubeVideoIds(env, channelId) {
  const url =
    `https://www.googleapis.com/youtube/v3/search` +
    `?part=id` +
    `&channelId=${channelId}` +
    `&order=date` +
    `&maxResults=5` +
    `&type=video` +
    `&key=${env.YOUTUBE_API_KEY}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error("YouTube API error");
  const data = await res.json();
  return (data.items || []).map((v) => v.id?.videoId).filter(Boolean);
}
async function videoExists(env, youtubeVideoId) {
  const row = await env.DB.prepare(`SELECT 1 FROM videos WHERE youtube_video_id = ? LIMIT 1`)
    .bind(youtubeVideoId)
    .first();

  return !!row;
}
async function processAutomationForCreator(env, creator) {
  const { id: creatorId, automation_channel_id: channelId, automation_game_tag: gameTag } = creator;
  if (!channelId || !gameTag) return;
  const latestVideoIds = await fetchLatestYouTubeVideoIds(env, channelId);
  for (const youtubeVideoId of latestVideoIds) {
    if (await videoExists(env, youtubeVideoId)) continue;
    const submittedAt = nowIso();
    const expiresAt = addDaysIso(7);
    const youtubeUrl = `https://www.youtube.com/watch?v=${youtubeVideoId}`;
    await env.DB.prepare(
      `INSERT INTO videos
       (id, creator_id, youtube_url, youtube_video_id, game_tag, submitted_at, expires_at, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'active')`
    )
      .bind(
        crypto.randomUUID(),
        creatorId,
        youtubeUrl,
        youtubeVideoId,
        gameTag,
        submittedAt,
        expiresAt
      )
      .run();
    // enforce cap = 10
    await env.DB.prepare(
      `DELETE FROM videos
       WHERE id IN (
         SELECT id FROM videos
         WHERE creator_id = ? AND status='active'
         ORDER BY submitted_at DESC
         LIMIT -1 OFFSET 10
       )`
    )
      .bind(creatorId)
      .run();
  }
}
async function adminSetAutomationConfig(request, env) {
  const parsed = await readJsonObject(request);
  if (!parsed.ok) return bad("Invalid JSON");
  const id = toStr(parsed.body.id).trim();
  const channel_id = toStr(parsed.body.channel_id).trim();
  const game_tag = toStr(parsed.body.game_tag).trim();
  if (!id || !channel_id || !game_tag) return bad("Missing fields");
  if (tooLong(channel_id, LIMITS.YOUTUBE_CHANNEL_ID) || tooLong(game_tag, LIMITS.GAME_TAG)) {
    return bad("Invalid fields");
  }
  await env.DB.prepare(
    `UPDATE creators
     SET automation_channel_id = ?, automation_game_tag = ?
     WHERE id = ?`
  )
    .bind(channel_id, game_tag, id)
    .run();
  return json({ ok: true });
}
async function adminGrantAutomation(request, env) {
  const parsed = await readJsonObject(request);
  if (!parsed.ok) return bad("Invalid JSON");
  const id = toStr(parsed.body.id).trim();
  const hoursNum = Number(parsed.body.hours);
  if (!id) return bad("Missing id");
  if (!Number.isFinite(hoursNum) || !Number.isInteger(hoursNum) || hoursNum <= 0) {
    return bad("Invalid hours");
  }
  // Hard cap to avoid accidental giant grants
  if (hoursNum > 24 * 365) {
    return bad("Invalid hours");
  }
  const row = await env.DB.prepare(`SELECT automation_expires_at FROM creators WHERE id = ?`)
    .bind(id)
    .first();
  let expires;
  if (row?.automation_expires_at && row.automation_expires_at > nowIso()) {
    expires = new Date(row.automation_expires_at);
    expires.setUTCHours(expires.getUTCHours() + hoursNum);
  } else {
    expires = new Date();
    expires.setUTCHours(expires.getUTCHours() + hoursNum);
  }

  await env.DB.prepare(
    `UPDATE creators
     SET automation_enabled = 1, automation_expires_at = ?
     WHERE id = ?`
  )
    .bind(expires.toISOString(), id)
    .run();

  return json({ ok: true });
}
async function adminRevokeAutomation(request, env) {
  const parsed = await readJsonObject(request);
  if (!parsed.ok) return bad("Invalid JSON");

  const id = toStr(parsed.body.id).trim();
  if (!id) return bad("Missing id");

  await env.DB.prepare(`UPDATE creators SET automation_enabled = 0 WHERE id = ?`).bind(id).run();

  return json({ ok: true });
}