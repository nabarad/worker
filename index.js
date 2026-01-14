/**
 * Alyxar Worker — Full file through Phase 3
 *
 * Bindings (Dashboard):
 * - env.DB (D1)
 * - env.FEED_BUCKET (R2)
 * - env.ADMIN_KEY (secret)
 *
 * Optional vars:
 * - env.FEEDS_PREFIX (default: "feeds")
 * - env.LUMEN_FEED_LIMIT (default: 10)
 * - env.MAX_ACTIVE_VIDEOS_PER_CREATOR (default: 10)
 */

const ADMIN_COOKIE_NAME = "admin_session";
const ADMIN_SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 30; // 30 days

const CREATOR_COOKIE_NAME = "alyxar_submit";
const CREATOR_SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7; // 7 days

const DEFAULT_MAX_ACTIVE_VIDEOS = 10;
const DEFAULT_VIDEO_LIFETIME_DAYS = 7;

const INACTIVE_GRACE_DAYS = 7; // inactive → deleted after 7 days

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method.toUpperCase();

      // Health
      if (path === "/health") return text("ok", 200, { "cache-control": "no-store" });

      // Feeds (R2 read-only)
      if (path.startsWith("/feeds/")) return serveFeedFromR2(env, path);

      /* ---------------- Admin auth ---------------- */

      if (path === "/admin/login" && method === "POST") return adminLogin(request, env);
      if (path === "/admin/logout" && method === "POST") return adminLogout(request, env);

      /* ---------------- Admin APIs ---------------- */

      if (path.startsWith("/admin/api/")) {
        if (!(await requireAdminSession(request, env))) {
          return json({ error: "Unauthorized" }, 401, { "cache-control": "no-store" });
        }
      if (path === "/admin/api/game-tags" && method === "GET") {
        return adminListGameTags(env);
      }

      if (path === "/admin/api/game-tags/upsert" && method === "POST") {
        return adminUpsertGameTag(request, env);
      }

      if (path === "/admin/api/game-tags/delete" && method === "POST") {
        return adminDeleteGameTag(request, env);
      }
        // Creator management
        if (path === "/admin/api/creators" && method === "GET") return adminListCreators(env);
        if (path === "/admin/api/creators/issue-token" && method === "POST") return adminIssueToken(request, env);
        if (path === "/admin/api/creators/update-state" && method === "POST")
          return adminUpdateCreatorState(request, env, ctx);
        if (path === "/admin/api/creators/allowed-tags" && method === "POST") return adminSetAllowedTags(request, env);

        // Feed publication (manual trigger)
        if (path === "/admin/api/feeds/publish" && method === "POST") {
          // publish in background but also return the new version
          const result = await publishFeeds(env);
          return json({ ok: true, ...result }, 200, { "cache-control": "no-store" });
        }

        return json({ error: "Not found" }, 404, { "cache-control": "no-store" });
      }

      /* ---------------- Creator auth ---------------- */

      if (path === "/api/submit/login" && method === "POST") return creatorLogin(request, env);
      if (path === "/api/submit/logout" && method === "POST") return creatorLogout(request, env);

      if (path === "/api/submit/me" && method === "GET") {
        const creator = await requireCreatorSession(request, env);
        if (!creator) return json({ error: "Unauthorized" }, 401, { "cache-control": "no-store" });

        return json(
          { ok: true, creator: pickCreatorSafe(creator) },
          200,
          { "cache-control": "no-store" }
        );
      }

      /* ---------------- Creator video APIs (Phase 2F + Phase 3 hooks) ---------------- */

      if (path === "/api/submit/videos" && method === "GET") {
        const creator = await requireCreatorSession(request, env);
        if (!creator) return json({ error: "Unauthorized" }, 401, { "cache-control": "no-store" });

        await expireCreatorVideosIfNeeded(env, creator.id);

        const allowedTags = await getAllowedTagsForCreator(env, creator.id);

        const videos = await env.DB.prepare(
          `SELECT id, youtube_video_id, youtube_url, game_tag, status,
                  submitted_at, expires_at, inactive_at, deleted_at, repost_count
           FROM videos
           WHERE creator_id = ?
           ORDER BY submitted_at DESC
           LIMIT 20`
        ).bind(creator.id).all();

        return json(
          {
            ok: true,
            creator: pickCreatorSafe(creator),
            allowed_tags: allowedTags,
            videos: videos.results ?? [],
          },
          200,
          { "cache-control": "no-store" }
        );
      }

      if (path === "/api/submit" && method === "POST") {
        const creator = await requireCreatorSession(request, env);
        if (!creator) return json({ error: "Unauthorized" }, 401, { "cache-control": "no-store" });

        if (creator.state !== "approved") {
          return json({ error: "Forbidden" }, 403, { "cache-control": "no-store" });
        }

        await expireCreatorVideosIfNeeded(env, creator.id);

        const body = await safeJson(request);
        if (!body) return json({ error: "Invalid JSON" }, 400, { "cache-control": "no-store" });

        const youtubeUrl = typeof body.youtube_url === "string" ? body.youtube_url.trim() : "";
        const gameTag = typeof body.game_tag === "string" ? body.game_tag.trim() : "";

        if (!youtubeUrl || !gameTag) {
          return json({ error: "Missing youtube_url or game_tag" }, 400, { "cache-control": "no-store" });
        }

        const ytId = parseYouTubeVideoId(youtubeUrl);
        if (!ytId) return json({ error: "Invalid YouTube URL" }, 400, { "cache-control": "no-store" });

        if (!(await isGameTagAllowed(env, creator.id, gameTag))) {
          return json({ error: "Unauthorized game tag" }, 403, { "cache-control": "no-store" });
        }

        const maxActive = parsePositiveInt(env.MAX_ACTIVE_VIDEOS_PER_CREATOR, DEFAULT_MAX_ACTIVE_VIDEOS);
        const activeCount = await countActiveVideosForCreator(env, creator.id);
        if (activeCount >= maxActive) {
          return json({ error: "Active video limit reached", max_active: maxActive }, 403, { "cache-control": "no-store" });
        }

        const existing = await env.DB.prepare(
          `SELECT id, creator_id, status
           FROM videos
           WHERE youtube_video_id = ?
           LIMIT 1`
        ).bind(ytId).first();

        const nowIso = new Date().toISOString();
        const expiresIso = addDaysIso(nowIso, DEFAULT_VIDEO_LIFETIME_DAYS);

        if (existing) {
          if (existing.creator_id !== creator.id) {
            return json({ error: "Video already submitted" }, 409, { "cache-control": "no-store" });
          }
          if (existing.status === "inactive" || existing.status === "deleted") {
            await env.DB.prepare(
              `UPDATE videos
               SET status='active',
                   submitted_at=?,
                   expires_at=?,
                   inactive_at=NULL,
                   deleted_at=NULL,
                   repost_count=repost_count+1
               WHERE id=? AND creator_id=?`
            ).bind(nowIso, expiresIso, existing.id, creator.id).run();

            const updated = await env.DB.prepare(
              `SELECT id, youtube_video_id, youtube_url, game_tag, status,
                      submitted_at, expires_at, inactive_at, deleted_at, repost_count
               FROM videos WHERE id=?`
            ).bind(existing.id).first();

            // Additions can wait for cron; no immediate publish required.
            return json({ ok: true, mode: "reposted", video: updated }, 200, { "cache-control": "no-store" });
          }
          return json({ error: "Video already active" }, 409, { "cache-control": "no-store" });
        }

        const id = crypto.randomUUID();
        await env.DB.prepare(
          `INSERT INTO videos (
             id, creator_id, youtube_video_id, youtube_url, game_tag,
             status, submitted_at, expires_at, repost_count
           ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, 0)`
        ).bind(id, creator.id, ytId, youtubeUrl, gameTag, nowIso, expiresIso).run();

        const inserted = await env.DB.prepare(
          `SELECT id, youtube_video_id, youtube_url, game_tag, status,
                  submitted_at, expires_at, inactive_at, deleted_at, repost_count
           FROM videos WHERE id=?`
        ).bind(id).first();

        // Additions can wait for cron; no immediate publish required.
        return json({ ok: true, mode: "inserted", video: inserted }, 200, { "cache-control": "no-store" });
      }

      if (path === "/api/video/delete" && method === "POST") {
        const creator = await requireCreatorSession(request, env);
        if (!creator) return json({ error: "Unauthorized" }, 401, { "cache-control": "no-store" });

        if (creator.state !== "approved") {
          return json({ error: "Forbidden" }, 403, { "cache-control": "no-store" });
        }

        await expireCreatorVideosIfNeeded(env, creator.id);

        const body = await safeJson(request);
        if (!body) return json({ error: "Invalid JSON" }, 400, { "cache-control": "no-store" });

        const videoId = typeof body.video_id === "string" ? body.video_id.trim() : "";
        if (!videoId) return json({ error: "Missing video_id" }, 400, { "cache-control": "no-store" });

        const nowIso = new Date().toISOString();

        await env.DB.prepare(
          `UPDATE videos
           SET status='deleted', deleted_at=?
           WHERE id=? AND creator_id=? AND status!='deleted'`
        ).bind(nowIso, videoId, creator.id).run();

        const row = await env.DB.prepare(
          `SELECT id, status, deleted_at FROM videos WHERE id=? AND creator_id=?`
        ).bind(videoId, creator.id).first();

        if (!row) return json({ error: "Not found" }, 404, { "cache-control": "no-store" });

        // Immediate republish (takedown)
        ctx.waitUntil(publishFeeds(env));

        return json({ ok: true, video: row }, 200, { "cache-control": "no-store" });
      }

      if (path === "/api/video/repost" && method === "POST") {
        const creator = await requireCreatorSession(request, env);
        if (!creator) return json({ error: "Unauthorized" }, 401, { "cache-control": "no-store" });

        if (creator.state !== "approved") {
          return json({ error: "Forbidden" }, 403, { "cache-control": "no-store" });
        }

        await expireCreatorVideosIfNeeded(env, creator.id);

        const maxActive = parsePositiveInt(env.MAX_ACTIVE_VIDEOS_PER_CREATOR, DEFAULT_MAX_ACTIVE_VIDEOS);
        const activeCount = await countActiveVideosForCreator(env, creator.id);
        if (activeCount >= maxActive) {
          return json({ error: "Active video limit reached", max_active: maxActive }, 403, { "cache-control": "no-store" });
        }

        const body = await safeJson(request);
        if (!body) return json({ error: "Invalid JSON" }, 400, { "cache-control": "no-store" });

        const videoId = typeof body.video_id === "string" ? body.video_id.trim() : "";
        if (!videoId) return json({ error: "Missing video_id" }, 400, { "cache-control": "no-store" });

        const existing = await env.DB.prepare(
          `SELECT id, status FROM videos WHERE id=? AND creator_id=? LIMIT 1`
        ).bind(videoId, creator.id).first();

        if (!existing) return json({ error: "Not found" }, 404, { "cache-control": "no-store" });

        if (existing.status !== "inactive" && existing.status !== "deleted") {
          return json({ error: "Not eligible for repost" }, 409, { "cache-control": "no-store" });
        }

        const nowIso = new Date().toISOString();
        const expiresIso = addDaysIso(nowIso, DEFAULT_VIDEO_LIFETIME_DAYS);

        await env.DB.prepare(
          `UPDATE videos
           SET status='active',
               submitted_at=?,
               expires_at=?,
               inactive_at=NULL,
               deleted_at=NULL,
               repost_count=repost_count+1
           WHERE id=? AND creator_id=?`
        ).bind(nowIso, expiresIso, videoId, creator.id).run();

        const updated = await env.DB.prepare(
          `SELECT id, youtube_video_id, youtube_url, game_tag, status,
                  submitted_at, expires_at, inactive_at, deleted_at, repost_count
           FROM videos WHERE id=?`
        ).bind(videoId).first();

        // Additions can wait for cron; no immediate publish required.
        return json({ ok: true, video: updated }, 200, { "cache-control": "no-store" });
      }

      /* ---------------- Placeholders (pages) ---------------- */

      if (path === "/admin" || path === "/admin/") return text("Admin UI placeholder", 200, { "cache-control": "no-store" });
      if (path === "/submit" || path === "/submit/") return text("Creator submit UI placeholder", 200, { "cache-control": "no-store" });

      return json({ error: "Not found" }, 404, { "cache-control": "no-store" });
    } catch {
      return json({ error: "Internal error" }, 500, { "cache-control": "no-store" });
    }
  },

  async scheduled(controller, env, ctx) {
    // Scheduled job: lifecycle cleanup + publish feeds
    ctx.waitUntil(publishFeeds(env));
  },
};

/* =========================================================
   Phase 3: Lifecycle + Feed Publisher
   ========================================================= */

async function publishFeeds(env) {
  // 1) lifecycle cleanup (global)
  const nowIso = new Date().toISOString();
  const inactiveCutoffIso = addDaysIso(nowIso, -INACTIVE_GRACE_DAYS);

  // active -> inactive where expired
  await env.DB.prepare(
    `UPDATE videos
     SET status='inactive',
         inactive_at=COALESCE(inactive_at, ?)
     WHERE status='active'
       AND expires_at <= ?`
  ).bind(nowIso, nowIso).run();

  // inactive -> deleted after grace period
  await env.DB.prepare(
    `UPDATE videos
     SET status='deleted',
         deleted_at=COALESCE(deleted_at, ?)
     WHERE status='inactive'
       AND inactive_at IS NOT NULL
       AND inactive_at <= ?`
  ).bind(nowIso, inactiveCutoffIso).run();

  // 2) query active videos for feeds (only approved creators)
  const rows = await env.DB.prepare(
    `SELECT v.youtube_video_id, v.game_tag, v.submitted_at,
            c.display_name AS creator_name
     FROM videos v
     JOIN creators c ON c.id = v.creator_id
     WHERE v.status='active'
       AND v.expires_at > ?
       AND c.state='approved'
     ORDER BY v.submitted_at DESC`
  ).bind(nowIso).all();

  const latest = (rows.results ?? []).map((r) => ({
    youtube_id: r.youtube_video_id,
    thumbnail_url: `https://i.ytimg.com/vi/${r.youtube_video_id}/hqdefault.jpg`,
    creator: r.creator_name,
    game: r.game_tag,
    submitted_at: r.submitted_at,
  }));

  const lumenLimit = parsePositiveInt(env.LUMEN_FEED_LIMIT, 10);
  const lumen = latest.slice(0, lumenLimit);

  // 3) version bump via manifest
  const prefix = typeof env.FEEDS_PREFIX === "string" && env.FEEDS_PREFIX.trim() ? env.FEEDS_PREFIX.trim() : "feeds";
  const manifestKey = `${prefix}/manifest.json`;

  let currentVersion = 0;
  const manifestObj = await env.FEED_BUCKET.get(manifestKey);
  if (manifestObj) {
    try {
      const parsed = await manifestObj.json();
      const v = Number(parsed?.latest_version ?? 0);
      if (Number.isFinite(v) && v >= 0) currentVersion = v;
    } catch {
      // ignore; treat as 0
    }
  }
  const newVersion = currentVersion + 1;

  const lumenKey = `${prefix}/lumen.v${newVersion}.json`;
  const latestKey = `${prefix}/latest.v${newVersion}.json`;

  // 4) write versioned feeds
  await env.FEED_BUCKET.put(lumenKey, JSON.stringify(lumen), {
    httpMetadata: { contentType: "application/json; charset=utf-8" },
  });

  await env.FEED_BUCKET.put(latestKey, JSON.stringify(latest), {
    httpMetadata: { contentType: "application/json; charset=utf-8" },
  });

  // 5) update manifest
  const newManifest = {
    latest_version: newVersion,
    updated_at: nowIso,
    counts: {
      lumen: lumen.length,
      latest: latest.length,
    },
  };

  await env.FEED_BUCKET.put(manifestKey, JSON.stringify(newManifest), {
    httpMetadata: { contentType: "application/json; charset=utf-8" },
  });

  return { version: newVersion, keys: { lumen: lumenKey, latest: latestKey, manifest: manifestKey }, counts: newManifest.counts };
}

/* =========================================================
   Admin auth/session (D1-backed)
   ========================================================= */

async function adminLogin(request, env) {
  if (!env.ADMIN_KEY || typeof env.ADMIN_KEY !== "string") {
    return json({ error: "Admin auth not configured" }, 500, { "cache-control": "no-store" });
  }

  const body = await safeJson(request);
  if (!body) return json({ error: "Invalid JSON" }, 400, { "cache-control": "no-store" });

  const provided = typeof body.key === "string" ? body.key : "";
  if (!provided) return json({ error: "Missing key" }, 400, { "cache-control": "no-store" });

  if (!timingSafeEqualUtf8(provided, env.ADMIN_KEY)) {
    return json({ error: "Unauthorized" }, 401, { "cache-control": "no-store" });
  }

  await deleteExpiredAdminSessions(env);

  const sessionId = crypto.randomUUID();
  const sessionHash = await sha256Hex(sessionId);
  const expiresAt = new Date(Date.now() + ADMIN_SESSION_MAX_AGE_SECONDS * 1000).toISOString();

  await env.DB.prepare(
    "INSERT OR REPLACE INTO admin_sessions (session_hash, expires_at) VALUES (?, ?)"
  ).bind(sessionHash, expiresAt).run();

  const setCookie = buildSetCookie(ADMIN_COOKIE_NAME, sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    path: "/",
    maxAge: ADMIN_SESSION_MAX_AGE_SECONDS,
  });

  return json({ ok: true }, 200, { "set-cookie": setCookie, "cache-control": "no-store" });
}

async function adminLogout(request, env) {
  const cookies = parseCookies(request.headers.get("cookie") || "");
  const sessionId = cookies[ADMIN_COOKIE_NAME];

  if (sessionId) {
    const sessionHash = await sha256Hex(sessionId);
    await env.DB.prepare("DELETE FROM admin_sessions WHERE session_hash = ?").bind(sessionHash).run();
  }

  const clearCookie = buildSetCookie(ADMIN_COOKIE_NAME, "", {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    path: "/",
    maxAge: 0,
  });

  return json({ ok: true }, 200, { "set-cookie": clearCookie, "cache-control": "no-store" });
}

async function requireAdminSession(request, env) {
  const cookies = parseCookies(request.headers.get("cookie") || "");
  const sessionId = cookies[ADMIN_COOKIE_NAME];
  if (!sessionId) return false;

  const sessionHash = await sha256Hex(sessionId);
  const nowIso = new Date().toISOString();

  const row = await env.DB.prepare(
    "SELECT session_hash FROM admin_sessions WHERE session_hash = ? AND expires_at > ? LIMIT 1"
  ).bind(sessionHash, nowIso).first();

  return !!row;
}

async function deleteExpiredAdminSessions(env) {
  const nowIso = new Date().toISOString();
  await env.DB.prepare("DELETE FROM admin_sessions WHERE expires_at <= ?").bind(nowIso).run();
}

/* =========================================================
   Admin creator APIs
   ========================================================= */

  async function adminListCreators(env) {
    const rows = await env.DB.prepare(
      `SELECT c.id, c.display_name, c.email, c.youtube_channel, c.state, c.created_at, c.approved_at,
              cat.game_tag AS allowed_tag
      FROM creators c
      LEFT JOIN creator_allowed_tags cat
        ON cat.creator_id = c.id
      ORDER BY c.created_at DESC`
    ).all();

    // Group rows into creators with allowed_tags[]
    const map = new Map();

    for (const r of (rows.results ?? [])) {
      if (!map.has(r.id)) {
        map.set(r.id, {
          id: r.id,
          display_name: r.display_name,
          email: r.email,
          youtube_channel: r.youtube_channel,
          state: r.state,
          created_at: r.created_at,
          approved_at: r.approved_at,
          allowed_tags: [],
        });
      }
      if (r.allowed_tag) {
        map.get(r.id).allowed_tags.push(r.allowed_tag);
      }
    }

    const creators = Array.from(map.values());
    return json({ creators }, 200, { "cache-control": "no-store" });
  }

async function adminIssueToken(request, env) {
  const body = await safeJson(request);
  if (!body) return json({ error: "Invalid JSON" }, 400, { "cache-control": "no-store" });

  const creatorId = typeof body.creator_id === "string" ? body.creator_id.trim() : "";
  if (!creatorId) return json({ error: "Missing creator_id" }, 400, { "cache-control": "no-store" });

  const token = `alyxar_${crypto.randomUUID()}`;
  const tokenHash = await sha256Hex(token);

  await env.DB.prepare(
    `UPDATE creators
     SET submit_token_hash = ?,
         submit_session_hash = NULL,
         submit_session_expires_at = NULL
     WHERE id = ?`
  ).bind(tokenHash, creatorId).run();

  return json({ ok: true, token }, 200, { "cache-control": "no-store" });
}

async function adminUpdateCreatorState(request, env, ctx) {
  const body = await safeJson(request);
  if (!body) return json({ error: "Invalid JSON" }, 400, { "cache-control": "no-store" });

  const creatorId = typeof body.creator_id === "string" ? body.creator_id.trim() : "";
  const state = typeof body.state === "string" ? body.state.trim() : "";

  if (!creatorId || !state) return json({ error: "Missing fields" }, 400, { "cache-control": "no-store" });

  const allowed = new Set(["approved", "waitlisted", "suspended", "banned"]);
  if (!allowed.has(state)) return json({ error: "Invalid state" }, 400, { "cache-control": "no-store" });

  const nowIso = new Date().toISOString();

  await env.DB.prepare(
    `UPDATE creators
     SET state = ?,
         approved_at = CASE WHEN ? = 'approved' THEN ? ELSE approved_at END,
         submit_session_hash = NULL,
         submit_session_expires_at = NULL
     WHERE id = ?`
  ).bind(state, state, nowIso, creatorId).run();

  // Hard takedown on suspend/ban: remove all videos immediately + republish feeds
  if (state === "suspended" || state === "banned") {
    await env.DB.prepare(`DELETE FROM videos WHERE creator_id = ?`).bind(creatorId).run();
    ctx.waitUntil(publishFeeds(env));
  }

  return json({ ok: true }, 200, { "cache-control": "no-store" });
}

async function adminSetAllowedTags(request, env) {
  const body = await safeJson(request);
  if (!body) return json({ error: "Invalid JSON" }, 400, { "cache-control": "no-store" });

  const creatorId = typeof body.creator_id === "string" ? body.creator_id.trim() : "";
  const tags = Array.isArray(body.tags) ? body.tags.map((t) => (typeof t === "string" ? t.trim() : "")).filter(Boolean) : null;

  if (!creatorId || tags === null) return json({ error: "Invalid payload" }, 400, { "cache-control": "no-store" });

  if (tags.length > 0) {
    const placeholders = tags.map(() => "?").join(",");
    const valid = await env.DB.prepare(`SELECT tag FROM game_tags WHERE tag IN (${placeholders})`)
      .bind(...tags).all();

    if ((valid.results ?? []).length !== tags.length) {
      return json({ error: "Invalid game tag" }, 400, { "cache-control": "no-store" });
    }
  }

  await env.DB.prepare(`DELETE FROM creator_allowed_tags WHERE creator_id = ?`).bind(creatorId).run();

  for (const tag of tags) {
    await env.DB.prepare(`INSERT INTO creator_allowed_tags (creator_id, game_tag) VALUES (?, ?)`)
      .bind(creatorId, tag).run();
  }

  return json({ ok: true }, 200, { "cache-control": "no-store" });
}
  async function adminListGameTags(env) {
    const rows = await env.DB.prepare(
      `SELECT tag, label
      FROM game_tags
      ORDER BY tag ASC`
    ).all();

    return json({ ok: true, tags: rows.results ?? [] }, 200, { "cache-control": "no-store" });
  }

  async function adminUpsertGameTag(request, env) {
    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid JSON" }, 400, { "cache-control": "no-store" });

    const tag = typeof body.tag === "string" ? body.tag.trim() : "";
    const label = typeof body.label === "string" ? body.label.trim() : "";

    // Tag is the stable identifier used everywhere; keep it strict.
    if (!tag) return json({ error: "Missing tag" }, 400, { "cache-control": "no-store" });
    if (!/^[a-z0-9][a-z0-9-_]{1,48}$/.test(tag)) {
      return json({ error: "Invalid tag format. Use lowercase letters, numbers, '-' or '_' (2-49 chars)." }, 400, { "cache-control": "no-store" });
    }

    await env.DB.prepare(
      `INSERT INTO game_tags (tag, label)
      VALUES (?, ?)
      ON CONFLICT(tag) DO UPDATE SET label = excluded.label`
    ).bind(tag, label || null).run();

    return json({ ok: true }, 200, { "cache-control": "no-store" });
  }

  async function adminDeleteGameTag(request, env) {
    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid JSON" }, 400, { "cache-control": "no-store" });

    const tag = typeof body.tag === "string" ? body.tag.trim() : "";
    if (!tag) return json({ error: "Missing tag" }, 400, { "cache-control": "no-store" });

    // Block delete if in use by creators
    const inCreators = await env.DB.prepare(
      `SELECT 1 AS ok FROM creator_allowed_tags WHERE game_tag = ? LIMIT 1`
    ).bind(tag).first();

    if (inCreators) {
      return json({ error: "Tag is assigned to creators; remove assignments first." }, 409, { "cache-control": "no-store" });
    }

    // Block delete if used by videos (historic integrity)
    const inVideos = await env.DB.prepare(
      `SELECT 1 AS ok FROM videos WHERE game_tag = ? LIMIT 1`
    ).bind(tag).first();

    if (inVideos) {
      return json({ error: "Tag is used by videos; cannot delete." }, 409, { "cache-control": "no-store" });
    }

    await env.DB.prepare(`DELETE FROM game_tags WHERE tag = ?`).bind(tag).run();

    return json({ ok: true }, 200, { "cache-control": "no-store" });
  }
/* =========================================================
   Creator auth/session (Creators table)
   ========================================================= */

async function creatorLogin(request, env) {
  const body = await safeJson(request);
  if (!body) return json({ error: "Invalid JSON" }, 400, { "cache-control": "no-store" });

  const token = typeof body.token === "string" ? body.token.trim() : "";
  if (!token) return json({ error: "Missing token" }, 400, { "cache-control": "no-store" });

  const tokenHash = await sha256Hex(token);

  const creator = await env.DB.prepare(
    "SELECT id, display_name, email, state FROM creators WHERE submit_token_hash = ? LIMIT 1"
  ).bind(tokenHash).first();

  if (!creator) return json({ error: "Unauthorized" }, 401, { "cache-control": "no-store" });

  if (creator.state !== "approved" && creator.state !== "suspended" && creator.state !== "banned") {
    return json({ error: "Unauthorized" }, 401, { "cache-control": "no-store" });
  }

  const sessionId = crypto.randomUUID();
  const sessionHash = await sha256Hex(sessionId);
  const expiresAt = new Date(Date.now() + CREATOR_SESSION_MAX_AGE_SECONDS * 1000).toISOString();

  await env.DB.prepare(
    "UPDATE creators SET submit_session_hash = ?, submit_session_expires_at = ? WHERE id = ?"
  ).bind(sessionHash, expiresAt, creator.id).run();

  const setCookie = buildSetCookie(CREATOR_COOKIE_NAME, sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    path: "/",
    maxAge: CREATOR_SESSION_MAX_AGE_SECONDS,
  });

  return json({ ok: true, creator: pickCreatorSafe(creator) }, 200, { "set-cookie": setCookie, "cache-control": "no-store" });
}

async function creatorLogout(request, env) {
  const cookies = parseCookies(request.headers.get("cookie") || "");
  const sessionId = cookies[CREATOR_COOKIE_NAME];

  if (sessionId) {
    const sessionHash = await sha256Hex(sessionId);
    await env.DB.prepare(
      "UPDATE creators SET submit_session_hash = NULL, submit_session_expires_at = NULL WHERE submit_session_hash = ?"
    ).bind(sessionHash).run();
  }

  const clearCookie = buildSetCookie(CREATOR_COOKIE_NAME, "", {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    path: "/",
    maxAge: 0,
  });

  return json({ ok: true }, 200, { "set-cookie": clearCookie, "cache-control": "no-store" });
}

async function requireCreatorSession(request, env) {
  const cookies = parseCookies(request.headers.get("cookie") || "");
  const sessionId = cookies[CREATOR_COOKIE_NAME];
  if (!sessionId) return null;

  const sessionHash = await sha256Hex(sessionId);
  const nowIso = new Date().toISOString();

  const creator = await env.DB.prepare(
    `SELECT id, display_name, email, state
     FROM creators
     WHERE submit_session_hash = ? AND submit_session_expires_at > ?
     LIMIT 1`
  ).bind(sessionHash, nowIso).first();

  return creator || null;
}

function pickCreatorSafe(creator) {
  return { id: creator.id, display_name: creator.display_name, email: creator.email, state: creator.state };
}

/* =========================================================
   Creator video helpers
   ========================================================= */

async function expireCreatorVideosIfNeeded(env, creatorId) {
  const nowIso = new Date().toISOString();
  await env.DB.prepare(
    `UPDATE videos
     SET status='inactive',
         inactive_at=COALESCE(inactive_at, ?)
     WHERE creator_id=?
       AND status='active'
       AND expires_at <= ?`
  ).bind(nowIso, creatorId, nowIso).run();
}

async function countActiveVideosForCreator(env, creatorId) {
  const nowIso = new Date().toISOString();
  const row = await env.DB.prepare(
    `SELECT COUNT(1) AS cnt
     FROM videos
     WHERE creator_id=?
       AND status='active'
       AND expires_at > ?`
  ).bind(creatorId, nowIso).first();

  return Number(row?.cnt ?? 0);
}

async function getAllowedTagsForCreator(env, creatorId) {
  const rows = await env.DB.prepare(
    `SELECT game_tag
     FROM creator_allowed_tags
     WHERE creator_id=?
     ORDER BY game_tag ASC`
  ).bind(creatorId).all();

  return (rows.results ?? []).map((r) => r.game_tag);
}

async function isGameTagAllowed(env, creatorId, gameTag) {
  const row = await env.DB.prepare(
    `SELECT 1 AS ok
     FROM creator_allowed_tags
     WHERE creator_id=? AND game_tag=?
     LIMIT 1`
  ).bind(creatorId, gameTag).first();

  return !!row;
}

/* =========================================================
   YouTube URL parsing
   ========================================================= */

function parseYouTubeVideoId(inputUrl) {
  const raw = inputUrl.trim();
  if (/^[a-zA-Z0-9_-]{11}$/.test(raw)) return raw;

  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }

  const host = url.hostname.replace(/^www\./, "").toLowerCase();

  if (host === "youtu.be") {
    const id = url.pathname.split("/").filter(Boolean)[0] || "";
    return /^[a-zA-Z0-9_-]{11}$/.test(id) ? id : null;
  }

  if (host === "youtube.com" || host === "m.youtube.com" || host === "music.youtube.com") {
    if (url.pathname === "/watch") {
      const id = url.searchParams.get("v") || "";
      return /^[a-zA-Z0-9_-]{11}$/.test(id) ? id : null;
    }

    const parts = url.pathname.split("/").filter(Boolean);
    if (parts[0] === "shorts" && parts[1]) return /^[a-zA-Z0-9_-]{11}$/.test(parts[1]) ? parts[1] : null;
    if (parts[0] === "embed" && parts[1]) return /^[a-zA-Z0-9_-]{11}$/.test(parts[1]) ? parts[1] : null;
  }

  return null;
}

/* =========================================================
   Generic helpers
   ========================================================= */

function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...headers,
    },
  });
}

function text(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", ...headers },
  });
}

async function safeJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function parseCookies(cookieHeader) {
  const out = Object.create(null);
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

function buildSetCookie(name, value, opts) {
  const segments = [`${name}=${value}`];
  if (opts.maxAge !== undefined) segments.push(`Max-Age=${opts.maxAge}`);
  if (opts.path) segments.push(`Path=${opts.path}`);
  if (opts.sameSite) segments.push(`SameSite=${opts.sameSite}`);
  if (opts.httpOnly) segments.push("HttpOnly");
  if (opts.secure) segments.push("Secure");
  return segments.join("; ");
}

function timingSafeEqualUtf8(a, b) {
  const enc = new TextEncoder();
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);
  let diff = aBytes.length ^ bBytes.length;
  const len = Math.max(aBytes.length, bBytes.length);
  for (let i = 0; i < len; i++) diff |= (aBytes[i] ?? 0) ^ (bBytes[i] ?? 0);
  return diff === 0;
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

function parsePositiveInt(value, fallback) {
  const n = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function addDaysIso(iso, days) {
  const d = new Date(iso);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString();
}

/* =========================================================
   Feeds (R2 read-only)
   ========================================================= */

async function serveFeedFromR2(env, path) {
  const prefix = typeof env.FEEDS_PREFIX === "string" && env.FEEDS_PREFIX.trim() ? env.FEEDS_PREFIX.trim() : "feeds";
  const key = path.startsWith("/") ? path.slice(1) : path;

  if (!key.startsWith(`${prefix}/`)) return json({ error: "Not found" }, 404, { "cache-control": "no-store" });

  const obj = await env.FEED_BUCKET.get(key);
  if (!obj) return json({ error: "Feed not found" }, 404, { "cache-control": "no-store" });

  const isManifest = key === `${prefix}/manifest.json`;
  const isVersioned = /\.v\d+\.json$/i.test(key);

  const cacheControl = isManifest
    ? "public, max-age=30, must-revalidate"
    : isVersioned
      ? "public, max-age=86400, immutable"
      : "public, max-age=300";

  const headers = new Headers();
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", cacheControl);
  if (obj.httpEtag) headers.set("etag", obj.httpEtag);

  return new Response(obj.body, { status: 200, headers });
}
