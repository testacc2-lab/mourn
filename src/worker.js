const RESERVED_USERNAMES = new Set([
  "admin", "administrator", "root", "api", "dashboard", "login", "signup",
  "help", "privacy", "terms", "pricing", "profile", "home", "www"
]);

const SESSION_COOKIE = "mourn_session";
const SESSION_TTL_DAYS = 30;
const VIEW_DEDUPE_MS = 6 * 60 * 60 * 1000;
const PBKDF2_ITERATIONS = 210000;
const encoder = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (!url.pathname.startsWith("/api/")) {
      const assetRes = await env.ASSETS.fetch(request);
      if (assetRes.status !== 404) {
        return assetRes;
      }

      const fallbackCandidates = [];
      const pathname = url.pathname;
      if (pathname === "/") {
        fallbackCandidates.push("/index.html");
      } else if (!pathname.includes(".")) {
        fallbackCandidates.push(pathname + "/index.html");
        fallbackCandidates.push(pathname + "/");
      }

      for (const candidatePath of fallbackCandidates) {
        const fallbackUrl = new URL(request.url);
        fallbackUrl.pathname = candidatePath;
        const fallbackReq = new Request(fallbackUrl.toString(), request);
        const fallbackRes = await env.ASSETS.fetch(fallbackReq);
        if (fallbackRes.status !== 404) {
          return fallbackRes;
        }
      }

      const routeUsername = usernameFromPathname(url.pathname);
      if (routeUsername) {
        const profileUrl = new URL(request.url);
        profileUrl.pathname = "/profile/";
        profileUrl.searchParams.set("u", routeUsername);
        const rewritten = new Request(profileUrl.toString(), request);
        return env.ASSETS.fetch(rewritten);
      }

      return assetRes;
    }

    if (!env.DB) {
      return json({ error: "Database binding missing" }, 500);
    }

    try {
      if (url.pathname === "/api/check" && request.method === "GET") {
        return handleCheck(url, env);
      }
      if (url.pathname === "/api/signup" && request.method === "POST") {
        return handleSignup(request, env);
      }
      if (url.pathname === "/api/login" && request.method === "POST") {
        return handleLogin(request, env);
      }
      if (url.pathname === "/api/logout" && request.method === "POST") {
        return handleLogout(request, env);
      }
      if (url.pathname === "/api/profile" && request.method === "GET") {
        return handleProfileGet(request, env);
      }
      if (url.pathname === "/api/profile" && request.method === "POST") {
        return handleProfileSave(request, env);
      }
      if (url.pathname === "/api/public-profile" && request.method === "GET") {
        return handlePublicProfile(url, request, env);
      }
      if (url.pathname === "/api/admin/badges/grant" && request.method === "POST") {
        return handleAdminGrantBadge(request, env);
      }
      if (url.pathname === "/api/admin/badges/revoke" && request.method === "POST") {
        return handleAdminRevokeBadge(request, env);
      }
      if (url.pathname === "/api/upload" && request.method === "POST") {
        return json({ error: "Upload storage is not configured yet" }, 501);
      }

      return json({ error: "Not found" }, 404);
    } catch (err) {
      console.error("API error", err);
      return json({ error: "Internal server error" }, 500);
    }
  },
};

async function handleCheck(url, env) {
  const username = normalizeUsername(url.searchParams.get("username") || "");
  if (!isValidUsername(username)) {
    return json({ available: false, reason: "invalid" });
  }
  if (RESERVED_USERNAMES.has(username)) {
    return json({ available: false, reason: "reserved" });
  }

  const exists = await env.DB.prepare("SELECT 1 FROM users WHERE username = ? LIMIT 1")
    .bind(username)
    .first();
  return json({ available: !exists, reason: exists ? "taken" : "ok" });
}

async function handleSignup(request, env) {
  const body = await readJson(request);
  const username = normalizeUsername(body.username || "");
  const email = normalizeEmail(body.email || "");
  const password = String(body.password || "");

  if (!isValidUsername(username)) {
    return json({ error: "Username must be 2-20 chars: a-z 0-9 _ ." }, 400);
  }
  if (RESERVED_USERNAMES.has(username)) {
    return json({ error: "Username is reserved" }, 400);
  }
  if (!isValidEmail(email)) {
    return json({ error: "Enter a valid email" }, 400);
  }
  if (isDisposableEmail(email)) {
    return json({ error: "Please use a permanent email address. Disposable email providers are not allowed." }, 400);
  }
  if (password.length < 8) {
    return json({ error: "Password must be at least 8 characters" }, 400);
  }

  const dup = await env.DB.prepare(
    "SELECT username, email FROM users WHERE username = ? OR email = ? LIMIT 1"
  ).bind(username, email).first();
  if (dup) {
    return json({ error: "Username or email already exists" }, 409);
  }

  const createdAt = new Date().toISOString();
  const passHash = await hashPassword(password);
  const insertUser = await env.DB.prepare(
    "INSERT INTO users (username, email, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?, 0)"
  ).bind(username, email, passHash, createdAt).run();

  const userId = Number(insertUser.meta.last_row_id || 0);
  if (!userId) {
    return json({ error: "Failed to create user" }, 500);
  }

  const profile = defaultProfile(username);
  await env.DB.prepare(
    "INSERT INTO profiles (user_id, profile_json, updated_at) VALUES (?, ?, ?)"
  ).bind(userId, JSON.stringify(profile), createdAt).run();

  await env.DB.prepare(
    "INSERT INTO profile_stats (user_id, views_total, updated_at) VALUES (?, 0, ?)"
  ).bind(userId, createdAt).run();

  return json({ ok: true });
}

async function handleLogin(request, env) {
  const body = await readJson(request);
  const identifier = String(body.identifier || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!identifier || !password) {
    return json({ error: "Missing credentials" }, 400);
  }

  const user = await env.DB.prepare(
    "SELECT id, username, email, password_hash, created_at FROM users WHERE username = ? OR email = ? LIMIT 1"
  ).bind(identifier, identifier).first();

  if (!user) {
    return json({ error: "Invalid username/email or password." }, 401);
  }

  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) {
    return json({ error: "Invalid username/email or password." }, 401);
  }

  const token = randomHex(32);
  const tokenHash = await sha256Hex(token);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_DAYS * 86400000);

  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(user.id).run();
  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)"
  ).bind(tokenHash, user.id, expiresAt.toISOString(), now.toISOString()).run();

  const headers = new Headers({ "content-type": "application/json; charset=utf-8" });
  headers.append("set-cookie", serializeSessionCookie(token, expiresAt, urlIsSecure(request.url)));
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

async function handleLogout(request, env) {
  const token = readCookie(request.headers.get("cookie"), SESSION_COOKIE);
  if (token) {
    const tokenHash = await sha256Hex(token);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
  }
  const headers = new Headers({ "content-type": "application/json; charset=utf-8" });
  headers.append("set-cookie", clearSessionCookie(urlIsSecure(request.url)));
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

async function handleProfileGet(request, env) {
  const auth = await requireAuth(request, env.DB);
  if (!auth.ok) {
    return json({ error: "Unauthorized" }, 401);
  }

  const merged = await buildProfileResponse(auth.user.id, auth.user.username, env.DB);
  return json({
    username: auth.user.username,
    email: auth.user.email,
    createdAt: auth.user.created_at,
    isAdmin: !!auth.user.is_admin,
    profile: merged,
  });
}

async function handleProfileSave(request, env) {
  const auth = await requireAuth(request, env.DB);
  if (!auth.ok) {
    return json({ error: "Unauthorized" }, 401);
  }

  const incoming = await readJson(request);
  const sanitized = sanitizeProfileInput(incoming, auth.user.username);
  const now = new Date().toISOString();

  await env.DB.prepare(
    "INSERT INTO profiles (user_id, profile_json, updated_at) VALUES (?, ?, ?) " +
      "ON CONFLICT(user_id) DO UPDATE SET profile_json = excluded.profile_json, updated_at = excluded.updated_at"
  ).bind(auth.user.id, JSON.stringify(sanitized), now).run();

  const merged = await buildProfileResponse(auth.user.id, auth.user.username, env.DB);
  return json({ ok: true, profile: merged });
}

async function handlePublicProfile(url, request, env) {
  const username = normalizeUsername(url.searchParams.get("u") || "");
  if (!isValidUsername(username)) {
    return json({ error: "Profile not found" }, 404);
  }

  const user = await env.DB.prepare(
    "SELECT id, username FROM users WHERE username = ? LIMIT 1"
  ).bind(username).first();

  if (!user) {
    return json({ error: "Profile not found" }, 404);
  }

  await recordProfileView(user.id, request, env.DB);
  const merged = await buildProfileResponse(user.id, user.username, env.DB);
  return json({ profile: merged });
}

async function handleAdminGrantBadge(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin.ok) {
    return json({ error: "Forbidden" }, 403);
  }

  const body = await readJson(request);
  const username = normalizeUsername(body.username || "");
  const badgeKey = badgeKeyFromLabel(body.key || body.label || "");
  const label = String(body.label || body.key || "").trim().slice(0, 40);
  const icon = sanitizeHttpUrl(body.icon || "");
  const grantedBy = String(body.grantedBy || admin.actor || "admin").trim().slice(0, 32);

  if (!isValidUsername(username) || !badgeKey || !label) {
    return json({ error: "username, key/label and label are required" }, 400);
  }

  const user = await env.DB.prepare("SELECT id FROM users WHERE username = ? LIMIT 1")
    .bind(username)
    .first();
  if (!user) {
    return json({ error: "User not found" }, 404);
  }

  await env.DB.prepare(
    "INSERT INTO badge_grants (user_id, badge_key, label, icon, granted_by, granted_at) VALUES (?, ?, ?, ?, ?, ?) " +
      "ON CONFLICT(user_id, badge_key) DO UPDATE SET label = excluded.label, icon = excluded.icon, granted_by = excluded.granted_by, granted_at = excluded.granted_at"
  ).bind(user.id, badgeKey, label, icon || null, grantedBy, new Date().toISOString()).run();

  return json({ ok: true });
}

async function handleAdminRevokeBadge(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin.ok) {
    return json({ error: "Forbidden" }, 403);
  }

  const body = await readJson(request);
  const username = normalizeUsername(body.username || "");
  const badgeKey = badgeKeyFromLabel(body.key || body.label || "");
  if (!isValidUsername(username) || !badgeKey) {
    return json({ error: "username and key are required" }, 400);
  }

  const user = await env.DB.prepare("SELECT id FROM users WHERE username = ? LIMIT 1")
    .bind(username)
    .first();
  if (!user) {
    return json({ error: "User not found" }, 404);
  }

  await env.DB.prepare("DELETE FROM badge_grants WHERE user_id = ? AND badge_key = ?")
    .bind(user.id, badgeKey)
    .run();

  return json({ ok: true });
}

async function buildProfileResponse(userId, username, db) {
  const row = await db.prepare("SELECT profile_json FROM profiles WHERE user_id = ? LIMIT 1")
    .bind(userId)
    .first();

  let profile = defaultProfile(username);
  if (row && row.profile_json) {
    try {
      const parsed = JSON.parse(row.profile_json);
      profile = sanitizeProfileInput(parsed, username);
    } catch {
      profile = defaultProfile(username);
    }
  }

  const badges = await listGrantedBadges(userId, db);
  profile.badges = badges;
  profile.handle = username;

  const stats = await db.prepare("SELECT views_total FROM profile_stats WHERE user_id = ? LIMIT 1")
    .bind(userId)
    .first();
  profile.views = Number(stats?.views_total || 0);

  return profile;
}

async function listGrantedBadges(userId, db) {
  const rows = await db.prepare(
    "SELECT badge_key, label, icon FROM badge_grants WHERE user_id = ? ORDER BY granted_at DESC LIMIT 24"
  ).bind(userId).all();

  return (rows.results || []).map((b) => ({
    key: String(b.badge_key || "").trim(),
    label: String(b.label || "").trim(),
    icon: sanitizeHttpUrl(b.icon || ""),
    custom: false,
  })).filter((b) => b.key && b.label);
}

async function recordProfileView(userId, request, db) {
  const now = new Date();
  const nowIso = now.toISOString();
  const viewerHash = await buildViewerHash(request);

  const existing = await db.prepare(
    "SELECT id, last_seen_at FROM profile_views WHERE user_id = ? AND viewer_hash = ? LIMIT 1"
  ).bind(userId, viewerHash).first();

  if (!existing) {
    await db.prepare(
      "INSERT INTO profile_views (user_id, viewer_hash, last_seen_at, total_hits) VALUES (?, ?, ?, 1)"
    ).bind(userId, viewerHash, nowIso).run();
    await incrementViewCounter(userId, nowIso, db);
    return;
  }

  const lastMs = Date.parse(existing.last_seen_at || "");
  await db.prepare("UPDATE profile_views SET last_seen_at = ?, total_hits = total_hits + 1 WHERE id = ?")
    .bind(nowIso, existing.id)
    .run();

  if (!Number.isFinite(lastMs) || now.getTime() - lastMs >= VIEW_DEDUPE_MS) {
    await incrementViewCounter(userId, nowIso, db);
  }
}

async function incrementViewCounter(userId, nowIso, db) {
  await db.prepare(
    "INSERT INTO profile_stats (user_id, views_total, updated_at) VALUES (?, 1, ?) " +
      "ON CONFLICT(user_id) DO UPDATE SET views_total = profile_stats.views_total + 1, updated_at = excluded.updated_at"
  ).bind(userId, nowIso).run();
}

function isAdminRequest(request, env) {
  const expected = String(env.ADMIN_API_KEY || "").trim();
  if (!expected) return false;
  const got = String(request.headers.get("x-admin-key") || "").trim();
  return !!got && got === expected;
}

async function requireAdmin(request, env) {
  const auth = await requireAuth(request, env.DB);
  if (auth.ok && auth.user.is_admin) {
    return { ok: true, actor: auth.user.username };
  }
  if (isAdminRequest(request, env)) {
    return { ok: true, actor: "api-key-admin" };
  }
  return { ok: false };
}

async function requireAuth(request, db) {
  const token = readCookie(request.headers.get("cookie"), SESSION_COOKIE);
  if (!token) {
    return { ok: false };
  }

  const tokenHash = await sha256Hex(token);
  const row = await db.prepare(
    "SELECT s.expires_at, u.id, u.username, u.email, u.created_at, u.is_admin FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? LIMIT 1"
  ).bind(tokenHash).first();

  if (!row) {
    return { ok: false };
  }

  const exp = Date.parse(row.expires_at || "");
  if (!Number.isFinite(exp) || exp < Date.now()) {
    await db.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
    return { ok: false };
  }

  return {
    ok: true,
    user: {
      id: Number(row.id),
      username: String(row.username || ""),
      email: String(row.email || ""),
      created_at: String(row.created_at || ""),
      is_admin: Number(row.is_admin || 0) === 1,
    },
  };
}

function sanitizeProfileInput(incoming, username) {
  const src = incoming && typeof incoming === "object" ? incoming : {};
  const out = {
    handle: username,
    layout: stringOr(src.layout, "scroll", 20),
    displayName: stringOr(src.displayName, username, 40),
    bio: stringOr(src.bio, "", 320),
    statusText: stringOr(src.statusText, "", 120),
    nameTooltip: stringOr(src.nameTooltip, "", 120),
    entrySymbol: stringOr(src.entrySymbol, "✦", 4),
    background: sanitizeHttpUrl(src.background || ""),
    avatar: sanitizeHttpUrl(src.avatar || ""),
    cursor: sanitizeHttpUrl(src.cursor || ""),
    location: stringOr(src.location, "", 120),
    colors: sanitizeColors(src.colors),
    ui: sanitizeUi(src.ui),
    song: sanitizeSong(src.song),
    platforms: sanitizeContactList(src.platforms),
    projects: sanitizeLinkList(src.projects),
    links: sanitizeLinkList(src.links),
    contacts: sanitizeContactList(src.contacts),
    badges: [],
    views: 0,
  };

  if (!out.projects.length && out.links.length) {
    out.projects = out.links;
  }
  out.links = out.projects;

  return out;
}

function sanitizeColors(colors) {
  const c = colors && typeof colors === "object" ? colors : {};
  return {
    accent: sanitizeHex(c.accent, "#8b5cf6"),
    text: sanitizeHex(c.text, "#f4f2f8"),
    icon: sanitizeHex(c.icon, "#f4f2f8"),
    bg: sanitizeHex(c.bg, "#08070c"),
    bgFx: sanitizeHex(c.bgFx, "#8b5cf6"),
    primary: sanitizeHex(c.primary, "#171717"),
    secondary: sanitizeHex(c.secondary, "#000000"),
    useGradient: !!c.useGradient,
  };
}

function sanitizeUi(ui) {
  const x = ui && typeof ui === "object" ? ui : {};
  const iconShape = String(x.iconShape || "").trim().toLowerCase();
  const iconHoverFx = String(x.iconHoverFx || "").trim().toLowerCase();
  return {
    opacity: numberClamp(x.opacity, 78, 0, 100),
    blur: numberClamp(x.blur, 20, 0, 40),
    bgEffect: stringOr(x.bgEffect, "none", 24),
    usernameEffect: stringOr(x.usernameEffect, "none", 24),
    discordPresence: !!x.discordPresence,
    locVisible: x.locVisible !== false,
    glowUsername: x.glowUsername !== false,
    glowSocials: x.glowSocials !== false,
    glowBadges: !!x.glowBadges,
    monoIcons: !!x.monoIcons,
    animatedTitle: !!x.animatedTitle,
    swapBoxColors: !!x.swapBoxColors,
    cardTilt: numberClamp(x.cardTilt, 10, 0, 30),
    fxDensity: numberClamp(x.fxDensity, 100, 40, 180),
    socialIconSize: numberClamp(x.socialIconSize, 23, 14, 36),
    iconGlowStrength: numberClamp(x.iconGlowStrength, 65, 0, 100),
    badgeGlowStrength: numberClamp(x.badgeGlowStrength, 60, 0, 100),
    iconShape: ["round", "circle", "square"].includes(iconShape) ? iconShape : "round",
    iconHoverFx: ["lift", "pulse", "spin", "none"].includes(iconHoverFx) ? iconHoverFx : "lift",
    statusTypewriter: !!x.statusTypewriter,
    nameNoise: !!x.nameNoise,
    cursorSparkle: x.cursorSparkle !== false,
    entryGate: x.entryGate !== false,
    volumeControl: x.volumeControl !== false,
    useDiscordAvatar: !!x.useDiscordAvatar,
    discordDecoration: !!x.discordDecoration,
  };
}

function sanitizeSong(song) {
  const s = song && typeof song === "object" ? song : {};
  return {
    title: stringOr(s.title, "", 80),
    artist: stringOr(s.artist, "", 80),
    art: sanitizeHttpUrl(s.art || ""),
    url: sanitizeHttpUrl(s.url || ""),
  };
}

function sanitizeLinkList(items) {
  if (!Array.isArray(items)) return [];
  return items.map((item) => ({
    name: stringOr(item?.name || item?.title || item?.label, "", 80),
    url: sanitizeHttpUrl(item?.url || item?.link || item?.href || ""),
  })).filter((item) => item.name || item.url).slice(0, 32);
}

function sanitizeContactList(items) {
  if (!Array.isArray(items)) return [];
  return items.map((item) => ({
    platform: stringOr(item?.platform, "custom", 40),
    handle: stringOr(item?.handle, "", 120),
    desc: stringOr(item?.desc, "", 120),
    copy: stringOr(item?.copy, "", 120),
    url: sanitizeHttpUrl(item?.url || ""),
    icon: sanitizeHttpUrl(item?.icon || ""),
  })).filter((item) => item.platform || item.url || item.copy || item.handle).slice(0, 64);
}

function defaultProfile(username) {
  return {
    handle: username,
    layout: "scroll",
    displayName: username,
    bio: "",
    statusText: "",
    nameTooltip: "",
    entrySymbol: "✦",
    background: "",
    avatar: "",
    cursor: "",
    location: "",
    colors: sanitizeColors({}),
    ui: sanitizeUi({}),
    song: sanitizeSong({}),
    platforms: [],
    projects: [],
    links: [],
    contacts: [],
    badges: [],
    views: 0,
  };
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function normalizeUsername(v) {
  return String(v || "").toLowerCase().replace(/[^a-z0-9_.]/g, "").slice(0, 20);
}

function usernameFromPathname(pathname) {
  const parts = String(pathname || "").split("/").filter(Boolean);
  if (parts.length !== 1) return "";
  const candidate = normalizeUsername(decodeURIComponent(parts[0] || ""));
  if (!isValidUsername(candidate)) return "";
  if (RESERVED_USERNAMES.has(candidate)) return "";
  return candidate;
}

function isValidUsername(v) {
  return /^[a-z0-9_.]{2,20}$/.test(v);
}

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase().slice(0, 254);
}

function isValidEmail(v) {
  return /^\S+@\S+\.\S+$/.test(v);
}

function isDisposableEmail(v) {
  const value = String(v || "").trim().toLowerCase();
  if (!value || !value.includes("@")) return false;

  const domain = value.split("@").pop() || "";
  const blockedDomains = new Set([
    "10minutemail.com",
    "mailinator.com",
    "mailinator2.com",
    "maildrop.cc",
    "tempmail.com",
    "tempmail.org",
    "temp-mail.org",
    "tempmail.plus",
    "tempmailo.com",
    "guerrillamail.com",
    "guerrillamail.biz",
    "guerrillamail.net",
    "guerrillamail.org",
    "yopmail.com",
    "yopmail.fr",
    "yopmail.net",
    "mailnesia.com",
    "mailtothis.com",
    "trashmail.com",
    "throwawaymail.com",
    "fakemail.net",
    "getairmail.com",
    "mailforspam.com",
    "mailsac.com",
    "dispostable.com",
    "mailme.lv",
    "mailinator.net",
    "sharklasers.com",
    "emailondeck.com",
    "tmails.net",
    "aghism.com",
    "mailt.net",
    "mohmal.com",
    "maildrop.xyz",
    "mailbox.institute",
    "mytrashmail.com",
    "grr.la",
    "mintemail.com",
    "fakeinbox.com",
    "emailfake.com",
    "0-mail.com",
    "anonbox.net",
    "mailcatch.com",
    "mailslurp.com",
    "inboxbear.com",
    "mailnator.com",
    "emailnator.com",
    "dropmail.me",
    "dropjar.com",
    "eml.pp.ua",
    "zmailpro.com",
    "mailpoof.com",
    "spam4.me",
    "e4ward.com",
    "spamgourmet.com",
    "10mail.org",
    "curryworld.de",
    "getnada.com",
    "nada.email",
    "reallymymail.com",
    "imailzero.com",
    "mailtempora.com",
    "mailnesia.net",
    "mailhazard.com",
    "spambox.us",
    "spammotel.com",
    "voodoo.com",
    "suremail.info",
    "mailbucket.org",
    "temp-mail.ru",
    "tempmailaddress.com",
    "mailify.cc",
    "tempr.email",
  ]);

  return blockedDomains.has(domain) || blockedDomains.has(domain.replace(/^www\./, ""));
}

function sanitizeHttpUrl(v) {
  const raw = String(v || "").trim();
  if (!raw) return "";
  if (raw.startsWith("asset:")) return raw;
  try {
    const u = new URL(raw);
    if (u.protocol === "http:" || u.protocol === "https:") {
      return u.toString();
    }
  } catch {
    return "";
  }
  return "";
}

function sanitizeHex(v, fallback) {
  const s = String(v || "").trim();
  return /^#[0-9a-fA-F]{6}$/.test(s) ? s : fallback;
}

function numberClamp(v, fallback, min, max) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.round(n)));
}

function stringOr(v, fallback, maxLen) {
  const s = String(v ?? "").trim();
  if (!s) return fallback;
  return s.slice(0, maxLen);
}

function badgeKeyFromLabel(v) {
  return String(v || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32);
}

function readCookie(raw, name) {
  if (!raw) return "";
  const pairs = raw.split(/;\s*/g);
  for (const p of pairs) {
    const i = p.indexOf("=");
    if (i < 0) continue;
    const k = p.slice(0, i);
    if (k !== name) continue;
    return decodeURIComponent(p.slice(i + 1));
  }
  return "";
}

function serializeSessionCookie(token, expiresAt, secure) {
  const parts = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Expires=${expiresAt.toUTCString()}`,
  ];
  if (secure) {
    parts.push("Secure");
  }
  return parts.join("; ");
}

function clearSessionCookie(secure) {
  const parts = [
    `${SESSION_COOKIE}=`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
  ];
  if (secure) {
    parts.push("Secure");
  }
  return parts.join("; ");
}

function urlIsSecure(url) {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}

function randomHex(bytes) {
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(v) {
  const input = typeof v === "string" ? encoder.encode(v) : v;
  const digest = await crypto.subtle.digest("SHA-256", input);
  return bytesToHex(new Uint8Array(digest));
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const baseKey = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", iterations: PBKDF2_ITERATIONS, salt },
    baseKey,
    256
  );
  const hash = new Uint8Array(bits);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${bytesToHex(salt)}$${bytesToHex(hash)}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") {
    return false;
  }

  const iterations = Number(parts[1]);
  const salt = hexToBytes(parts[2]);
  const expected = parts[3];
  if (!Number.isFinite(iterations) || !salt || !expected) {
    return false;
  }

  const baseKey = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", iterations, salt },
    baseKey,
    256
  );
  const actual = bytesToHex(new Uint8Array(bits));
  return timingSafeEqual(actual, expected);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) {
    out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return out === 0;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function buildViewerHash(request) {
  const ip = request.headers.get("cf-connecting-ip") || "0.0.0.0";
  const ua = request.headers.get("user-agent") || "unknown";
  const lang = request.headers.get("accept-language") || "unknown";
  const source = `${ip}|${ua}|${lang}`;
  return sha256Hex(source);
}
