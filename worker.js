// Portofolio Nazril — backend gratis di Cloudflare Workers (+ static assets).
// Butuh: KV binding bernama DB, dan secret/variabel ADMIN_PASSWORD (password awal).
const enc = new TextEncoder();
const J = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...h } });
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64 = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const SESSION_MS = 12 * 3600e3;
const MAX_BODY = 24 * 1024 * 1024;

async function sha(s) { return b64(await crypto.subtle.digest('SHA-256', enc.encode(s))); }
function tse(a, b) { // perbandingan waktu-konstan
  const x = enc.encode(a), y = enc.encode(b); let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] || 0) ^ (y[i] || 0);
  return d === 0;
}
async function pbkdf2(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return b64(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(salt), iterations: 100000 }, k, 256));
}
async function getAuth(env) { try { return JSON.parse(await env.DB.get('auth')) || null; } catch (e) { return null; } }
async function checkPassword(env, pw) {
  if (typeof pw !== 'string' || !pw || pw.length > 200) return false;
  const a = await getAuth(env);
  if (a && a.hash) return tse(await pbkdf2(pw, a.salt), a.hash);
  return !!env.ADMIN_PASSWORD && tse(await sha(pw), await sha(env.ADMIN_PASSWORD));
}
async function secret(env) { const a = await getAuth(env); return (env.SESSION_SECRET || '') + '|' + ((a && a.hash) || '') + '|' + (a && a.ver || 0) + '|' + (env.ADMIN_PASSWORD || ''); }
async function hmac(env, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(await secret(env)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
async function makeToken(env) { const exp = Date.now() + SESSION_MS; return exp + '.' + await hmac(env, 'adm.' + exp); }
async function isAuthed(req, env) {
  const m = (req.headers.get('cookie') || '').match(/(?:^|;\s*)nz_s=([^;]+)/); if (!m) return false;
  const [exp, sig] = m[1].split('.'); if (!exp || !sig || Number(exp) < Date.now()) return false;
  return tse(sig, await hmac(env, 'adm.' + exp));
}
const cookie = (v, maxAge) => `nz_s=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
const sameOrigin = req => { const o = req.headers.get('origin'); return !o || o === new URL(req.url).origin; };
async function readJson(req) { const t = await req.text(); if (t.length > MAX_BODY) throw new Error('big'); return JSON.parse(t); }
const ip = req => req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || 'x';
async function kvJson(env, k, d) { try { const v = await env.DB.get(k); return v ? JSON.parse(v) : d; } catch (e) { return d; } }

async function rateLimit(env, req, key, max, ttl) {
  const k = 'rl:' + key + ':' + (await sha(ip(req))).slice(0, 16), n = Number(await env.DB.get(k)) || 0;
  if (n >= max) return false; await env.DB.put(k, String(n + 1), { expirationTtl: ttl }); return true;
}
const isBot = ua => /bot|crawl|spider|slurp|preview|facebookexternalhit|headless|monitor/i.test(ua || '');
const today = () => new Date().toISOString().slice(0, 10);

async function record(env, req, type, extra = {}) {
  const ua = req.headers.get('user-agent') || '';
  if (isBot(ua)) return;
  const st = await kvJson(env, 'stats', { visit: 0, preview: 0, download: 0, link: 0, days: {} });
  st[type] = (st[type] || 0) + 1;
  const d = today(); st.days[d] = st.days[d] || { visit: 0, preview: 0, download: 0, link: 0 }; st.days[d][type] = (st.days[d][type] || 0) + 1;
  Object.keys(st.days).sort().slice(0, -90).forEach(k => delete st.days[k]);
  await env.DB.put('stats', JSON.stringify(st));
  const log = await kvJson(env, 'log', []);
  const dev = /mobile|android|iphone/i.test(ua) ? 'Mobile' : 'Desktop';
  const br = (ua.match(/(Edg|OPR|Chrome|Firefox|Safari)\//) || [])[1] || 'Lainnya';
  log.unshift({ t: new Date().toISOString(), type, c: (req.cf && req.cf.country) || req.headers.get('cf-ipcountry') || '-', dev, br: br === 'Edg' ? 'Edge' : br === 'OPR' ? 'Opera' : br, ...extra });
  await env.DB.put('log', JSON.stringify(log.slice(0, 300)));
}
const clip = (s, n) => String(s == null ? '' : s).slice(0, n).replace(/[\u0000-\u001f]/g, '');

async function api(req, env, url) {
  const p = url.pathname, m = req.method;
  if (!env.DB) return J({ error: 'kv_missing', message: 'KV binding "DB" belum dipasang di Cloudflare Pages.' }, 500);
  if (p === '/api/ping') return J({ ok: true, passwordSet: !!(env.ADMIN_PASSWORD || await getAuth(env)) });
  if (p === '/api/content' && m === 'GET') {
    const v = await env.DB.get('content');
    return new Response(JSON.stringify({ data: v ? JSON.parse(v) : null }), { headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'public, max-age=20, stale-while-revalidate=120' } });
  }
  if (p === '/api/hit' && m === 'POST') {
    let b = {}; try { b = await readJson(req); } catch (e) { }
    const type = ['visit', 'preview', 'download'].includes(b.type) ? b.type : null; if (!type) return J({ ok: false }, 400);
    if (!(await rateLimit(env, req, 'hit', 120, 3600))) return J({ ok: false }, 429);
    let ref = ''; try { ref = b.ref ? new URL(b.ref).hostname : ''; } catch (e) { }
    await record(env, req, type, { src: clip(b.src, 40), label: clip(b.label, 80), ref: clip(ref, 60) });
    return J({ ok: true });
  }
  if (p === '/api/login' && m === 'POST') {
    if (!sameOrigin(req)) return J({ error: 'origin' }, 403);
    if (!(await rateLimit(env, req, 'login', 6, 900))) return J({ error: 'rate_limited', message: 'Terlalu banyak percobaan. Coba lagi 15 menit lagi.' }, 429);
    let b = {}; try { b = await readJson(req); } catch (e) { }
    if (!(await checkPassword(env, b.password))) return J({ error: 'bad_password', message: 'Password salah.' }, 401);
    return J({ ok: true }, 200, { 'set-cookie': cookie(await makeToken(env), SESSION_MS / 1000) });
  }
  if (p === '/api/logout' && m === 'POST') return J({ ok: true }, 200, { 'set-cookie': cookie('', 0) });
  if (p === '/api/me') return J({ authed: await isAuthed(req, env) });

  // ---- khusus admin ----
  if (!(await isAuthed(req, env))) return J({ error: 'unauthorized' }, 401);
  if (m !== 'GET' && !sameOrigin(req)) return J({ error: 'origin' }, 403);
  if (p === '/api/content' && m === 'PUT') {
    let b; try { b = await readJson(req); } catch (e) { return J({ error: 'bad_json' }, 400); }
    if (!b || !b.profile || !b.experience) return J({ error: 'invalid_content' }, 400);
    await env.DB.put('content', JSON.stringify(b)); return J({ ok: true, at: new Date().toISOString() });
  }
  if (p === '/api/stats') return J({ stats: await kvJson(env, 'stats', { visit: 0, preview: 0, download: 0, link: 0, days: {} }), log: await kvJson(env, 'log', []) });
  if (p === '/api/stats/reset' && m === 'POST') { await env.DB.delete('stats'); await env.DB.delete('log'); return J({ ok: true }); }
  if (p === '/api/links' && m === 'GET') return J({ links: await kvJson(env, 'links', []) });
  if (p === '/api/links' && m === 'PUT') {
    let b; try { b = await readJson(req); } catch (e) { return J({ error: 'bad_json' }, 400); }
    const old = await kvJson(env, 'links', []), seen = new Set(), out = [];
    for (const l of (b.links || []).slice(0, 100)) {
      const slug = clip(l.slug, 40).toLowerCase().replace(/[^a-z0-9-_]/g, '-').replace(/^-+|-+$/g, ''); if (!slug || seen.has(slug)) continue; seen.add(slug);
      const prev = old.find(o => o.slug === slug);
      out.push({ slug, label: clip(l.label, 80), hits: prev ? prev.hits || 0 : 0 });
    }
    await env.DB.put('links', JSON.stringify(out)); return J({ links: out });
  }
  if (p === '/api/password' && m === 'POST') {
    let b = {}; try { b = await readJson(req); } catch (e) { }
    if (!(await rateLimit(env, req, 'pw', 8, 900))) return J({ error: 'rate_limited' }, 429);
    if (!(await checkPassword(env, b.current))) return J({ error: 'bad_password', message: 'Password saat ini salah.' }, 401);
    if (typeof b.next !== 'string' || b.next.length < 10 || b.next.length > 200) return J({ error: 'weak', message: 'Password baru minimal 10 karakter.' }, 400);
    const salt = b64(crypto.getRandomValues(new Uint8Array(16))), a = await getAuth(env);
    await env.DB.put('auth', JSON.stringify({ salt, hash: await pbkdf2(b.next, salt), ver: ((a && a.ver) || 0) + 1 }));
    return J({ ok: true }, 200, { 'set-cookie': cookie(await makeToken(env), SESSION_MS / 1000) });
  }
  if (p === '/api/logout-all' && m === 'POST') {
    const a = (await getAuth(env)) || {}; await env.DB.put('auth', JSON.stringify({ ...a, ver: (a.ver || 0) + 1 }));
    return J({ ok: true }, 200, { 'set-cookie': cookie('', 0) });
  }
  return J({ error: 'not_found' }, 404);
}

async function go(req, env, url) {
  const slug = decodeURIComponent(url.pathname.slice(4)).toLowerCase();
  if (env.DB) {
    const links = await kvJson(env, 'links', []), l = links.find(x => x.slug === slug);
    if (l && !isBot(req.headers.get('user-agent'))) {
      l.hits = (l.hits || 0) + 1; await env.DB.put('links', JSON.stringify(links));
      await record(env, req, 'link', { src: slug, label: l.label });
    }
    if (l) return new Response(null, { status: 302, headers: { location: '/?src=' + encodeURIComponent(slug), 'cache-control': 'no-store' } });
  }
  return new Response(null, { status: 302, headers: { location: '/' } });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    try {
      if (url.pathname.startsWith('/api/')) return await api(req, env, url);
      if (url.pathname.startsWith('/go/')) return await go(req, env, url);
    } catch (e) { return J({ error: 'server', message: String(e && e.message || e) }, 500); }
    if (/^\/(worker\.js|wrangler\.jsonc|PANDUAN\.md)$/.test(url.pathname)) return new Response('Not found', { status: 404 });
    const r = await env.ASSETS.fetch(req), h = new Headers(r.headers);
    h.set('x-content-type-options', 'nosniff'); h.set('referrer-policy', 'strict-origin-when-cross-origin'); h.set('x-frame-options', 'SAMEORIGIN');
    const isHtml = (h.get('content-type') || '').includes('text/html');
    if (isHtml) h.set('cache-control', 'no-cache');
    let res = new Response(r.body, { status: r.status, statusText: r.statusText, headers: h });
    // Sisipkan konten terbaru langsung ke HTML supaya pengunjung tidak melihat data lama (tanpa kedipan).
    if (isHtml && env.DB && typeof HTMLRewriter !== 'undefined') {
      try {
        const raw = await env.DB.get('content');
        if (raw) res = new HTMLRewriter().on('script#site-data', { element(el) { el.setInnerContent(raw.replace(/</g, '\\u003c'), { html: true }); el.setAttribute('data-live', '1'); } }).transform(res);
      } catch (e) { }
    }
    return res;
  },
};
