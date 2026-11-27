// ═══════════════════════════════════════════════════════════════════
//  🌙 MoonX AI — Cloudflare Worker (ملف واحد كامل)
//  ضعه في: Workers → foxtwin → Edit Code → احذف القديم والصق هذا
// ═══════════════════════════════════════════════════════════════════

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Session-Token',
    };

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    function json(data, status = 200) {
      return new Response(JSON.stringify(data), {
        status, headers: { 'Content-Type': 'application/json', ...cors },
      });
    }

    try {
      if (path === '/' || path === '') return new Response(HTML_PAGE, { headers: { 'Content-Type': 'text/html;charset=UTF-8', ...cors } });
      if (path.startsWith('/api/auth'))    return await handleAuth(request, env, json, path);
      if (path.startsWith('/api/chat'))    return await handleChat(request, env, json);
      if (path.startsWith('/api/storage')) return await handleStorage(request, env, json, path);
      if (path.startsWith('/api/payment')) return await handlePayment(request, env, json, path);
      if (path.startsWith('/api/agent'))   return await handleAgent(request, env, json);
      if (path === '/health') return json({ status: 'ok', name: 'MoonX', version: '1.0.0' });
      return json({ error: 'Not found' }, 404);
    } catch (err) {
      console.error('MoonX error:', err);
      return json({ error: 'Internal server error', detail: err.message }, 500);
    }
  },
};

// ═══════════════════════════════════════════════════════════════════
//  AUTH
// ═══════════════════════════════════════════════════════════════════

async function handleAuth(request, env, json, path) {
  const sub = path.replace('/api/auth/', '');

  if (sub === 'register' && request.method === 'POST') {
    const { email, password, name } = await request.json();
    if (!email || !password || !name) return json({ error: 'Missing fields' }, 400);
    const existing = await env.MOONX_KV.get(`user:${email}`);
    if (existing) return json({ error: 'Email already registered' }, 409);
    const hash = await hashPassword(password);
    const userId = crypto.randomUUID();
    const user = {
      id: userId, email, name, passwordHash: hash,
      plan: 'free', planExpiry: null,
      freeTrialStart: Date.now(), freeTrialDays: 90,
      createdAt: Date.now(), storageUsed: 0,
      storageLimit: 20 * 1024 * 1024 * 1024,
    };
    await env.MOONX_KV.put(`user:${email}`, JSON.stringify(user));
    await env.MOONX_KV.put(`userid:${userId}`, email);
    const token = await createToken(userId, env);
    return json({ token, user: safeUser(user) });
  }

  if (sub === 'login' && request.method === 'POST') {
    const { email, password } = await request.json();
    if (!email || !password) return json({ error: 'Missing fields' }, 400);
    const raw = await env.MOONX_KV.get(`user:${email}`);
    if (!raw) return json({ error: 'Invalid credentials' }, 401);
    const user = JSON.parse(raw);
    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) return json({ error: 'Invalid credentials' }, 401);
    const token = await createToken(user.id, env);
    return json({ token, user: safeUser(user) });
  }

  if (sub === 'me' && request.method === 'GET') {
    const user = await requireAuth(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    return json({ user: safeUser(user) });
  }

  if (sub === 'logout' && request.method === 'POST') {
    const token = getToken(request);
    if (token) await env.MOONX_KV.delete(`session:${token}`);
    return json({ ok: true });
  }

  return json({ error: 'Auth route not found' }, 404);
}

async function requireAuth(request, env) {
  const token = getToken(request);
  if (!token) return null;
  const sessionRaw = await env.MOONX_KV.get(`session:${token}`);
  if (!sessionRaw) return null;
  const session = JSON.parse(sessionRaw);
  if (session.expiresAt < Date.now()) { await env.MOONX_KV.delete(`session:${token}`); return null; }
  const email = await env.MOONX_KV.get(`userid:${session.userId}`);
  if (!email) return null;
  const userRaw = await env.MOONX_KV.get(`user:${email}`);
  if (!userRaw) return null;
  return JSON.parse(userRaw);
}

function getToken(request) {
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7);
  return request.headers.get('X-Session-Token') || null;
}

async function createToken(userId, env) {
  const token = crypto.randomUUID() + '-' + crypto.randomUUID();
  await env.MOONX_KV.put(`session:${token}`, JSON.stringify({
    userId, createdAt: Date.now(), expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
  }), { expirationTtl: 30 * 24 * 60 * 60 });
  return token;
}

async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return btoa(String.fromCharCode(...salt)) + ':' + btoa(String.fromCharCode(...new Uint8Array(bits)));
}

async function verifyPassword(password, stored) {
  try {
    const [saltB64, hashB64] = stored.split(':');
    const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
    return btoa(String.fromCharCode(...new Uint8Array(bits))) === hashB64;
  } catch { return false; }
}

function safeUser(u) {
  const { passwordHash, ...safe } = u;
  const now = Date.now();
  safe.isFreeTrial = u.plan === 'free' && (now - u.freeTrialStart) < u.freeTrialDays * 86400000;
  safe.freeTrialDaysLeft = safe.isFreeTrial ? Math.ceil(u.freeTrialDays - (now - u.freeTrialStart) / 86400000) : 0;
  safe.isPaid = u.plan !== 'free' && u.planExpiry && u.planExpiry > now;
  return safe;
}

// ═══════════════════════════════════════════════════════════════════
//  CHAT / AI
// ═══════════════════════════════════════════════════════════════════

async function handleChat(request, env, json) {
  if (request.method !== 'POST') return json({ error: 'POST only' }, 405);
  const user = await requireAuth(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401);

  const now = Date.now();
  const inTrial = user.plan === 'free' && (now - user.freeTrialStart) < user.freeTrialDays * 86400000;
  const isPaid = user.planExpiry && user.planExpiry > now;
  if (!inTrial && !isPaid) return json({ error: 'Subscription required. Subscribe for $20/year.', code: 'SUBSCRIPTION_REQUIRED' }, 403);

  const body = await request.json();
  const { message, history = [], mode = 'chat', sources = [] } = body;
  if (!message) return json({ error: 'Message required' }, 400);

  let context = '';
  if (sources.includes('wikipedia') || mode === 'search') {
    const wiki = await searchWikipedia(message);
    if (wiki) context += `\n\n[Wikipedia]\n${wiki}`;
  }
  if (sources.includes('github') || mode === 'build') {
    const gh = await searchGitHub(message, env.GITHUB_TOKEN);
    if (gh) context += `\n\n[GitHub]\n${gh}`;
  }

  const systemPrompts = {
    chat: `أنت MoonX، ذكاء اصطناعي متطور يفكر كإنسان. تتحدث بشكل طبيعي وذكي وصادق.${context ? `\n\nمعلومات:\n${context}` : ''}`,
    build: `أنت MoonX، متخصص في بناء الكود. تكتب كوداً نظيفاً وتفحص الأخطاء تلقائياً.${context ? `\n\nمراجع:\n${context}` : ''}`,
    search: `أنت MoonX، محرك بحث ذكي. تجمع المعلومات وتقدمها بشكل منظم.${context ? `\n\nنتائج:\n${context}` : ''}`,
    analyze: `أنت MoonX، محلل بيانات خبير. تحلل بعمق وتعطي تقارير مفصلة.${context ? `\n\nسياق:\n${context}` : ''}`,
  };

  const apiKey = env.ANTHROPIC_API_KEY;
  const messages = [...history.slice(-10), { role: 'user', content: message }];

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({
      model: user.plan === 'moonhigh' ? 'claude-opus-4-5' : 'claude-sonnet-4-5',
      max_tokens: 4096,
      system: systemPrompts[mode] || systemPrompts.chat,
      messages,
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    return json({ error: 'AI service error', detail: err }, 502);
  }

  const data = await response.json();
  const reply = data.content?.[0]?.text || '';
  const agentCheck = await runAgentCheck(reply, mode);

  const convId = body.conversationId || crypto.randomUUID();
  const convKey = `conv:${user.id}:${convId}`;
  const existing = await env.MOONX_KV.get(convKey);
  const conv = existing ? JSON.parse(existing) : { id: convId, messages: [], createdAt: Date.now() };
  conv.messages.push({ role: 'user', content: message, ts: Date.now() });
  conv.messages.push({ role: 'assistant', content: reply, ts: Date.now() });
  conv.updatedAt = Date.now();
  await env.MOONX_KV.put(convKey, JSON.stringify(conv));

  return json({ reply, conversationId: convId, agentReport: agentCheck, model: user.plan === 'moonhigh' ? 'moonhigh' : 'normal', sourcesUsed: sources });
}

async function searchWikipedia(query) {
  try {
    const r = await fetch(`https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(query)}`, { headers: { 'User-Agent': 'MoonX/1.0' } });
    if (!r.ok) {
      const s = await fetch(`https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(query)}&format=json&srlimit=3`, { headers: { 'User-Agent': 'MoonX/1.0' } });
      if (!s.ok) return null;
      const sd = await s.json();
      return (sd?.query?.search || []).map(r => `• ${r.title}: ${r.snippet.replace(/<[^>]+>/g, '')}`).join('\n');
    }
    const d = await r.json();
    return d.extract ? `${d.title}: ${d.extract.slice(0, 500)}` : null;
  } catch { return null; }
}

async function searchGitHub(query, token) {
  try {
    const headers = { 'User-Agent': 'MoonX/1.0', 'Accept': 'application/vnd.github.v3+json' };
    if (token) headers['Authorization'] = `token ${token}`;
    const r = await fetch(`https://api.github.com/search/repositories?q=${encodeURIComponent(query)}&sort=stars&per_page=3`, { headers });
    if (!r.ok) return null;
    const d = await r.json();
    return (d.items || []).map(repo => `• ${repo.full_name} (★${repo.stargazers_count}): ${repo.description || ''}\n  ${repo.html_url}`).join('\n');
  } catch { return null; }
}

async function runAgentCheck(text, mode) {
  const issues = [];
  if (mode === 'build' || text.includes('```')) {
    const codeBlocks = text.match(/```[\s\S]*?```/g) || [];
    for (const block of codeBlocks) {
      const code = block.replace(/```\w*\n?/, '').replace(/```$/, '');
      if ((code.match(/\(/g)||[]).length !== (code.match(/\)/g)||[]).length) issues.push({ type: 'error', msg: 'Mismatched parentheses' });
      if ((code.match(/\{/g)||[]).length !== (code.match(/\}/g)||[]).length) issues.push({ type: 'error', msg: 'Mismatched curly braces' });
      if (code.includes('console.log')) issues.push({ type: 'info', msg: 'console.log found — remove before production' });
    }
  }
  if (text.length < 10) issues.push({ type: 'warning', msg: 'Response seems too short' });
  return { passed: issues.filter(i => i.type === 'error').length === 0, issues, checkedAt: new Date().toISOString(), charCount: text.length };
}

// ═══════════════════════════════════════════════════════════════════
//  STORAGE — 20GB R2
// ═══════════════════════════════════════════════════════════════════

const GB20 = 20 * 1024 * 1024 * 1024;

async function handleStorage(request, env, json, path) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  const sub = path.replace('/api/storage', '');

  if (sub === '/upload' && request.method === 'POST') {
    const formData = await request.formData();
    const file = formData.get('file');
    if (!file) return json({ error: 'No file provided' }, 400);
    const userRaw = await env.MOONX_KV.get(`user:${user.email}`);
    const userData = JSON.parse(userRaw);
    const fileSize = file.size || 0;
    if ((userData.storageUsed || 0) + fileSize > GB20) return json({ error: 'Storage limit exceeded (20GB)', code: 'STORAGE_FULL' }, 413);
    const fileId = crypto.randomUUID();
    const ext = file.name.split('.').pop() || 'bin';
    const key = `${user.id}/${fileId}.${ext}`;
    await env.MOONX_BUCKET.put(key, await file.arrayBuffer(), {
      httpMetadata: { contentType: file.type || 'application/octet-stream' },
      customMetadata: { originalName: file.name, uploadedBy: user.id, uploadedAt: Date.now().toString(), size: fileSize.toString() },
    });
    userData.storageUsed = (userData.storageUsed || 0) + fileSize;
    await env.MOONX_KV.put(`user:${user.email}`, JSON.stringify(userData));
    await env.MOONX_KV.put(`file:${user.id}:${fileId}`, JSON.stringify({ id: fileId, key, name: file.name, type: file.type, size: fileSize, uploadedAt: Date.now(), userId: user.id }));
    return json({ fileId, key, name: file.name, size: fileSize, url: `/api/storage/download/${fileId}`, storageUsed: userData.storageUsed, storageLimit: GB20 });
  }

  if (sub.startsWith('/download/') && request.method === 'GET') {
    const fileId = sub.replace('/download/', '');
    const metaRaw = await env.MOONX_KV.get(`file:${user.id}:${fileId}`);
    if (!metaRaw) return json({ error: 'File not found' }, 404);
    const meta = JSON.parse(metaRaw);
    const obj = await env.MOONX_BUCKET.get(meta.key);
    if (!obj) return json({ error: 'File not found in storage' }, 404);
    return new Response(obj.body, { headers: { 'Content-Type': meta.type || 'application/octet-stream', 'Content-Disposition': `attachment; filename="${meta.name}"`, 'Content-Length': meta.size.toString() } });
  }

  if (sub === '/list' && request.method === 'GET') {
    const list = await env.MOONX_KV.list({ prefix: `file:${user.id}:` });
    const files = await Promise.all(list.keys.map(async k => { const raw = await env.MOONX_KV.get(k.name); return raw ? JSON.parse(raw) : null; }));
    const userRaw = await env.MOONX_KV.get(`user:${user.email}`);
    const userData = JSON.parse(userRaw);
    return json({ files: files.filter(Boolean).sort((a, b) => b.uploadedAt - a.uploadedAt), storageUsed: userData.storageUsed || 0, storageLimit: GB20, storageUsedGB: ((userData.storageUsed || 0) / (1024 ** 3)).toFixed(2) });
  }

  if (sub.startsWith('/delete/') && request.method === 'DELETE') {
    const fileId = sub.replace('/delete/', '');
    const metaRaw = await env.MOONX_KV.get(`file:${user.id}:${fileId}`);
    if (!metaRaw) return json({ error: 'File not found' }, 404);
    const meta = JSON.parse(metaRaw);
    await env.MOONX_BUCKET.delete(meta.key);
    await env.MOONX_KV.delete(`file:${user.id}:${fileId}`);
    const userRaw = await env.MOONX_KV.get(`user:${user.email}`);
    const userData = JSON.parse(userRaw);
    userData.storageUsed = Math.max(0, (userData.storageUsed || 0) - meta.size);
    await env.MOONX_KV.put(`user:${user.email}`, JSON.stringify(userData));
    return json({ ok: true, freedBytes: meta.size });
  }

  return json({ error: 'Storage route not found' }, 404);
}

// ═══════════════════════════════════════════════════════════════════
//  PAYMENT — STRIPE $20/YEAR
// ═══════════════════════════════════════════════════════════════════

async function handlePayment(request, env, json, path) {
  const sub = path.replace('/api/payment', '');

  if (sub === '/create-checkout' && request.method === 'POST') {
    const user = await requireAuth(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    const body = await request.json();
    const plan = body.plan || 'normal';
    const priceId = plan === 'moonhigh' ? env.STRIPE_PRICE_MOONHIGH : env.STRIPE_PRICE_NORMAL;
    const origin = request.headers.get('Origin') || 'https://foxtwin.workers.dev';
    const params = new URLSearchParams({
      'mode': 'subscription', 'payment_method_types[]': 'card',
      'line_items[0][price]': priceId || 'price_placeholder', 'line_items[0][quantity]': '1',
      'success_url': `${origin}/?payment=success&plan=${plan}`,
      'cancel_url': `${origin}/?payment=cancelled`,
      'metadata[userId]': user.id, 'metadata[plan]': plan, 'customer_email': user.email,
    });
    const stripeRes = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    if (!stripeRes.ok) return json({ error: 'Payment initialization failed', detail: await stripeRes.text() }, 502);
    const session = await stripeRes.json();
    return json({ checkoutUrl: session.url, sessionId: session.id });
  }

  if (sub === '/webhook' && request.method === 'POST') {
    const rawBody = await request.text();
    const signature = request.headers.get('stripe-signature');
    let event;
    try { event = await verifyStripeWebhook(rawBody, signature, env.STRIPE_WEBHOOK_SECRET); }
    catch (err) { return json({ error: 'Invalid signature' }, 400); }
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const userId = session.metadata?.userId;
      const plan = session.metadata?.plan || 'normal';
      if (userId) {
        const email = await env.MOONX_KV.get(`userid:${userId}`);
        if (email) {
          const userRaw = await env.MOONX_KV.get(`user:${email}`);
          if (userRaw) {
            const user = JSON.parse(userRaw);
            user.plan = plan;
            user.planExpiry = Date.now() + 365 * 24 * 60 * 60 * 1000;
            user.stripeCustomerId = session.customer;
            user.stripeSubscriptionId = session.subscription;
            await env.MOONX_KV.put(`user:${email}`, JSON.stringify(user));
          }
        }
      }
    }
    return json({ received: true });
  }

  if (sub === '/status' && request.method === 'GET') {
    const user = await requireAuth(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    const now = Date.now();
    return json({
      plan: user.plan,
      isPaid: user.planExpiry && user.planExpiry > now,
      isFreeTrial: user.plan === 'free' && (now - user.freeTrialStart) < user.freeTrialDays * 86400000,
      freeTrialDaysLeft: Math.max(0, Math.ceil(user.freeTrialDays - (now - user.freeTrialStart) / 86400000)),
      planExpiry: user.planExpiry ? new Date(user.planExpiry).toISOString() : null,
      price: '$20/year',
    });
  }

  return json({ error: 'Payment route not found' }, 404);
}

async function verifyStripeWebhook(payload, signature, secret) {
  if (!signature || !secret) return JSON.parse(payload);
  const parts = signature.split(',').reduce((acc, p) => { const [k, v] = p.split('='); acc[k] = v; return acc; }, {});
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, enc.encode(`${parts.t}.${payload}`));
  const computed = Array.from(new Uint8Array(mac)).map(b => b.toString(16).padStart(2, '0')).join('');
  if (computed !== parts.v1) throw new Error('Signature mismatch');
  if (Math.abs(Date.now() / 1000 - parseInt(parts.t)) > 300) throw new Error('Timestamp too old');
  return JSON.parse(payload);
}

// ═══════════════════════════════════════════════════════════════════
//  AGENT — Error Checker + Bot
// ═══════════════════════════════════════════════════════════════════

async function handleAgent(request, env, json) {
  if (request.method !== 'POST') return json({ error: 'POST only' }, 405);
  const user = await requireAuth(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  const { content, type = 'auto', fix = true } = await request.json();
  if (!content) return json({ error: 'Content required' }, 400);

  const detectedType = type === 'auto' ? detectType(content) : type;
  const issues = [];
  let fixedContent = content;

  // Char-by-char scan
  const lines = content.split('\n');
  lines.forEach((line, li) => {
    for (let i = 0; i < line.length; i++) {
      const c = line.charCodeAt(i);
      if ([0x200B, 0x200C, 0x200D, 0xFEFF].includes(c)) issues.push({ severity: 'error', type: 'invisible-char', line: li + 1, col: i + 1, msg: `حرف غير مرئي في السطر ${li + 1}، عمود ${i + 1}`, autoFixable: true });
    }
    if (line !== line.trimEnd()) issues.push({ severity: 'info', type: 'trailing-whitespace', line: li + 1, msg: `مسافة زائدة في نهاية السطر ${li + 1}`, autoFixable: true });
    if (line.length > 200) issues.push({ severity: 'warning', type: 'long-line', line: li + 1, msg: `السطر ${li + 1} طويل جداً (${line.length} حرف)`, autoFixable: false });
  });

  if (detectedType === 'javascript' || detectedType === 'code') {
    const pairs = [['(', ')'], ['[', ']'], ['{', '}']];
    for (const [o, c] of pairs) {
      const opens = (content.match(new RegExp(`\\${o}`, 'g')) || []).length;
      const closes = (content.match(new RegExp(`\\${c}`, 'g')) || []).length;
      if (opens !== closes) issues.push({ severity: 'critical', type: 'bracket-mismatch', msg: `أقواس غير متوازنة ${o}${c}: ${opens} فتح مقابل ${closes} إغلاق`, autoFixable: false });
    }
    if (/eval\(/.test(content)) issues.push({ severity: 'critical', type: 'security', msg: 'eval() خطر أمني — تجنبه', autoFixable: false });
    if (/var\s+/.test(content)) issues.push({ severity: 'info', type: 'modern-js', msg: 'استخدم const/let بدل var', autoFixable: true });
    if (/console\.log/.test(content)) issues.push({ severity: 'info', type: 'debug', msg: 'console.log موجود — احذفه قبل النشر', autoFixable: false });
    if (fix) fixedContent = content.replace(/\u200B|\u200C|\u200D|\uFEFF/g, '').replace(/\bvar\b/g, 'const').replace(/[ \t]+$/gm, '');
  }

  if (detectedType === 'html') {
    if (!content.includes('<!DOCTYPE')) issues.push({ severity: 'warning', msg: 'DOCTYPE مفقود', autoFixable: true });
    if (!content.includes('<title>')) issues.push({ severity: 'warning', msg: 'وسم title مفقود', autoFixable: false });
    if (!content.includes('charset')) issues.push({ severity: 'warning', msg: 'charset مفقود', autoFixable: true });
  }

  if (detectedType === 'json') {
    try { JSON.parse(content); }
    catch (e) { issues.push({ severity: 'critical', type: 'json-syntax', msg: `JSON غير صحيح: ${e.message}`, autoFixable: false }); }
  }

  const passed = issues.filter(i => i.severity === 'critical' || i.severity === 'error').length === 0;
  let botSuggestion = null;

  if (!passed && env.ANTHROPIC_API_KEY) {
    const errorList = issues.filter(i => i.severity === 'critical' || i.severity === 'error').map(i => `- ${i.msg}`).join('\n');
    try {
      const r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: 'claude-sonnet-4-5', max_tokens: 512, messages: [{ role: 'user', content: `أنت Bot مساعد في MoonX. الأخطاء:\n${errorList}\n\nالكود:\n\`\`\`\n${content.slice(0, 800)}\n\`\`\`\n\nكيف نصلح هذه الأخطاء؟` }] }),
      });
      if (r.ok) { const d = await r.json(); botSuggestion = d.content?.[0]?.text || null; }
    } catch {}
  }

  return json({ passed, contentType: detectedType, originalLength: content.length, fixedContent: fix ? fixedContent : null, wasFixed: fixedContent !== content, summary: { total: issues.length, critical: issues.filter(i => i.severity === 'critical').length, errors: issues.filter(i => i.severity === 'error').length, warnings: issues.filter(i => i.severity === 'warning').length, info: issues.filter(i => i.severity === 'info').length }, issues, botSuggestion, checkedAt: new Date().toISOString() });
}

function detectType(content) {
  const t = content.trim();
  if (t.startsWith('{') || t.startsWith('[')) return 'json';
  if (t.startsWith('<') && t.includes('>')) return 'html';
  if (content.includes('function ') || content.includes('=>') || content.includes('const ') || content.includes('import ')) return 'javascript';
  return 'text';
}

// ═══════════════════════════════════════════════════════════════════
//  HTML UI — الواجهة الكاملة
// ═══════════════════════════════════════════════════════════════════

const HTML_PAGE = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MoonX — ذكاء اصطناعي متطور</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--black:#0a0a0a;--white:#f5f5f0;--g1:#1a1a1a;--g2:#2a2a2a;--g3:#3a3a3a;--g4:#888;--g5:#bbb;--border:#2a2a2a;--font:'IBM Plex Sans Arabic',sans-serif;--mono:'JetBrains Mono',monospace;}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;background:var(--black);color:var(--white);font-family:var(--font);}
body{display:flex;flex-direction:column;}
::-webkit-scrollbar{width:4px;}::-webkit-scrollbar-track{background:var(--black);}::-webkit-scrollbar-thumb{background:var(--g3);border-radius:4px;}

/* AUTH */
#auth-screen{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px;background:radial-gradient(ellipse at 50% 0%,#1a1a1a 0%,#0a0a0a 70%);}
.auth-card{width:100%;max-width:420px;background:var(--g1);border:1px solid var(--border);border-radius:20px;padding:48px 40px;}
.auth-moon{text-align:center;margin-bottom:28px;}
.auth-logo-name{font-size:26px;font-weight:700;letter-spacing:-.5px;margin-top:12px;}
.auth-logo-name span{color:var(--g4);font-weight:300;font-size:13px;display:block;margin-top:3px;}
.auth-tabs{display:flex;gap:4px;background:var(--black);border-radius:10px;padding:4px;margin-bottom:24px;}
.auth-tab{flex:1;padding:9px;border:none;background:transparent;color:var(--g4);font-family:var(--font);font-size:14px;border-radius:7px;cursor:pointer;transition:all .2s;}
.auth-tab.active{background:var(--g2);color:var(--white);}
.form-group{margin-bottom:14px;}
.form-group label{display:block;font-size:12px;color:var(--g5);margin-bottom:5px;}
.form-group input{width:100%;padding:11px 14px;background:var(--black);border:1px solid var(--border);border-radius:9px;color:var(--white);font-family:var(--font);font-size:14px;outline:none;transition:border-color .2s;}
.form-group input:focus{border-color:var(--g4);}
.btn-primary{width:100%;padding:13px;background:var(--white);color:var(--black);border:none;border-radius:9px;font-family:var(--font);font-size:14px;font-weight:600;cursor:pointer;transition:opacity .2s;margin-top:4px;}
.btn-primary:hover{opacity:.9;}
.btn-primary:disabled{opacity:.5;cursor:not-allowed;}
.auth-err{background:rgba(255,80,80,.1);border:1px solid rgba(255,80,80,.3);color:#ff8080;padding:9px 13px;border-radius:8px;font-size:13px;margin-bottom:14px;display:none;}
.plan-badges{display:flex;gap:8px;margin-bottom:18px;}
.plan-badge{flex:1;padding:10px 8px;border:1px solid var(--border);border-radius:10px;text-align:center;cursor:pointer;transition:all .2s;}
.plan-badge.sel{border-color:var(--white);background:var(--g2);}
.plan-badge h4{font-size:13px;font-weight:600;}
.plan-badge p{font-size:11px;color:var(--g4);margin-top:3px;}
.plan-badge .free{color:#7fff7f;}

/* APP */
#app{display:none;height:100vh;flex-direction:column;}
.topbar{display:flex;align-items:center;justify-content:space-between;padding:0 20px;height:54px;border-bottom:1px solid var(--border);background:var(--black);flex-shrink:0;gap:12px;}
.topbar-logo{display:flex;align-items:center;gap:10px;}
.topbar-logo span{font-size:17px;font-weight:700;}
.topbar-nav{display:flex;gap:4px;}
.nav-btn{padding:7px 13px;border:none;background:transparent;color:var(--g4);font-family:var(--font);font-size:13px;border-radius:8px;cursor:pointer;transition:all .2s;}
.nav-btn:hover,.nav-btn.active{background:var(--g2);color:var(--white);}
.topbar-right{display:flex;align-items:center;gap:10px;}
.user-pill{display:flex;align-items:center;gap:8px;padding:5px 12px;background:var(--g1);border:1px solid var(--border);border-radius:20px;font-size:13px;}
.plan-tag{font-size:10px;padding:2px 7px;border-radius:10px;background:var(--g2);color:var(--g5);}
.plan-tag.paid{background:rgba(255,255,255,.1);color:var(--white);}
.logout-btn{padding:6px 13px;border:1px solid var(--border);background:transparent;color:var(--g4);font-family:var(--font);font-size:13px;border-radius:8px;cursor:pointer;transition:all .2s;}
.logout-btn:hover{border-color:var(--g4);color:var(--white);}
.main-layout{display:flex;flex:1;overflow:hidden;}
.sidebar{width:210px;border-left:1px solid var(--border);background:var(--g1);display:flex;flex-direction:column;flex-shrink:0;overflow-y:auto;}
.sidebar-section{padding:14px 10px 6px;}
.sidebar-label{font-size:11px;color:var(--g4);text-transform:uppercase;letter-spacing:.7px;padding:0 4px 7px;}
.sidebar-btn{width:100%;text-align:right;padding:8px 10px;border:none;background:transparent;color:var(--g5);font-family:var(--font);font-size:13px;border-radius:7px;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:7px;}
.sidebar-btn:hover,.sidebar-btn.active{background:var(--g2);color:var(--white);}
.new-chat-btn{margin:10px;padding:9px;border:1px dashed var(--border);background:transparent;color:var(--g4);font-family:var(--font);font-size:13px;border-radius:9px;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:6px;}
.new-chat-btn:hover{border-color:var(--g4);color:var(--white);}
.content{flex:1;display:flex;flex-direction:column;overflow:hidden;}
#chat-view{display:flex;flex-direction:column;height:100%;}
.chat-messages{flex:1;overflow-y:auto;padding:24px 28px;display:flex;flex-direction:column;gap:18px;}
.chat-welcome{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;text-align:center;gap:14px;}
.chat-welcome h2{font-size:21px;font-weight:500;color:var(--g5);}
.chat-welcome p{font-size:14px;color:var(--g4);max-width:300px;line-height:1.6;}
.quick-actions{display:flex;gap:7px;flex-wrap:wrap;justify-content:center;margin-top:6px;}
.quick-btn{padding:7px 14px;border:1px solid var(--border);background:transparent;color:var(--g5);font-family:var(--font);font-size:12px;border-radius:18px;cursor:pointer;transition:all .2s;}
.quick-btn:hover{border-color:var(--g4);color:var(--white);}
.msg{display:flex;gap:10px;max-width:760px;}
.msg.user{flex-direction:row-reverse;align-self:flex-end;}
.msg.assistant{align-self:flex-start;}
.msg-avatar{width:30px;height:30px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:14px;background:var(--g2);border:1px solid var(--border);}
.msg.assistant .msg-avatar{background:var(--white);color:var(--black);}
.msg-bubble{padding:11px 15px;border-radius:13px;font-size:14px;line-height:1.65;max-width:580px;}
.msg.user .msg-bubble{background:var(--g2);border:1px solid var(--border);border-top-left-radius:3px;}
.msg.assistant .msg-bubble{background:var(--g1);border:1px solid var(--border);border-top-right-radius:3px;}
.msg-bubble pre{background:var(--black);padding:11px;border-radius:7px;overflow-x:auto;margin:9px 0;}
.msg-bubble code{font-family:var(--mono);font-size:13px;}
.agent-report{margin-top:9px;padding:9px 11px;background:rgba(0,0,0,.3);border-radius:7px;border:1px solid var(--border);font-size:12px;}
.agent-report .ok{color:#7fff7f;}.agent-report .fail{color:#ff8080;}
.agent-issue{display:flex;gap:5px;align-items:flex-start;padding:2px 0;}
.sev-critical{color:#ff4040;}.sev-error{color:#ff8040;}.sev-warning{color:#ffcc40;}.sev-info{color:#80ccff;}
.mode-bar{display:flex;gap:4px;padding:9px 28px 0;border-top:1px solid var(--border);flex-shrink:0;}
.mode-pill{padding:5px 13px;border:1px solid var(--border);border-radius:18px;background:transparent;color:var(--g4);font-family:var(--font);font-size:12px;cursor:pointer;transition:all .2s;}
.mode-pill.active{border-color:var(--white);background:var(--g2);color:var(--white);}
.sources-bar{display:flex;gap:4px;padding:7px 28px 0;}
.src-pill{padding:4px 10px;border:1px solid transparent;border-radius:18px;background:var(--g2);color:var(--g4);font-family:var(--font);font-size:11px;cursor:pointer;transition:all .2s;}
.src-pill.active{border-color:var(--g4);color:var(--white);}
.chat-input-wrap{padding:14px 28px 22px;flex-shrink:0;border-top:1px solid var(--border);}
.chat-input-box{display:flex;gap:9px;align-items:flex-end;background:var(--g1);border:1px solid var(--border);border-radius:13px;padding:11px 13px;transition:border-color .2s;}
.chat-input-box:focus-within{border-color:var(--g4);}
.chat-input-box textarea{flex:1;background:transparent;border:none;outline:none;color:var(--white);font-family:var(--font);font-size:14px;resize:none;min-height:22px;max-height:110px;line-height:1.5;}
.chat-input-box textarea::placeholder{color:var(--g4);}
.send-btn{width:34px;height:34px;border-radius:9px;border:none;background:var(--white);color:var(--black);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:15px;flex-shrink:0;transition:opacity .2s;}
.send-btn:hover{opacity:.85;}.send-btn:disabled{opacity:.4;cursor:not-allowed;}
.typing-indicator{display:flex;gap:4px;align-items:center;padding:3px 0;}
.typing-dot{width:5px;height:5px;background:var(--g4);border-radius:50%;animation:bounce 1.2s infinite;}
.typing-dot:nth-child(2){animation-delay:.2s;}.typing-dot:nth-child(3){animation-delay:.4s;}
@keyframes bounce{0%,60%,100%{transform:translateY(0);}30%{transform:translateY(-5px);}}

/* STORAGE */
#storage-view{padding:28px;overflow-y:auto;display:none;}
.storage-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;}
.storage-header h2{font-size:18px;font-weight:600;}
.quota-bar-wrap{background:var(--g2);border-radius:4px;height:5px;margin-top:7px;}
.quota-bar{background:var(--white);height:5px;border-radius:4px;transition:width .4s;}
.quota-text{font-size:12px;color:var(--g4);margin-top:5px;}
.upload-zone{border:2px dashed var(--border);border-radius:13px;padding:36px;text-align:center;cursor:pointer;transition:all .2s;margin-bottom:20px;}
.upload-zone:hover,.upload-zone.drag{border-color:var(--g4);background:var(--g1);}
.upload-zone p{color:var(--g4);font-size:13px;margin-top:7px;}
#file-input{display:none;}
.file-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px;}
.file-card{background:var(--g1);border:1px solid var(--border);border-radius:11px;padding:14px;transition:all .2s;}
.file-card:hover{border-color:var(--g4);}
.file-card .file-icon{font-size:26px;margin-bottom:9px;}
.file-card .file-name{font-size:13px;font-weight:500;word-break:break-all;}
.file-card .file-meta{font-size:11px;color:var(--g4);margin-top:3px;}
.file-card .file-actions{display:flex;gap:5px;margin-top:9px;}
.fah{flex:1;padding:5px;border:1px solid var(--border);background:transparent;color:var(--g4);font-size:11px;border-radius:5px;cursor:pointer;transition:all .2s;font-family:var(--font);}
.fah:hover{background:var(--g2);color:var(--white);}
.fah.del:hover{border-color:#ff4040;color:#ff4040;}

/* SETTINGS */
#settings-view{padding:28px;overflow-y:auto;display:none;}
#settings-view h2{font-size:18px;font-weight:600;margin-bottom:20px;}
.plan-cards{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:28px;}
.plan-card{background:var(--g1);border:1px solid var(--border);border-radius:14px;padding:22px;}
.plan-card.current{border-color:var(--white);}
.plan-card h3{font-size:15px;font-weight:600;margin-bottom:7px;}
.plan-card .price{font-size:26px;font-weight:700;margin:10px 0;}
.plan-card .price span{font-size:13px;font-weight:300;color:var(--g4);}
.plan-card ul{list-style:none;padding:0;margin-bottom:18px;}
.plan-card ul li{font-size:12px;color:var(--g5);padding:4px 0;display:flex;gap:7px;}
.plan-card ul li::before{content:"✓";color:var(--white);font-weight:600;}
.btn-plan{width:100%;padding:11px;border:1px solid var(--border);background:transparent;color:var(--white);font-family:var(--font);font-size:13px;border-radius:9px;cursor:pointer;transition:all .2s;}
.btn-plan:hover{background:var(--white);color:var(--black);}

/* AGENT */
#agent-panel{position:fixed;bottom:90px;left:18px;width:300px;background:var(--g1);border:1px solid var(--border);border-radius:13px;padding:14px;display:none;z-index:100;max-height:55vh;overflow-y:auto;}
.agent-panel-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;}
.agent-panel-header h4{font-size:13px;font-weight:600;}
.close-btn{border:none;background:none;color:var(--g4);cursor:pointer;font-size:17px;}
.agent-toggle{position:fixed;bottom:22px;left:18px;width:42px;height:42px;border-radius:50%;background:var(--g2);border:1px solid var(--border);color:var(--white);font-size:19px;cursor:pointer;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 12px rgba(0,0,0,.4);z-index:99;transition:all .2s;}
.agent-toggle:hover{background:var(--g3);}

/* MISC */
.toast{position:fixed;bottom:22px;right:22px;padding:11px 18px;background:var(--g2);border:1px solid var(--border);border-radius:9px;font-size:13px;z-index:1000;animation:slideIn .3s ease;pointer-events:none;}
@keyframes slideIn{from{transform:translateY(16px);opacity:0;}to{transform:translateY(0);opacity:1;}}
.sec-badge{position:fixed;top:58px;right:10px;padding:3px 9px;background:rgba(10,10,10,.8);border:1px solid var(--border);border-radius:18px;font-size:10px;color:var(--g4);display:flex;align-items:center;gap:4px;}
.sec-dot{width:5px;height:5px;background:#7fff7f;border-radius:50%;animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{opacity:1;}50%{opacity:.4;}}
@media(max-width:680px){.sidebar{display:none;}.chat-messages{padding:14px;}.chat-input-wrap{padding:10px 14px 18px;}.plan-cards{grid-template-columns:1fr;}.mode-bar,.sources-bar{padding:7px 14px 0;}}
</style>
</head>
<body>

<!-- AUTH -->
<div id="auth-screen">
  <div class="auth-card">
    <div class="auth-moon">
      <svg viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg" width="80" height="80">
        <circle cx="40" cy="40" r="34" fill="url(#mg)" opacity="0.12"/>
        <circle cx="40" cy="40" r="28" fill="#f5f5f0"/>
        <circle cx="56" cy="30" r="22" fill="#0a0a0a"/>
        <circle cx="24" cy="42" r="4.5" fill="none" stroke="#ccc" stroke-width="1.3" opacity="0.5"/>
        <circle cx="30" cy="57" r="2.8" fill="none" stroke="#ccc" stroke-width="1.1" opacity="0.4"/>
        <circle cx="20" cy="28" r="2.2" fill="none" stroke="#ccc" stroke-width="1" opacity="0.35"/>
        <circle cx="66" cy="14" r="1.3" fill="#f5f5f0" opacity="0.7"/>
        <circle cx="11" cy="20" r="1" fill="#f5f5f0" opacity="0.5"/>
        <circle cx="70" cy="52" r="1.1" fill="#f5f5f0" opacity="0.6"/>
        <circle cx="9" cy="56" r="1.5" fill="#f5f5f0" opacity="0.5"/>
        <circle cx="60" cy="68" r="0.9" fill="#f5f5f0" opacity="0.4"/>
        <circle cx="15" cy="66" r="1.1" fill="#f5f5f0" opacity="0.4"/>
        <defs><radialGradient id="mg" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="#f5f5f0"/><stop offset="100%" stop-color="#0a0a0a"/></radialGradient></defs>
      </svg>
      <div class="auth-logo-name">MoonX <span>ذكاء اصطناعي متطور</span></div>
    </div>

    <div class="auth-tabs">
      <button class="auth-tab active" onclick="switchTab('login')">تسجيل الدخول</button>
      <button class="auth-tab" onclick="switchTab('register')">حساب جديد</button>
    </div>
    <div id="auth-err" class="auth-err"></div>

    <div id="login-form">
      <div class="form-group"><label>البريد الإلكتروني</label><input type="email" id="login-email" placeholder="your@email.com" autocomplete="email"></div>
      <div class="form-group"><label>كلمة المرور</label><input type="password" id="login-pass" placeholder="••••••••" autocomplete="current-password"></div>
      <button class="btn-primary" onclick="doLogin()">دخول</button>
    </div>

    <div id="register-form" style="display:none">
      <div class="form-group"><label>الاسم</label><input type="text" id="reg-name" placeholder="اسمك"></div>
      <div class="form-group"><label>البريد الإلكتروني</label><input type="email" id="reg-email" placeholder="your@email.com"></div>
      <div class="form-group"><label>كلمة المرور</label><input type="password" id="reg-pass" placeholder="8 أحرف على الأقل"></div>
      <div style="font-size:12px;color:var(--g4);margin-bottom:10px;">اختر خطتك:</div>
      <div class="plan-badges">
        <div class="plan-badge sel" id="b-moonhigh" onclick="selectPlan('moonhigh')"><h4>🌙 MoonHigh</h4><p class="free">مجاني 3 شهور</p><p>ثم $20/سنة</p></div>
        <div class="plan-badge" id="b-normal" onclick="selectPlan('normal')"><h4>⭐ Normal</h4><p>$20/سنة</p><p>كل الميزات</p></div>
      </div>
      <button class="btn-primary" onclick="doRegister()">إنشاء الحساب</button>
    </div>
  </div>
</div>

<!-- APP -->
<div id="app">
  <div class="sec-badge"><div class="sec-dot"></div> محمي ومشفر</div>
  <div class="topbar">
    <div class="topbar-logo">
      <svg viewBox="0 0 36 36" fill="none" xmlns="http://www.w3.org/2000/svg" width="30" height="30">
        <circle cx="18" cy="18" r="13" fill="#f5f5f0"/>
        <circle cx="25" cy="13" r="10" fill="#0a0a0a"/>
        <circle cx="11" cy="20" r="2" fill="none" stroke="#bbb" stroke-width="0.8" opacity="0.5"/>
        <circle cx="14" cy="27" r="1.2" fill="none" stroke="#bbb" stroke-width="0.6" opacity="0.4"/>
        <circle cx="30" cy="6" r="0.6" fill="#f5f5f0" opacity="0.7"/>
        <circle cx="5" cy="10" r="0.5" fill="#f5f5f0" opacity="0.5"/>
      </svg>
      <span>MoonX</span>
    </div>
    <div class="topbar-nav">
      <button class="nav-btn active" onclick="showView('chat',this)">💬 محادثة</button>
      <button class="nav-btn" onclick="showView('storage',this)">🗂 ملفاتي</button>
      <button class="nav-btn" onclick="showView('settings',this)">⚙️ الحساب</button>
    </div>
    <div class="topbar-right">
      <div class="user-pill"><span id="uname">...</span><span class="plan-tag" id="ptag">...</span></div>
      <button class="logout-btn" onclick="doLogout()">خروج</button>
    </div>
  </div>

  <div class="main-layout">
    <div class="sidebar">
      <button class="new-chat-btn" onclick="newChat()">+ محادثة جديدة</button>
      <div class="sidebar-section">
        <div class="sidebar-label">الوضع</div>
        <button class="sidebar-btn active" id="sb-chat" onclick="setMode('chat')"><span>💬</span> محادثة</button>
        <button class="sidebar-btn" id="sb-build" onclick="setMode('build')"><span>🔨</span> بناء كود</button>
        <button class="sidebar-btn" id="sb-search" onclick="setMode('search')"><span>🔍</span> بحث</button>
        <button class="sidebar-btn" id="sb-analyze" onclick="setMode('analyze')"><span>📊</span> تحليل</button>
      </div>
      <div class="sidebar-section">
        <div class="sidebar-label">المصادر</div>
        <button class="sidebar-btn" id="src-wiki" onclick="toggleSrc('wikipedia')"><span>📖</span> Wikipedia</button>
        <button class="sidebar-btn" id="src-github" onclick="toggleSrc('github')"><span>🐙</span> GitHub</button>
      </div>
    </div>

    <div class="content">
      <!-- CHAT -->
      <div id="chat-view">
        <div class="chat-messages" id="messages">
          <div class="chat-welcome" id="welcome">
            <svg viewBox="0 0 72 72" fill="none" xmlns="http://www.w3.org/2000/svg" width="64" height="64">
              <circle cx="36" cy="36" r="30" fill="url(#wg)" opacity="0.12"/>
              <circle cx="36" cy="36" r="26" fill="#f5f5f0"/>
              <circle cx="50" cy="28" r="20" fill="#0a0a0a"/>
              <circle cx="22" cy="38" r="4" fill="none" stroke="#ccc" stroke-width="1.2" opacity="0.5"/>
              <circle cx="28" cy="52" r="2.5" fill="none" stroke="#ccc" stroke-width="1" opacity="0.4"/>
              <circle cx="60" cy="12" r="1.2" fill="#f5f5f0" opacity="0.7"/>
              <circle cx="8" cy="52" r="1.4" fill="#f5f5f0" opacity="0.5"/>
              <defs><radialGradient id="wg" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="#f5f5f0"/><stop offset="100%" stop-color="#0a0a0a"/></radialGradient></defs>
            </svg>
            <h2>مرحباً، أنا MoonX 🌙</h2>
            <p>ذكاء اصطناعي يفكر كإنسان. اسألني أي شيء.</p>
            <div class="quick-actions">
              <button class="quick-btn" onclick="quickMsg('اشرح كيف يعمل الذكاء الاصطناعي')">🧠 الذكاء الاصطناعي</button>
              <button class="quick-btn" onclick="quickMsg('ابنِ لي موقع HTML بسيط')">🔨 ابنِ موقع</button>
              <button class="quick-btn" onclick="quickMsg('ابحث عن أحدث تقنيات AI')">🔍 بحث</button>
              <button class="quick-btn" onclick="quickMsg('حلل هذا الكود وأخبرني بالأخطاء')">📊 تحليل</button>
            </div>
          </div>
        </div>
        <div class="mode-bar">
          <button class="mode-pill active" id="mp-chat" onclick="setMode('chat')">💬 محادثة</button>
          <button class="mode-pill" id="mp-build" onclick="setMode('build')">🔨 بناء</button>
          <button class="mode-pill" id="mp-search" onclick="setMode('search')">🔍 بحث</button>
          <button class="mode-pill" id="mp-analyze" onclick="setMode('analyze')">📊 تحليل</button>
        </div>
        <div class="sources-bar">
          <button class="src-pill" id="sp-wiki" onclick="toggleSrc('wikipedia')">📖 Wikipedia</button>
          <button class="src-pill" id="sp-github" onclick="toggleSrc('github')">🐙 GitHub</button>
        </div>
        <div class="chat-input-wrap">
          <div class="chat-input-box">
            <textarea id="msg-input" placeholder="اكتب رسالتك..." rows="1" onkeydown="handleKey(event)" oninput="autoResize(this)"></textarea>
            <button class="send-btn" id="send-btn" onclick="sendMsg()">↑</button>
          </div>
        </div>
      </div>

      <!-- STORAGE -->
      <div id="storage-view">
        <div class="storage-header"><h2>🗂 مساحة التخزين — 20GB</h2><button class="btn-primary" style="width:auto;padding:9px 18px" onclick="document.getElementById('file-input').click()">رفع ملف</button></div>
        <div class="storage-quota">
          <div style="display:flex;justify-content:space-between;font-size:12px;"><span>المساحة المستخدمة</span><span id="quota-txt">0 GB / 20 GB</span></div>
          <div class="quota-bar-wrap"><div class="quota-bar" id="quota-bar" style="width:0%"></div></div>
        </div>
        <input type="file" id="file-input" multiple onchange="uploadFiles(this.files)">
        <div class="upload-zone" id="drop-zone"
          ondragover="event.preventDefault();this.classList.add('drag')"
          ondragleave="this.classList.remove('drag')"
          ondrop="event.preventDefault();this.classList.remove('drag');uploadFiles(event.dataTransfer.files)"
          onclick="document.getElementById('file-input').click()">
          <div style="font-size:30px">🌙</div>
          <p>اسحب ملفاتك هنا أو اضغط للاختيار</p>
          <p style="font-size:11px;margin-top:3px">صور، مستندات، أكواد — أي شيء</p>
        </div>
        <div class="file-grid" id="file-grid"><div style="color:var(--g4);font-size:13px;grid-column:1/-1;text-align:center;padding:16px">جاري التحميل...</div></div>
      </div>

      <!-- SETTINGS -->
      <div id="settings-view">
        <h2>⚙️ الحساب والاشتراك</h2>
        <div class="plan-cards">
          <div class="plan-card"><h3>🌙 MoonHigh</h3><div class="price">مجاني <span>/ 3 شهور</span></div><ul><li>Claude Opus (أقوى)</li><li>Wikipedia + GitHub</li><li>20GB تخزين</li><li>Agent فاحص</li><li>Bot مساعد</li></ul><button class="btn-plan" onclick="subscribe('moonhigh')">اشترك الآن</button></div>
          <div class="plan-card"><h3>⭐ Normal</h3><div class="price">$20 <span>/ سنة</span></div><ul><li>Claude Sonnet (سريع)</li><li>Wikipedia + GitHub</li><li>20GB تخزين</li><li>Agent فاحص</li><li>Bot مساعد</li></ul><button class="btn-plan" onclick="subscribe('normal')">اشترك الآن</button></div>
        </div>
        <div style="background:var(--g1);border:1px solid var(--border);border-radius:13px;padding:22px;">
          <h3 style="font-size:15px;margin-bottom:14px">معلومات حسابي</h3>
          <div id="acct-info" style="font-size:13px;color:var(--g5);line-height:2.2"></div>
        </div>
      </div>
    </div>
  </div>

  <div id="agent-panel">
    <div class="agent-panel-header"><h4>🤖 Agent الفاحص</h4><button class="close-btn" onclick="document.getElementById('agent-panel').style.display='none'">×</button></div>
    <div id="agent-content"><p style="font-size:12px;color:var(--g4)">الـ Agent يفحص كل ما تبنيه ويبلغك بالأخطاء هنا.</p></div>
  </div>
  <button class="agent-toggle" onclick="toggleAgent()" title="Agent الفاحص">🤖</button>
</div>

<script>
const API='';
let token=localStorage.getItem('moonx_token');
let currentUser=null,currentMode='chat',activeSources=[],convId=null,convHistory=[],selPlan='moonhigh';

window.addEventListener('DOMContentLoaded',()=>{
  if(token)loadApp(); else showAuth();
  document.getElementById('login-pass').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();});
  document.getElementById('login-email').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();});
  if(new URLSearchParams(location.search).get('payment')==='success'){showToast('✓ تم الاشتراك بنجاح!');setTimeout(loadApp,1000);}
});

function showAuth(){document.getElementById('auth-screen').style.display='flex';document.getElementById('app').style.display='none';}
function switchTab(t){
  document.querySelectorAll('.auth-tab').forEach((el,i)=>el.classList.toggle('active',(i===0&&t==='login')||(i===1&&t==='register')));
  document.getElementById('login-form').style.display=t==='login'?'':'none';
  document.getElementById('register-form').style.display=t==='register'?'':'none';
  document.getElementById('auth-err').style.display='none';
}
function selectPlan(p){selPlan=p;document.getElementById('b-moonhigh').classList.toggle('sel',p==='moonhigh');document.getElementById('b-normal').classList.toggle('sel',p==='normal');}
function showErr(m){const e=document.getElementById('auth-err');e.textContent=m;e.style.display='block';}

async function doLogin(){
  const email=document.getElementById('login-email').value.trim();
  const pass=document.getElementById('login-pass').value;
  if(!email||!pass)return showErr('الرجاء إدخال البريد وكلمة المرور');
  const btn=document.querySelector('#login-form .btn-primary');btn.disabled=true;btn.textContent='...';
  try{
    const r=await fetch(API+'/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password:pass})});
    const d=await r.json();
    if(!r.ok)return showErr(d.error||'خطأ في تسجيل الدخول');
    token=d.token;localStorage.setItem('moonx_token',token);currentUser=d.user;loadApp();
  }catch{showErr('خطأ في الاتصال');}
  finally{btn.disabled=false;btn.textContent='دخول';}
}

async function doRegister(){
  const name=document.getElementById('reg-name').value.trim();
  const email=document.getElementById('reg-email').value.trim();
  const pass=document.getElementById('reg-pass').value;
  if(!name||!email||!pass)return showErr('جميع الحقول مطلوبة');
  if(pass.length<8)return showErr('كلمة المرور 8 أحرف على الأقل');
  const btn=document.querySelector('#register-form .btn-primary');btn.disabled=true;btn.textContent='...';
  try{
    const r=await fetch(API+'/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,email,password:pass,plan:selPlan})});
    const d=await r.json();
    if(!r.ok)return showErr(d.error||'خطأ في إنشاء الحساب');
    token=d.token;localStorage.setItem('moonx_token',token);currentUser=d.user;loadApp();
  }catch{showErr('خطأ في الاتصال');}
  finally{btn.disabled=false;btn.textContent='إنشاء الحساب';}
}

async function doLogout(){
  await fetch(API+'/api/auth/logout',{method:'POST',headers:{'Authorization':'Bearer '+token}}).catch(()=>{});
  localStorage.removeItem('moonx_token');token=null;currentUser=null;showAuth();
}

async function loadApp(){
  if(!currentUser){
    const r=await fetch(API+'/api/auth/me',{headers:{'Authorization':'Bearer '+token}});
    if(!r.ok){localStorage.removeItem('moonx_token');showAuth();return;}
    currentUser=(await r.json()).user;
  }
  document.getElementById('auth-screen').style.display='none';
  document.getElementById('app').style.display='flex';
  updateUI();loadFiles();updateAcct();
}

function updateUI(){
  if(!currentUser)return;
  document.getElementById('uname').textContent=currentUser.name;
  const t=document.getElementById('ptag');
  t.textContent=currentUser.plan==='moonhigh'?'🌙 MoonHigh':currentUser.plan==='normal'?'⭐ Normal':currentUser.isFreeTrial?'🆓 تجريبي':'مجاني';
  if(currentUser.isPaid||currentUser.isFreeTrial)t.classList.add('paid');
}

function showView(v,btn){
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  if(btn)btn.classList.add('active');
  document.getElementById('chat-view').style.display=v==='chat'?'flex':'none';
  document.getElementById('storage-view').style.display=v==='storage'?'block':'none';
  document.getElementById('settings-view').style.display=v==='settings'?'block':'none';
  if(v==='storage')loadFiles();
}

function setMode(m){
  currentMode=m;
  document.querySelectorAll('.mode-pill').forEach(p=>p.classList.remove('active'));
  document.getElementById('mp-'+m).classList.add('active');
  document.querySelectorAll('.sidebar-btn[id^="sb-"]').forEach(b=>b.classList.remove('active'));
  document.getElementById('sb-'+m).classList.add('active');
}

function toggleSrc(s){
  const i=activeSources.indexOf(s);
  if(i===-1)activeSources.push(s);else activeSources.splice(i,1);
  const id=s==='wikipedia'?'wiki':'github';
  document.getElementById('sp-'+id).classList.toggle('active',activeSources.includes(s));
  document.getElementById('src-'+id).classList.toggle('active',activeSources.includes(s));
}

function newChat(){
  convId=null;convHistory=[];
  const m=document.getElementById('messages');
  m.innerHTML='<div class="chat-welcome" id="welcome"><svg viewBox="0 0 72 72" fill="none" width="56" height="56"><circle cx="36" cy="36" r="26" fill="#f5f5f0"/><circle cx="50" cy="28" r="20" fill="#0a0a0a"/><circle cx="22" cy="38" r="4" fill="none" stroke="#ccc" stroke-width="1.2" opacity="0.5"/><circle cx="60" cy="12" r="1.2" fill="#f5f5f0" opacity="0.7"/></svg><h2>محادثة جديدة 🌙</h2><p>اسألني أي شيء</p></div>';
}

function quickMsg(t){document.getElementById('msg-input').value=t;sendMsg();}
function handleKey(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMsg();}}
function autoResize(el){el.style.height='auto';el.style.height=Math.min(el.scrollHeight,110)+'px';}

async function sendMsg(){
  const inp=document.getElementById('msg-input');
  const msg=inp.value.trim();if(!msg)return;
  document.getElementById('welcome')?.remove();
  inp.value='';inp.style.height='auto';
  document.getElementById('send-btn').disabled=true;
  appendMsg('user',msg);
  convHistory.push({role:'user',content:msg});
  const tid=appendTyping();
  try{
    const r=await fetch(API+'/api/chat',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({message:msg,history:convHistory.slice(-10),mode:currentMode,sources:activeSources,conversationId:convId})});
    const d=await r.json();
    removeTyping(tid);
    if(!r.ok){
      if(d.code==='SUBSCRIPTION_REQUIRED'){appendMsg('assistant','⚠️ انتهت الفترة التجريبية. اشترك بـ $20/سنة للاستمرار.');showView('settings',null);}
      else appendMsg('assistant','❌ خطأ: '+(d.error||''));
      return;
    }
    convId=d.conversationId;convHistory.push({role:'assistant',content:d.reply});
    appendMsg('assistant',d.reply,d.agentReport);
    if(d.agentReport)updateAgent(d.agentReport);
  }catch(e){removeTyping(tid);appendMsg('assistant','❌ خطأ: '+e.message);}
  finally{document.getElementById('send-btn').disabled=false;inp.focus();}
}

function appendMsg(role,text,ar){
  const msgs=document.getElementById('messages');
  const isU=role==='user';
  let agHtml='';
  if(ar&&ar.issues&&ar.issues.length>0){
    const st=ar.passed?'<span class="ok">✓ لا أخطاء</span>':'<span class="fail">✗ أخطاء</span>';
    const iList=ar.issues.slice(0,4).map(i=>'<div class="agent-issue"><span class="sev-'+(i.severity||i.type)+'">'+(i.severity==='critical'?'🔴':i.severity==='error'?'🟠':i.severity==='warning'?'🟡':'ℹ️')+'</span> '+i.msg+'</div>').join('');
    agHtml='<div class="agent-report">🤖 '+st+iList+'</div>';
  }
  const d=document.createElement('div');d.className='msg '+role;
  d.innerHTML='<div class="msg-avatar">'+(isU?'👤':'🌙')+'</div><div class="msg-bubble">'+fmtMsg(text)+agHtml+'</div>';
  msgs.appendChild(d);msgs.scrollTop=msgs.scrollHeight;
}

function fmtMsg(t){
  t=t.replace(/```(\w*)\n?([\s\S]*?)```/g,(_,l,c)=>'<pre><code>'+esc(c.trim())+'</code></pre>');
  t=t.replace(/`([^`]+)`/g,'<code>$1</code>');
  t=t.replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>');
  t=t.replace(/\n/g,'<br>');return t;
}
function esc(t){return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

let tc=0;
function appendTyping(){
  const id='ty-'+(++tc),m=document.getElementById('messages');
  const d=document.createElement('div');d.className='msg assistant';d.id=id;
  d.innerHTML='<div class="msg-avatar">🌙</div><div class="msg-bubble"><div class="typing-indicator"><div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div></div></div>';
  m.appendChild(d);m.scrollTop=m.scrollHeight;return id;
}
function removeTyping(id){document.getElementById(id)?.remove();}

async function loadFiles(){
  try{
    const r=await fetch(API+'/api/storage/list',{headers:{'Authorization':'Bearer '+token}});
    const d=await r.json();if(!r.ok)return;
    renderFiles(d.files||[],d.storageUsed||0,d.storageLimit);
  }catch{}
}

function renderFiles(files,used,limit){
  const gb=n=>(n/(1024**3)).toFixed(2);
  document.getElementById('quota-txt').textContent=gb(used)+' GB / '+gb(limit)+' GB';
  document.getElementById('quota-bar').style.width=Math.min((used/limit)*100,100)+'%';
  const g=document.getElementById('file-grid');
  if(!files.length){g.innerHTML='<div style="color:var(--g4);font-size:13px;grid-column:1/-1;text-align:center;padding:16px">لا توجد ملفات بعد</div>';return;}
  const icon=t=>!t?'📁':t.startsWith('image')?'🖼':t.includes('pdf')?'📄':t.startsWith('video')?'🎥':t.startsWith('audio')?'🎵':'📁';
  g.innerHTML=files.map(f=>'<div class="file-card"><div class="file-icon">'+icon(f.type)+'</div><div class="file-name">'+f.name+'</div><div class="file-meta">'+(f.size/1024).toFixed(1)+' KB</div><div class="file-actions"><button class="fah" onclick="dlFile(\''+f.id+'\',\''+f.name+'\')">تنزيل</button><button class="fah del" onclick="delFile(\''+f.id+'\')">حذف</button></div></div>').join('');
}

async function uploadFiles(files){
  for(const file of files){
    const fd=new FormData();fd.append('file',file);
    showToast('جاري رفع '+file.name+'...');
    const r=await fetch(API+'/api/storage/upload',{method:'POST',headers:{'Authorization':'Bearer '+token},body:fd});
    const d=await r.json();
    showToast(r.ok?'✓ تم رفع '+file.name:'✗ فشل: '+d.error);
  }
  loadFiles();
}

async function dlFile(id,name){
  const r=await fetch(API+'/api/storage/download/'+id,{headers:{'Authorization':'Bearer '+token}});
  const blob=await r.blob();const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;a.download=name;a.click();URL.revokeObjectURL(url);
}

async function delFile(id){
  if(!confirm('حذف هذا الملف؟'))return;
  const r=await fetch(API+'/api/storage/delete/'+id,{method:'DELETE',headers:{'Authorization':'Bearer '+token}});
  if(r.ok){showToast('تم الحذف');loadFiles();}
}

async function subscribe(plan){
  showToast('جاري الاتصال بـ Stripe...');
  const r=await fetch(API+'/api/payment/create-checkout',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({plan})});
  const d=await r.json();
  if(r.ok&&d.checkoutUrl)window.location.href=d.checkoutUrl;
  else showToast('خطأ: '+(d.error||''));
}

async function updateAcct(){
  if(!currentUser)return;
  const now=Date.now();
  document.getElementById('acct-info').innerHTML=
    '<div>الاسم: <strong>'+currentUser.name+'</strong></div>'+
    '<div>البريد: <strong>'+currentUser.email+'</strong></div>'+
    '<div>الخطة: <strong>'+(currentUser.plan==='moonhigh'?'🌙 MoonHigh':currentUser.plan==='normal'?'⭐ Normal':'🆓 مجاني')+'</strong></div>'+
    (currentUser.isFreeTrial?'<div>أيام مجانية متبقية: <strong>'+currentUser.freeTrialDaysLeft+' يوم</strong></div>':'')+
    (currentUser.isPaid?'<div>انتهاء الاشتراك: <strong>'+new Date(currentUser.planExpiry).toLocaleDateString('ar')+'</strong></div>':'');
}

function toggleAgent(){const p=document.getElementById('agent-panel');p.style.display=p.style.display==='block'?'none':'block';}
function updateAgent(r){
  const c=document.getElementById('agent-content');
  c.innerHTML='<div style="color:'+(r.passed?'#7fff7f':'#ff8080')+';font-size:13px;font-weight:600;margin-bottom:8px">'+(r.passed?'✓ لا أخطاء':'✗ توجد أخطاء')+'</div>'+
    '<div style="font-size:11px;color:var(--g4);margin-bottom:6px">الأحرف: '+r.charCount+' | النوع: '+r.contentType+'</div>'+
    (r.issues||[]).map(i=>'<div class="agent-issue"><span class="sev-'+(i.severity||'info')+'">'+(i.severity==='critical'?'🔴':i.severity==='error'?'🟠':i.severity==='warning'?'🟡':'ℹ️')+'</span><span style="font-size:12px"> '+i.msg+'</span></div>').join('')+
    (r.botSuggestion?'<div style="margin-top:10px;font-size:12px;color:var(--g5);border-top:1px solid var(--border);padding-top:8px">'+r.botSuggestion+'</div>':'');
  document.getElementById('agent-panel').style.display='block';
}

function showToast(m){const t=document.createElement('div');t.className='toast';t.textContent=m;document.body.appendChild(t);setTimeout(()=>t.remove(),3000);}
</script>
</body>
</html>`;
