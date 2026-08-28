const { sb, admin, json } = require('./_supabase');

function cleanKey(v) { return String(v || '').trim().toUpperCase(); }

module.exports = async (req, res) => {
  try {
    if (!admin(req)) return json(res, 401, { error: 'unauthorized' });

    if (req.method === 'GET') {
      const rows = await sb('keys?select=*&order=created_at.desc', { method: 'GET' });
      return json(res, 200, rows);
    }

    if (req.method !== 'POST') return json(res, 405, { error: 'method_not_allowed' });
    const body = typeof req.body === 'object' ? req.body : {};
    const action = String(body.action || '');

    if (action === 'create') {
      const key = cleanKey(body.key);
      const owner = String(body.owner || '');
      const days = Math.max(1, Number(body.days || 30));
      if (!key) return json(res, 400, { error: 'missing_key' });
      const expires = new Date(Date.now() + days * 86400000).toISOString();
      const rows = await sb('keys', { method: 'POST', headers: { Prefer: 'return=representation' }, body: JSON.stringify({ key, owner, status: 'active', expires_at: expires, uid: body.uid || null, reseller: body.reseller || '', cost: Number(body.cost || 0) }) });
      return json(res, 201, rows[0]);
    }

    const key = cleanKey(body.key);
    if (!key) return json(res, 400, { error: 'missing_key' });

    if (action === 'block' || action === 'revoke' || action === 'unblock') {
      const status = action === 'block' ? 'blocked' : action === 'revoke' ? 'revoked' : 'active';
      const rows = await sb(`keys?key=eq.${encodeURIComponent(key)}&select=id,key,status,expires_at&limit=1`, { method: 'GET' });
      if (!rows.length) return json(res, 404, { error: 'not_found' });
      const out = await sb(`keys?id=eq.${rows[0].id}`, { method: 'PATCH', headers: { Prefer: 'return=representation' }, body: JSON.stringify({ status }) });
      return json(res, 200, out[0]);
    }

    if (action === 'extend') {
      const days = Math.max(1, Number(body.days || 30));
      const rows = await sb(`keys?key=eq.${encodeURIComponent(key)}&select=id,expires_at&limit=1`, { method: 'GET' });
      if (!rows.length) return json(res, 404, { error: 'not_found' });
      const base = Math.max(Date.now(), new Date(rows[0].expires_at).getTime());
      const expires = new Date(base + days * 86400000).toISOString();
      const out = await sb(`keys?id=eq.${rows[0].id}`, { method: 'PATCH', headers: { Prefer: 'return=representation' }, body: JSON.stringify({ expires_at: expires, status: 'active' }) });
      return json(res, 200, out[0]);
    }

    if (action === 'delete') {
      await sb(`keys?key=eq.${encodeURIComponent(key)}`, { method: 'DELETE', headers: { Prefer: 'return=minimal' } });
      return json(res, 200, { ok: true });
    }

    return json(res, 400, { error: 'unknown_action' });
  } catch (e) {
    return json(res, 500, { error: 'server_error', message: String(e.message || e) });
  }
};
