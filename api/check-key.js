const { sb, json } = require('./_supabase');

module.exports = async (req, res) => {
  try {
    if (req.method !== 'POST') return json(res, 405, { valid: false, error: 'method_not_allowed' });
    const { key, uid } = typeof req.body === 'object' ? req.body : {};
    const cleanKey = String(key || '').trim().toUpperCase();
    const cleanUid = uid == null ? '' : String(uid);
    if (!cleanKey) return json(res, 400, { valid: false, error: 'missing_key' });

    const rows = await sb(`keys?key=eq.${encodeURIComponent(cleanKey)}&select=id,key,owner,status,expires_at,uid,reseller,cost&limit=1`, { method: 'GET' });
    if (!rows.length) return json(res, 200, { valid: false, reason: 'key_not_found' });
    const k = rows[0];
    const now = Date.now();
    const exp = new Date(k.expires_at).getTime();
    if (k.status === 'blocked') return json(res, 200, { valid: false, reason: 'blocked', expire: k.expires_at });
    if (k.status === 'revoked') return json(res, 200, { valid: false, reason: 'revoked', expire: k.expires_at });
    if (!Number.isFinite(exp) || exp <= now) {
      await sb(`keys?id=eq.${k.id}`, { method: 'PATCH', headers: { Prefer: 'return=minimal' }, body: JSON.stringify({ status: 'expired' }) });
      return json(res, 200, { valid: false, reason: 'expired', expire: k.expires_at });
    }
    if (k.uid && cleanUid && String(k.uid) !== cleanUid) {
      return json(res, 200, { valid: false, reason: 'uid_mismatch', expire: k.expires_at });
    }
    if (!k.uid && cleanUid) {
      await sb(`keys?id=eq.${k.id}`, { method: 'PATCH', headers: { Prefer: 'return=minimal' }, body: JSON.stringify({ uid: cleanUid, last_check_at: new Date().toISOString(), check_count: 1 }) });
    } else {
      await sb(`keys?id=eq.${k.id}`, { method: 'PATCH', headers: { Prefer: 'return=minimal' }, body: JSON.stringify({ last_check_at: new Date().toISOString() }) });
      // Count is intentionally best-effort to keep verification fast.
    }
    const days = Math.max(0, Math.ceil((exp - now) / 86400000));
    return json(res, 200, { valid: true, reason: 'ok', key: k.key, owner: k.owner, expire: k.expires_at, days_left: days, uid_bound: !!(k.uid || cleanUid) });
  } catch (e) {
    return json(res, 500, { valid: false, error: 'server_error', message: String(e.message || e) });
  }
};
