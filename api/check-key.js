const { sb, json } = require('./_supabase');

module.exports = async (req, res) => {
  try {
    if (req.method !== 'POST') return json(res, 405, { valid: false, error: 'method_not_allowed' });
    const body = typeof req.body === 'object' ? req.body : {};
    const cleanKey = String(body.key || '').trim().toUpperCase();
    const cleanUid = body.uid == null ? '' : String(body.uid).trim();
    if (!cleanKey) return json(res, 400, { valid: false, error: 'missing_key' });
    if (!cleanUid) return json(res, 400, { valid: false, error: 'missing_uid' });

    const result = await sb('rpc/check_and_bind_device', {
      method: 'POST',
      body: JSON.stringify({ p_key: cleanKey, p_uid: cleanUid })
    });

    if (!result || result.valid !== true) return json(res, 200, result || { valid: false, reason: 'invalid' });

    const rows = await sb(`keys?key=eq.${encodeURIComponent(cleanKey)}&select=key,owner,status,expires_at,device_limit,devices,reseller,cost&limit=1`, { method: 'GET' });
    const k = rows[0] || {};
    const exp = new Date(k.expires_at).getTime();
    const days = Number.isFinite(exp) ? Math.max(0, Math.ceil((exp - Date.now()) / 86400000)) : 0;
    return json(res, 200, {
      valid: true,
      reason: result.reason || 'ok',
      key: k.key || cleanKey,
      owner: k.owner || '',
      expire: k.expires_at || result.expire,
      days_left: days,
      device_limit: Number(k.device_limit ?? result.device_limit ?? 1),
      device_count: Array.isArray(k.devices) ? k.devices.length : Number(result.device_count || 0),
      uid_bound: true
    });
  } catch (e) {
    return json(res, 500, { valid: false, error: 'server_error', message: String(e.message || e) });
  }
};
