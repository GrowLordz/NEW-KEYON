-- FORGE/OS online key system + custom device limit
create table if not exists public.keys (
  id bigint generated always as identity primary key,
  key text unique not null,
  owner text not null default '',
  status text not null default 'active' check (status in ('active','blocked','revoked','expired')),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  uid text,
  reseller text not null default '',
  cost bigint not null default 0,
  last_check_at timestamptz,
  check_count bigint not null default 0,
  device_limit integer not null default 1 check (device_limit >= 0),
  devices text[] not null default '{}'
);

-- Safe migration for projects that already created the original table.
alter table public.keys add column if not exists device_limit integer not null default 1;
alter table public.keys add column if not exists devices text[] not null default '{}';

-- Preserve the old single-UID binding when migrating.
update public.keys
set devices = array[uid]
where uid is not null and uid <> '' and (devices is null or cardinality(devices) = 0);

create index if not exists keys_key_idx on public.keys(key);
create index if not exists keys_uid_idx on public.keys(uid);
create index if not exists keys_expires_idx on public.keys(expires_at);

alter table public.keys enable row level security;

-- Atomic online device binding. device_limit = 0 means unlimited devices.
create or replace function public.check_and_bind_device(p_key text, p_uid text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  k public.keys%rowtype;
  n integer;
begin
  select * into k from public.keys where key = upper(trim(p_key)) for update;
  if not found then
    return jsonb_build_object('valid', false, 'reason', 'key_not_found');
  end if;

  if k.status = 'blocked' then
    return jsonb_build_object('valid', false, 'reason', 'blocked', 'expire', k.expires_at);
  end if;
  if k.status = 'revoked' then
    return jsonb_build_object('valid', false, 'reason', 'revoked', 'expire', k.expires_at);
  end if;
  if k.expires_at <= now() then
    update public.keys set status = 'expired', last_check_at = now() where id = k.id;
    return jsonb_build_object('valid', false, 'reason', 'expired', 'expire', k.expires_at);
  end if;

  if p_uid is null or trim(p_uid) = '' then
    return jsonb_build_object('valid', false, 'reason', 'missing_uid', 'expire', k.expires_at);
  end if;

  -- Keep legacy uid synchronized for compatibility with older code.
  if k.uid is not null and k.uid <> '' and not (k.uid = any(coalesce(k.devices, '{}'))) then
    k.devices := array_append(coalesce(k.devices, '{}'), k.uid);
  end if;

  if p_uid = any(coalesce(k.devices, '{}')) then
    update public.keys
      set devices = coalesce(k.devices, '{}'),
          uid = coalesce(k.uid, p_uid),
          last_check_at = now(),
          check_count = check_count + 1
      where id = k.id;
    return jsonb_build_object('valid', true, 'reason', 'ok', 'device_limit', k.device_limit,
      'device_count', cardinality(coalesce(k.devices, '{}')), 'expire', k.expires_at);
  end if;

  n := cardinality(coalesce(k.devices, '{}'));
  if k.device_limit > 0 and n >= k.device_limit then
    return jsonb_build_object('valid', false, 'reason', 'device_limit_reached',
      'device_limit', k.device_limit, 'device_count', n, 'expire', k.expires_at);
  end if;

  k.devices := array_append(coalesce(k.devices, '{}'), trim(p_uid));
  update public.keys
    set devices = k.devices,
        uid = coalesce(uid, trim(p_uid)),
        last_check_at = now(),
        check_count = check_count + 1
    where id = k.id;

  return jsonb_build_object('valid', true, 'reason', 'device_bound', 'device_limit', k.device_limit,
    'device_count', cardinality(k.devices), 'expire', k.expires_at);
end;
$$;

revoke all on function public.check_and_bind_device(text, text) from public, anon, authenticated;
-- The Vercel backend uses the Supabase secret key and can execute this function.
grant execute on function public.check_and_bind_device(text, text) to service_role;
