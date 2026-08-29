
-- FORGE/OS production schema
create extension if not exists pgcrypto;

create table if not exists public.settings (
  key text primary key,
  value text not null,
  updated_at timestamptz not null default now()
);

insert into public.settings(key,value)
values ('key_price_per_day','1000')
on conflict (key) do nothing;

create table if not exists public.resellers (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  username text not null unique,
  password_hash text not null,
  quota integer not null default 0 check (quota >= 0),
  sold integer not null default 0 check (sold >= 0),
  expires_at timestamptz not null,
  prefix text not null default 'RS',
  balance bigint not null default 0 check (balance >= 0),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.keys (
  id bigint generated always as identity primary key,
  key text unique not null,
  owner text not null default '',
  status text not null default 'active' check (status in ('active','blocked','revoked','expired')),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  uid text,
  reseller text not null default '',
  reseller_id uuid references public.resellers(id) on delete set null,
  cost bigint not null default 0,
  last_check_at timestamptz,
  check_count bigint not null default 0,
  device_limit integer not null default 1 check (device_limit >= 0),
  devices text[] not null default '{}'
);

create table if not exists public.transactions (
  id bigint generated always as identity primary key,
  reseller_id uuid references public.resellers(id) on delete set null,
  account text not null default '',
  type text not null,
  detail text not null default '',
  amount bigint not null default 0,
  created_at timestamptz not null default now()
);

-- Compatibility migrations for older installations.
-- Run this whole schema after the production files are deployed.
alter table public.settings add column if not exists updated_at timestamptz not null default now();

alter table public.resellers add column if not exists id uuid default gen_random_uuid();
alter table public.resellers add column if not exists name text default '';
alter table public.resellers add column if not exists username text default '';
alter table public.resellers add column if not exists password_hash text default '';
alter table public.resellers add column if not exists quota integer not null default 0;
alter table public.resellers add column if not exists sold integer not null default 0;
alter table public.resellers add column if not exists expires_at timestamptz default now();
alter table public.resellers add column if not exists prefix text not null default 'RS';
alter table public.resellers add column if not exists balance bigint not null default 0;
alter table public.resellers add column if not exists active boolean not null default true;
alter table public.resellers add column if not exists created_at timestamptz not null default now();

alter table public.keys add column if not exists id bigint generated always as identity;
alter table public.keys add column if not exists key text default '';
alter table public.keys add column if not exists owner text not null default '';
alter table public.keys add column if not exists status text not null default 'active';
alter table public.keys add column if not exists created_at timestamptz not null default now();
alter table public.keys add column if not exists expires_at timestamptz default now();
alter table public.keys add column if not exists uid text;
alter table public.keys add column if not exists reseller text not null default '';
alter table public.keys add column if not exists reseller_id uuid;
alter table public.keys add column if not exists cost bigint not null default 0;
alter table public.keys add column if not exists last_check_at timestamptz;
alter table public.keys add column if not exists check_count bigint not null default 0;
alter table public.keys add column if not exists device_limit integer not null default 1;
alter table public.keys add column if not exists devices text[] not null default '{}';

alter table public.transactions add column if not exists id bigint generated always as identity;
alter table public.transactions add column if not exists reseller_id uuid;
alter table public.transactions add column if not exists account text not null default '';
alter table public.transactions add column if not exists type text not null default 'SYSTEM';
alter table public.transactions add column if not exists detail text not null default '';
alter table public.transactions add column if not exists amount bigint not null default 0;
alter table public.transactions add column if not exists created_at timestamptz not null default now();

update public.resellers set id=gen_random_uuid() where id is null;
update public.resellers set expires_at=now()+interval '30 days' where expires_at is null;
update public.keys set expires_at=now()+interval '30 days' where expires_at is null;

-- Safe migrations for the earlier schema.
alter table public.keys add column if not exists reseller_id uuid references public.resellers(id) on delete set null;
alter table public.keys add column if not exists device_limit integer not null default 1;
alter table public.keys add column if not exists devices text[] not null default '{}';
alter table public.keys add column if not exists last_check_at timestamptz;
alter table public.keys add column if not exists check_count bigint not null default 0;

update public.keys
set devices = array[uid]
where uid is not null and uid <> '' and coalesce(cardinality(devices),0)=0;

create index if not exists keys_key_idx on public.keys(key);
create index if not exists keys_uid_idx on public.keys(uid);
create index if not exists keys_reseller_id_idx on public.keys(reseller_id);
create index if not exists keys_expires_idx on public.keys(expires_at);
create index if not exists txns_reseller_idx on public.transactions(reseller_id);
create index if not exists txns_created_idx on public.transactions(created_at desc);

alter table public.settings enable row level security;
alter table public.resellers enable row level security;
alter table public.keys enable row level security;
alter table public.transactions enable row level security;

-- Backend uses the Supabase secret key. No public policies are required.
-- These RPCs are also protected by the same backend-only access pattern.

create or replace function public.check_and_bind_device(p_key text, p_uid text)
returns jsonb
language plpgsql
security definer
set search_path=public
as $$
declare k public.keys%rowtype; new_devices text[]; n integer;
begin
  select * into k from public.keys where key=upper(trim(p_key)) for update;
  if not found then return jsonb_build_object('valid',false,'reason','key_not_found'); end if;
  if k.status='blocked' then return jsonb_build_object('valid',false,'reason','blocked','expire',k.expires_at); end if;
  if k.status='revoked' then return jsonb_build_object('valid',false,'reason','revoked','expire',k.expires_at); end if;
  if k.expires_at <= now() then
    update public.keys set status='expired',last_check_at=now() where id=k.id;
    return jsonb_build_object('valid',false,'reason','expired','expire',k.expires_at);
  end if;
  if p_uid is null or trim(p_uid)='' then return jsonb_build_object('valid',false,'reason','missing_uid','expire',k.expires_at); end if;

  new_devices:=coalesce(k.devices,'{}');
  if k.uid is not null and k.uid<>'' and not(k.uid=any(new_devices)) then
    new_devices:=array_append(new_devices,k.uid);
  end if;

  if p_uid=any(new_devices) then
    update public.keys set devices=new_devices,uid=coalesce(k.uid,p_uid),
      last_check_at=now(),check_count=check_count+1 where id=k.id;
    return jsonb_build_object('valid',true,'reason','ok','expire',k.expires_at,
      'device_limit',k.device_limit,'device_count',cardinality(new_devices));
  end if;

  n:=cardinality(new_devices);
  if k.device_limit=0 or n < k.device_limit then
    new_devices:=array_append(new_devices,p_uid);
    update public.keys set devices=new_devices,uid=coalesce(k.uid,p_uid),
      last_check_at=now(),check_count=check_count+1 where id=k.id;
    return jsonb_build_object('valid',true,'reason','device_bound','expire',k.expires_at,
      'device_limit',k.device_limit,'device_count',cardinality(new_devices));
  end if;

  return jsonb_build_object('valid',false,'reason','device_limit_reached','expire',k.expires_at,
    'device_limit',k.device_limit,'device_count',n);
end;
$$;

create or replace function public.create_reseller_key(
  p_reseller_id uuid, p_key text, p_owner text, p_expires_at timestamptz,
  p_cost bigint, p_device_limit integer
) returns jsonb
language plpgsql security definer set search_path=public as $$
declare r public.resellers%rowtype; k public.keys%rowtype;
begin
  select * into r from public.resellers where id=p_reseller_id for update;
  if not found or not r.active then raise exception 'reseller_not_found'; end if;
  if r.expires_at <= now() then raise exception 'reseller_expired'; end if;
  if r.quota > 0 and r.sold >= r.quota then raise exception 'quota_exceeded'; end if;
  if r.balance < p_cost then raise exception 'insufficient_balance'; end if;
  insert into public.keys(key,owner,status,expires_at,reseller,reseller_id,cost,device_limit)
    values(upper(trim(p_key)),p_owner,'active',p_expires_at,r.name,r.id,p_cost,p_device_limit)
    returning * into k;
  update public.resellers set balance=balance-p_cost,sold=sold+1 where id=r.id;
  insert into public.transactions(reseller_id,account,type,detail,amount)
    values(r.id,r.name,'PEMBELIAN','Forge key '||k.key||' ('||p_cost||')',-p_cost);
  return jsonb_build_object('key',k.key,'owner',k.owner,'status',k.status,'expires_at',k.expires_at,
    'reseller',k.reseller,'reseller_id',k.reseller_id,'cost',k.cost,'device_limit',k.device_limit,
    'created_at',k.created_at);
exception when unique_violation then
  raise exception 'duplicate_key';
end;
$$;

create or replace function public.extend_reseller_key(
  p_key text,p_reseller_id uuid,p_days integer,p_cost bigint
) returns jsonb
language plpgsql security definer set search_path=public as $$
declare r public.resellers%rowtype; k public.keys%rowtype; base timestamptz;
begin
  select * into r from public.resellers where id=p_reseller_id for update;
  if not found or not r.active then raise exception 'reseller_not_found'; end if;
  if r.balance<p_cost then raise exception 'insufficient_balance'; end if;
  select * into k from public.keys where key=upper(trim(p_key)) and reseller_id=p_reseller_id for update;
  if not found then raise exception 'key_not_found'; end if;
  if k.status='revoked' then raise exception 'revoked'; end if;
  base:=greatest(k.expires_at,now());
  update public.keys set expires_at=base+(p_days||' days')::interval,
    status=case when status='expired' then 'active' else status end,
    cost=cost+p_cost where id=k.id returning * into k;
  update public.resellers set balance=balance-p_cost where id=r.id;
  insert into public.transactions(reseller_id,account,type,detail,amount)
    values(r.id,r.name,'PERPANJANG','Extend key '||k.key||' +'||p_days||' hari',-p_cost);
  return to_jsonb(k);
end;
$$;

create or replace function public.admin_topup_reseller(p_reseller_id uuid,p_amount bigint)
returns jsonb language plpgsql security definer set search_path=public as $$
declare r public.resellers%rowtype;
begin
  if p_amount<1000 then raise exception 'invalid_amount'; end if;
  select * into r from public.resellers where id=p_reseller_id for update;
  if not found then raise exception 'reseller_not_found'; end if;
  update public.resellers set balance=balance+p_amount where id=r.id returning * into r;
  insert into public.transactions(reseller_id,account,type,detail,amount)
    values(r.id,'admin','TOP UP','Admin top up '||r.name,p_amount);
  return to_jsonb(r);
end $$;

create or replace function public.admin_set_reseller(
  p_name text,p_username text,p_password_hash text,p_quota integer,p_days integer,
  p_prefix text,p_balance bigint
) returns jsonb language plpgsql security definer set search_path=public as $$
declare r public.resellers%rowtype;
begin
  if trim(p_name)='' or trim(p_username)='' or p_password_hash='' then raise exception 'invalid_reseller'; end if;
  insert into public.resellers(name,username,password_hash,quota,expires_at,prefix,balance)
    values(trim(p_name),lower(trim(p_username)),p_password_hash,greatest(0,p_quota),
      now()+(greatest(1,p_days)||' days')::interval,upper(trim(p_prefix)),greatest(0,p_balance))
    returning * into r;
  insert into public.transactions(reseller_id,account,type,detail,amount)
    values(r.id,'admin','DAFTAR','Reseller '||r.name||' dibuat',0);
  return to_jsonb(r);
exception when unique_violation then raise exception 'reseller_exists';
end $$;
