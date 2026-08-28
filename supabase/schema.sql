-- FORGE/OS online key system
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
  check_count bigint not null default 0
);

create index if not exists keys_key_idx on public.keys(key);
create index if not exists keys_uid_idx on public.keys(uid);
create index if not exists keys_expires_idx on public.keys(expires_at);

alter table public.keys enable row level security;

-- Do not add public policies. The Vercel server uses the Supabase secret key.
