create table if not exists public.app_state (
  id text primary key,
  revision bigint not null default 0,
  state jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.app_state enable row level security;

revoke all on public.app_state from anon, authenticated;
grant all on public.app_state to service_role;

insert into public.app_state (id, revision, state)
values ('main', 0, '{}'::jsonb)
on conflict (id) do nothing;
