begin;

create table if not exists public.stage11_devices (
  id uuid primary key default gen_random_uuid(),

  owner_id uuid not null
    references auth.users(id) on delete cascade,

  public_key_jwk jsonb not null,

  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected', 'revoked')),

  created_at timestamptz not null default now(),
  approved_at timestamptz,

  constraint stage11_device_key_is_object
    check (jsonb_typeof(public_key_jwk) = 'object')
);

create index if not exists stage11_devices_owner_idx
  on public.stage11_devices(owner_id);

alter table public.stage11_devices
  enable row level security;

revoke all on table public.stage11_devices from public;
revoke all on table public.stage11_devices from anon;
revoke all on table public.stage11_devices from authenticated;

commit;

-- Prevent replay of previously signed device requests.
create table if not exists public.stage11_device_nonces (
  device_id uuid not null
    references public.stage11_devices(id) on delete cascade,

  nonce text not null,

  created_at timestamptz not null default now(),

  primary key (device_id, nonce),

  constraint stage11_nonce_length
    check (length(nonce) between 16 and 128)
);

create index if not exists stage11_device_nonces_created_idx
  on public.stage11_device_nonces(created_at);

alter table public.stage11_device_nonces
  enable row level security;

revoke all on table public.stage11_device_nonces from public;
revoke all on table public.stage11_device_nonces from anon;
revoke all on table public.stage11_device_nonces from authenticated;