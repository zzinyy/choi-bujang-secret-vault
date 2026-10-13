
-- Stage 8: Instructor announcements
-- Keep the existing notes table unchanged.
-- Execute only after reviewing the schema and permissions.

begin;

-- 1. Create a separate announcements table.
create table if not exists public.announcements (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  content text not null,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint announcements_title_not_empty
    check (length(btrim(title)) > 0),

  constraint announcements_content_not_empty
    check (length(btrim(content)) > 0)
);

-- 2. Enable row-level security.
alter table public.announcements
  enable row level security;

-- 3. Block direct access from browser-facing roles.
revoke all on table public.announcements from public;
revoke all on table public.announcements from anon;
revoke all on table public.announcements from authenticated;

-- 4. No student INSERT, UPDATE or DELETE policies.
-- Instructor authorization must be verified by the server
-- using a trusted, server-controlled role assignment.
-- Never trust a role supplied in the request body.

-- 5. Index for listing announcements.
create index if not exists announcements_created_at_idx
  on public.announcements (created_at desc);

commit;
