
-- Stage 8: Server-controlled instructor authorization
-- Keep existing notes and announcements unchanged.

begin;

-- 1. Store instructor membership separately from user input.
create table if not exists public.instructor_roles (
  user_id uuid primary key references auth.users(id)
    on delete cascade,
  granted_at timestamptz not null default now()
);

-- 2. Enable row-level security.
alter table public.instructor_roles
  enable row level security;

-- 3. Restrict direct access from browser-facing roles.
revoke all on table public.instructor_roles from public;
revoke all on table public.instructor_roles from anon;
revoke all on table public.instructor_roles from authenticated;

-- 4. No client-accessible policies are created.
-- Only trusted server-side administrative access
-- may manage or check instructor membership.

commit;
