begin;

-- Stage 5: notes data access goes through the server API only.
-- Keep existing RLS policies, but remove direct table privileges
-- from browser-facing roles.

revoke all on table public.notes from public;
revoke all on table public.notes from anon;
revoke all on table public.notes from authenticated;

commit;