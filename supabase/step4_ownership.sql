begin;

alter table public.notes enable row level security;

revoke all on table public.notes from public;
revoke all on table public.notes from anon;
revoke all on table public.notes from authenticated;

grant select, insert, update, delete
on table public.notes
to authenticated;

drop policy if exists "notes_select_own" on public.notes;
drop policy if exists "notes_insert_own" on public.notes;
drop policy if exists "notes_update_own" on public.notes;
drop policy if exists "notes_delete_own" on public.notes;

create policy "notes_select_own"
on public.notes
for select
to authenticated
using (auth.uid() = owner_id);

create policy "notes_insert_own"
on public.notes
for insert
to authenticated
with check (auth.uid() = owner_id);

create policy "notes_update_own"
on public.notes
for update
to authenticated
using (auth.uid() = owner_id)
with check (auth.uid() = owner_id);

create policy "notes_delete_own"
on public.notes
for delete
to authenticated
using (auth.uid() = owner_id);

commit;