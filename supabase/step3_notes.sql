-- BYTE BACK 방어전 3단계
-- 기존 가상 메모를 유지하면서 notes.id를 UUID로 전환합니다.

begin;

alter table public.notes
  add column new_id uuid default gen_random_uuid();

update public.notes
set new_id = gen_random_uuid()
where new_id is null;

alter table public.notes
  drop constraint notes_pkey;

alter table public.notes
  drop column id;

alter table public.notes
  rename column new_id to id;

alter table public.notes
  alter column id set not null;

alter table public.notes
  alter column id set default gen_random_uuid();

alter table public.notes
  add constraint notes_pkey primary key (id);

commit;