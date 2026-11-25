-- מסלול אבני בניין · מבנה מסד הנתונים (Supabase / Postgres)
-- המערכת בלמ"ס. שלבים מסווגים (cls='c') שומרים סטטוס ומצביע לרשת הסגולה בלבד, והמסד עצמו חוסם תוכן בהם.

-- ---------- צוות: רק משתמשים שמופיעים כאן רואים נתונים ----------
create table if not exists team_members (
  email        text primary key,
  display_name text not null,
  role         text not null default 'member' check (role in ('admin','member','viewer')),
  created_at   timestamptz not null default now()
);

create or replace function is_team_member() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from team_members where lower(email) = lower(auth.jwt() ->> 'email'));
$$;

create or replace function is_team_editor() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from team_members
                 where lower(email) = lower(auth.jwt() ->> 'email') and role in ('admin','member'));
$$;

-- ---------- הגדרת המתודה (ניתנת לעריכה, לא קבועה בקוד) ----------
create table if not exists phases (
  n     int primary key,
  name  text not null,
  sub   text
);

create table if not exists stages (
  id          text primary key,
  phase       int  not null references phases(n),
  ord         int  not null,
  name        text not null,
  cls         text not null check (cls in ('u','h','c')),   -- u=בלמ"ס, h=היברידי, c=מסווג
  draft       boolean not null default true,
  question    text,
  deliverable text,
  criteria    jsonb not null default '[]',
  approvals   jsonb not null default '[]',
  deps        jsonb not null default '[]',
  updated_at  timestamptz not null default now()
);

-- ---------- אבני בניין ----------
create table if not exists blocks (
  id         text primary key,
  name       text not null,
  domain     text,
  owner      text,
  trl        int check (trl between 1 and 9),
  health     text not null default 'ok' check (health in ('ok','risk','stuck')),
  summary    text,
  created_at date not null default current_date,
  updated_at timestamptz not null default now()
);

create table if not exists block_stages (
  block_id       text not null references blocks(id) on delete cascade,
  stage_id       text not null references stages(id) on delete cascade,
  status         text not null default 'todo' check (status in ('todo','active','done')),
  notes          text not null default '',
  osint          text not null default '',
  materials      jsonb not null default '[]',
  checks         jsonb not null default '{}',
  approvals      jsonb not null default '{}',
  purple_exists  boolean not null default false,
  purple_updated date,
  purple_by      text,
  updated_at     timestamptz not null default now(),
  primary key (block_id, stage_id)
);

create table if not exists updates (
  id         bigint generated always as identity primary key,
  block_id   text not null references blocks(id) on delete cascade,
  stage_id   text references stages(id),
  author     text not null,
  body       text not null,
  date       date not null default current_date,
  created_by text default (auth.jwt() ->> 'email'),
  created_at timestamptz not null default now()
);
create index if not exists updates_block_idx on updates(block_id, date desc);

-- ---------- הגנת סיווג: אין תוכן בשלבים מסווגים ----------
create or replace function guard_classified() returns trigger
language plpgsql set search_path = public as $$
declare c text;
begin
  select cls into c from stages where id = new.stage_id;
  if c = 'c' and (coalesce(new.notes,'') <> '' or coalesce(new.osint,'') <> ''
                  or new.materials <> '[]'::jsonb) then
    raise exception 'שלב מסווג: אין להזין תוכן במערכת הבלמ"ס. התוכן נשמר ברשת הסגולה בלבד.';
  end if;
  if c = 'u' and coalesce(new.osint,'') <> '' then
    new.osint := '';
  end if;
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists trg_guard_classified on block_stages;
create trigger trg_guard_classified before insert or update on block_stages
  for each row execute function guard_classified();

create or replace function touch_updated() returns trigger language plpgsql set search_path = public as $$
begin new.updated_at := now(); return new; end $$;
drop trigger if exists trg_touch_blocks on blocks;
create trigger trg_touch_blocks before update on blocks for each row execute function touch_updated();
drop trigger if exists trg_touch_stages on stages;
create trigger trg_touch_stages before update on stages for each row execute function touch_updated();

-- ---------- הרשאות (RLS) ----------
alter table team_members enable row level security;
alter table phases       enable row level security;
alter table stages       enable row level security;
alter table blocks       enable row level security;
alter table block_stages enable row level security;
alter table updates      enable row level security;

do $$
declare t text;
begin
  foreach t in array array['phases','stages','blocks','block_stages','updates'] loop
    execute format('drop policy if exists team_read on %I', t);
    execute format('drop policy if exists team_write on %I', t);
    execute format('create policy team_read on %I for select to authenticated using (is_team_member())', t);
    execute format('create policy team_write on %I for all to authenticated using (is_team_editor()) with check (is_team_editor())', t);
  end loop;
end $$;

drop policy if exists team_read on team_members;
create policy team_read on team_members for select to authenticated using (is_team_member());

-- פונקציות העזר נדרשות רק למשתמשים מחוברים
revoke execute on function public.is_team_member() from public, anon;
revoke execute on function public.is_team_editor() from public, anon;
grant execute on function public.is_team_member() to authenticated;
grant execute on function public.is_team_editor() to authenticated;
