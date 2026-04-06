drop trigger  if exists on_auth_user_created on auth.users;
drop function if exists public.handle_new_user()                          cascade;
drop function if exists public.rpc_register(text,text)                    cascade;
drop function if exists public.rpc_login(text,text)                       cascade;
drop function if exists public.rpc_verify(bigint,text)                    cascade;
drop function if exists public.rpc_send_message(bigint,text,text)         cascade;
drop function if exists public.rpc_set_color(bigint,text,text)            cascade;
drop function if exists public.rpc_get_colors()                           cascade;
drop function if exists public.rpc_admin_users(bigint,text)               cascade;
drop function if exists public.rpc_admin_status(bigint,text,bigint,text)  cascade;
drop function if exists public.rpc_toggle_block(bigint,text,bigint,boolean) cascade;
drop function if exists public.rpc_delete_message(bigint,text,bigint)     cascade;
drop function if exists public.rpc_admin_messages(bigint,text)            cascade;
drop function if exists public.rpc_delete_user(bigint,text,bigint)        cascade;
drop function if exists public.rpc_delete_user_messages(bigint,text,text) cascade;
drop function if exists public.rpc_clear_chat(bigint,text)                cascade;
drop function if exists public.rpc_admin_stats(bigint,text)               cascade;
drop function if exists public.rpc_admin_set_color(bigint,text,bigint,text) cascade;
drop table    if exists public.messages cascade;
drop table    if exists public.users    cascade;

create table public.users (
  id                 bigserial primary key,
  username           text unique not null,
  password_hash      text not null,
  session_token      text,
  session_expires_at timestamptz,
  status             text not null default 'pending' check (status in ('pending','approved','rejected')),
  is_admin           boolean not null default false,
  is_blocked         boolean not null default false,
  chat_color         text default null,
  created_at         timestamptz not null default now()
);

create table public.messages (
  id         bigserial primary key,
  user_id    bigint references public.users(id) on delete set null,
  username   text not null,
  content    text not null,
  created_at timestamptz not null default now()
);

alter table public.users    enable row level security;
alter table public.messages enable row level security;

grant usage  on schema public to anon;
grant insert on public.users to anon;
grant select on public.messages to anon;
grant usage  on sequence public.users_id_seq to anon;

create policy "only_insert"   on public.users    for insert to anon with check (true);
create policy "read_messages" on public.messages for select to anon using (true);

alter publication supabase_realtime add table public.messages;

create or replace function public.rpc_register(p_username text, p_hash text)
returns text language plpgsql security definer set search_path = public as $$
begin
  if exists (select 1 from public.users where username = p_username) then
    return 'username_taken';
  end if;
  insert into public.users (username, password_hash) values (p_username, p_hash);
  return 'ok';
end; $$;
grant execute on function public.rpc_register(text,text) to anon;

create or replace function public.rpc_login(p_username text, p_hash text)
returns json language plpgsql security definer set search_path = public as $$
declare v public.users; tok text;
begin
  select * into v from public.users where username = p_username and password_hash = p_hash;
  if not found then return json_build_object('error','invalid'); end if;
  tok := gen_random_uuid()::text;
  update public.users set session_token = tok, session_expires_at = now() + interval '7 days' where id = v.id;
  return json_build_object('id',v.id,'username',v.username,'status',v.status,
    'is_admin',v.is_admin,'is_blocked',v.is_blocked,'chat_color',v.chat_color,'token',tok);
end; $$;
grant execute on function public.rpc_login(text,text) to anon;

create or replace function public.rpc_verify(p_id bigint, p_token text)
returns json language plpgsql security definer set search_path = public as $$
declare v public.users;
begin
  select * into v from public.users
  where id = p_id and session_token = p_token
  and (session_expires_at is null or session_expires_at > now());
  if not found then return json_build_object('valid',false); end if;
  return json_build_object('valid',true,'username',v.username,'status',v.status,
    'is_admin',v.is_admin,'is_blocked',v.is_blocked,'chat_color',v.chat_color);
end; $$;
grant execute on function public.rpc_verify(bigint,text) to anon;

create or replace function public.rpc_send_message(p_id bigint, p_token text, p_content text)
returns json language plpgsql security definer set search_path = public as $$
declare v public.users;
begin
  select * into v from public.users
  where id = p_id and session_token = p_token and status = 'approved' and is_blocked = false
  and (session_expires_at is null or session_expires_at > now());
  if not found then return json_build_object('error','unauthorized'); end if;
  if length(trim(p_content)) = 0   then return json_build_object('error','empty'); end if;
  if length(trim(p_content)) > 280 then return json_build_object('error','too_long'); end if;
  insert into public.messages (user_id, username, content) values (v.id, v.username, trim(p_content));
  return json_build_object('ok',true);
end; $$;
grant execute on function public.rpc_send_message(bigint,text,text) to anon;

create or replace function public.rpc_get_colors()
returns json language plpgsql security definer set search_path = public as $$
begin
  return (
    select coalesce(json_agg(json_build_object('u',username,'c',chat_color)),'[]'::json)
    from public.users where chat_color is not null
  );
end; $$;
grant execute on function public.rpc_get_colors() to anon;

create or replace function public.rpc_admin_users(p_id bigint, p_token text)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.users where id=p_id and session_token=p_token and is_admin=true) then
    return json_build_object('error','unauthorized');
  end if;
  return (select coalesce(json_agg(json_build_object(
    'id',id,'username',username,'status',status,'is_admin',is_admin,
    'is_blocked',is_blocked,'chat_color',chat_color,'created_at',created_at
  ) order by created_at desc),'[]'::json) from public.users);
end; $$;
grant execute on function public.rpc_admin_users(bigint,text) to anon;

create or replace function public.rpc_admin_status(p_id bigint, p_token text, p_target bigint, p_status text)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.users where id=p_id and session_token=p_token and is_admin=true) then
    return json_build_object('error','unauthorized');
  end if;
  update public.users set status = p_status where id = p_target;
  return json_build_object('ok',true);
end; $$;
grant execute on function public.rpc_admin_status(bigint,text,bigint,text) to anon;

create or replace function public.rpc_toggle_block(p_id bigint, p_token text, p_target bigint, p_blocked boolean)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.users where id=p_id and session_token=p_token and is_admin=true) then
    return json_build_object('error','unauthorized');
  end if;
  update public.users set is_blocked = p_blocked where id = p_target;
  return json_build_object('ok',true);
end; $$;
grant execute on function public.rpc_toggle_block(bigint,text,bigint,boolean) to anon;

create or replace function public.rpc_delete_user(p_id bigint, p_token text, p_target bigint)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.users where id=p_id and session_token=p_token and is_admin=true) then
    return json_build_object('error','unauthorized');
  end if;
  if p_target = p_id then return json_build_object('error','cannot_delete_self'); end if;
  delete from public.users where id = p_target;
  return json_build_object('ok',true);
end; $$;
grant execute on function public.rpc_delete_user(bigint,text,bigint) to anon;

create or replace function public.rpc_admin_messages(p_id bigint, p_token text)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.users where id=p_id and session_token=p_token and is_admin=true) then
    return json_build_object('error','unauthorized');
  end if;
  return (select coalesce(json_agg(json_build_object(
    'id',id,'username',username,'content',content,'created_at',created_at
  ) order by created_at desc),'[]'::json)
  from (select * from public.messages order by created_at desc limit 100) s);
end; $$;
grant execute on function public.rpc_admin_messages(bigint,text) to anon;

create or replace function public.rpc_delete_message(p_id bigint, p_token text, p_msg_id bigint)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.users where id=p_id and session_token=p_token and is_admin=true) then
    return json_build_object('error','unauthorized');
  end if;
  delete from public.messages where id = p_msg_id;
  return json_build_object('ok',true);
end; $$;
grant execute on function public.rpc_delete_message(bigint,text,bigint) to anon;

create or replace function public.rpc_delete_user_messages(p_id bigint, p_token text, p_username text)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.users where id=p_id and session_token=p_token and is_admin=true) then
    return json_build_object('error','unauthorized');
  end if;
  delete from public.messages where username = p_username;
  return json_build_object('ok',true);
end; $$;
grant execute on function public.rpc_delete_user_messages(bigint,text,text) to anon;

create or replace function public.rpc_clear_chat(p_id bigint, p_token text)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.users where id=p_id and session_token=p_token and is_admin=true) then
    return json_build_object('error','unauthorized');
  end if;
  delete from public.messages;
  return json_build_object('ok',true);
end; $$;
grant execute on function public.rpc_clear_chat(bigint,text) to anon;

create or replace function public.rpc_admin_stats(p_id bigint, p_token text)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.users where id=p_id and session_token=p_token and is_admin=true) then
    return json_build_object('error','unauthorized');
  end if;
  return json_build_object(
    'total_users',    (select count(*) from public.users),
    'pending',        (select count(*) from public.users where status='pending'),
    'approved',       (select count(*) from public.users where status='approved'),
    'blocked',        (select count(*) from public.users where is_blocked=true),
    'total_messages', (select count(*) from public.messages)
  );
end; $$;
grant execute on function public.rpc_admin_stats(bigint,text) to anon;

create or replace function public.rpc_admin_set_color(p_id bigint, p_token text, p_target bigint, p_color text)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.users where id=p_id and session_token=p_token and is_admin=true) then
    return json_build_object('error','unauthorized');
  end if;
  update public.users set chat_color = p_color where id = p_target;
  return json_build_object('ok',true);
end; $$;
grant execute on function public.rpc_admin_set_color(bigint,text,bigint,text) to anon;

notify pgrst, 'reload schema';

-- Apos criar sua conta, rode isso separado para virar admin:
-- update public.users set is_admin=true, status='approved' where username='SEU_NOME';
