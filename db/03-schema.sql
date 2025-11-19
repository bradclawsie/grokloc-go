-- shared functions
create or replace function unixtime()
returns bigint as $unixtime$
begin
  return floor(extract(epoch from now()));
end;
$unixtime$ language plpgsql
stable;

-- tables
--
-- audit_log
create table if not exists audit_log (
  -- our columns
  audit_table text not null,
  audit_id uuid not null,
  audit_column text not null,
  old_mtime bigint not null,
  new_mtime bigint not null,
  old_signature uuid unique not null,
  new_signature uuid unique not null,
  details jsonb not null,
  -- model base
  insert_order bigint generated always as identity unique,
  ctime bigint default unixtime(),
  -- attributes
  primary key(new_signature));

-- orgs
create table if not exists orgs (
  -- our columns
  name text unique not null check (name != ''),
  owner uuid not null check (owner != '00000000-0000-0000-0000-000000000000'),
  -- model base
  id uuid unique not null default gen_random_uuid() check (id != '00000000-0000-0000-0000-000000000000'),
  insert_order bigint generated always as identity unique,
  schema_version bigint not null default 0 check (schema_version >= 0 and schema_version <= 99999),
  status bigint not null check (status > 0 and status < 4),
  ctime bigint not null default unixtime(),
  mtime bigint not null default unixtime(),
  signature uuid unique not null default gen_random_uuid(),
  role bigint not null check (role > 0 and role < 4),
  -- attributes
  primary key (id));

-- repositories
create table if not exists repositories (
  -- our columns
  name text not null check (name != ''),
  org uuid not null check (org != '00000000-0000-0000-0000-000000000000'),
  owner uuid not null check (owner != '00000000-0000-0000-0000-000000000000'),
  path text not null check (path != ''),
  -- model base
  id uuid unique not null default gen_random_uuid() check (id != '00000000-0000-0000-0000-000000000000'),
  insert_order bigint generated always as identity unique,
  schema_version bigint not null default 0 check (schema_version >= 0 and schema_version <= 99999),
  status bigint not null check (status > 0 and status < 4),
  ctime bigint not null default unixtime(),
  mtime bigint not null default unixtime(),
  signature uuid unique not null default gen_random_uuid(),
  role bigint not null check (role > 0 and role < 4),
  -- attributes
  primary key (id));
  -- indexes
  create unique index if not exists repositories_name_owner on repositories (name, owner);

-- users
create table if not exists users (
  -- our columns
  ed25519_public text not null check (ed25519_public != ''),
  ed25519_public_digest text unique not null check (ed25519_public_digest != ''),
  display_name text not null check (display_name != ''),
  display_name_digest text not null check (display_name_digest != ''),
  email text not null check (email != ''),
  email_digest text not null check (email_digest != ''),
  key_version uuid not null,
  org uuid not null check (org != '00000000-0000-0000-0000-000000000000'),
  password text not null check (password != ''),
  -- model base
  id uuid unique not null default gen_random_uuid() check (id != '00000000-0000-0000-0000-000000000000'),
  insert_order bigint generated always as identity unique,
  schema_version bigint not null default 0 check (schema_version >= 0 and schema_version <= 99999),
  status bigint not null check (status > 0 and status < 4),
  ctime bigint not null default unixtime(),
  mtime bigint not null default unixtime(),
  signature uuid unique not null default gen_random_uuid(),
  role bigint not null check (role > 0 and role < 4),
  -- attributes
  primary key (id));
  --indexes
  create unique index if not exists users_email_digest_org on users (email_digest, org);

-- triggers
create or replace function metadata_update()
returns trigger
as $metadata_update$
declare
_new record;
begin
  _new := new;
  _new."mtime" = unixtime();
  _new."signature" = gen_random_uuid();
  return _new;
end;
$metadata_update$ language plpgsql;

create trigger update_users
before update on users
for each row
execute procedure metadata_update();

create trigger update_orgs
before update on orgs
for each row
execute procedure metadata_update();

create trigger update_repositories
before update on repositories
for each row
execute procedure metadata_update();

create or replace function orgs_audit_update()
returns trigger
as $orgs_audit_update$
begin
  if old.owner is distinct from new.owner then
    insert into audit_log (
      audit_table,
      audit_id,
      audit_column,
      old_mtime,
      new_mtime,
      old_signature,
      new_signature,
      details
    )
    values (
      'orgs',
      old.id,
      'owner',
      old.mtime,
      new.mtime,
      old.signature,
      new.signature,
      jsonb_build_object('old', old.owner, 'new', new.owner)
    );
  end if;

  if old.status is distinct from new.status then
    insert into audit_log (
      audit_table,
      audit_id,
      audit_column,
      old_mtime,
      new_mtime,
      old_signature,
      new_signature,
      details
    )
    values (
      'orgs',
      old.id,
      'status',
      old.mtime,
      new.mtime,
      old.signature,
      new.signature,
      jsonb_build_object('old', old.status, 'new', new.status)
    );
  end if;

  return new;
end;
$orgs_audit_update$ language plpgsql;

create trigger orgs_audit_update
after update on orgs
for each row
execute procedure orgs_audit_update();

create or replace function users_audit_update()
returns trigger
as $users_audit_update$
begin
  if old.ed25519_public_digest is distinct from new.ed25519_public_digest then
    insert into audit_log (
      audit_table,
      audit_id,
      audit_column,
      old_mtime,
      new_mtime,
      old_signature,
      new_signature,
      details
    )
    values (
      'users',
      old.id,
      'ed25519_public_digest',
      old.mtime,
      new.mtime,
      old.signature,
      new.signature,
      jsonb_build_object('old', old.ed25519_public_digest, 'new', new.ed25519_public_digest)
    );
  end if;

  if old.display_name_digest is distinct from new.display_name_digest then
    insert into audit_log (
      audit_table,
      audit_id,
      audit_column,
      old_mtime,
      new_mtime,
      old_signature,
      new_signature,
      details
    )
    values (
      'users',
      old.id,
      'display_name_digest',
      old.mtime,
      new.mtime,
      old.signature,
      new.signature,
      jsonb_build_object('old', old.display_name_digest, 'new', new.display_name_digest)
    );
  end if;

  if old.key_version is distinct from new.key_version then
    insert into audit_log (
      audit_table,
      audit_id,
      audit_column,
      old_mtime,
      new_mtime,
      old_signature,
      new_signature,
      details
    )
    values (
      'users',
      old.id,
      'key_version',
      old.mtime,
      new.mtime,
      old.signature,
      new.signature,
      jsonb_build_object('old', old.key_version, 'new', new.key_version)
    );
  end if;

  if old.password is distinct from new.password then
    insert into audit_log (
      audit_table,
      audit_id,
      audit_column,
      old_mtime,
      new_mtime,
      old_signature,
      new_signature,
      details
    )
    values (
      'users',
      old.id,
      'password',
      old.mtime,
      new.mtime,
      old.signature,
      new.signature,
      jsonb_build_object('old', old.password, 'new', new.password)
    );
  end if;

  if old.status is distinct from new.status then
    insert into audit_log (
      audit_table,
      audit_id,
      audit_column,
      old_mtime,
      new_mtime,
      old_signature,
      new_signature,
      details
    )
    values (
      'users',
      old.id,
      'status',
      old.mtime,
      new.mtime,
      old.signature,
      new.signature,
      jsonb_build_object('old', old.status, 'new', new.status)
    );
  end if;

  return new;
end;
$users_audit_update$ language plpgsql;

create trigger users_audit_update
after update on users
for each row
execute procedure users_audit_update();

