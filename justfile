set shell := ["bash", "-c"]
set dotenv-load := true
set dotenv-filename := "dotenv-unit"
set dotenv-required := true

default:
    @just --list

# -- Go rules.

pkgs:
    go install golang.org/x/vuln/cmd/govulncheck@latest
    go install github.com/securego/gosec/v2/cmd/gosec@latest
    go install github.com/google/capslock/cmd/capslock@latest

# -- Database rules.

# Init db from nothing.
initdb:
    # must be run as `sudo just initdb`
    su -l postgres -c "initdb --locale=C.UTF-8 --encoding=UTF8 -D /var/lib/postgres/data --data-checksums"

# DB users.
create-users:
    sudo -u postgres psql --file=db/00-create-users.sql

# Create databases.
create-databases:
    sudo -u postgres psql --file=db/01-create-databases.sql

# Grants.
alter-grants:
    sudo -u postgres psql --dbname="test" --file=db/02-alter-grants.sql
    sudo -u postgres psql --dbname="app" --file=db/02-alter-grants.sql
    sudo -u postgres psql --dbname="grokloc" --file=db/02-alter-grants.sql

# Create schema.
apply-schema:
    psql --username="grokloc" --dbname="app" --file=db/03-schema.sql

# Truncate all tables.
truncate:
    psql --username="grokloc" --dbname="app" --file=db/04-truncate-tables.sql

# Drop all tables.
drop:
    psql --username="grokloc" --dbname="app" --file=db/05-drop-tables.sql

# Recreate everything.
recreate: drop apply-schema

# Prompt.
psql:
    @psql ${POSTGRES_APP_URL}

# Root prompt.
root_psql:
    @psql ${DATABASE_URL}

# -- CI rules.

# Set up everything for development from nothing.
setup:
    just create-users create-databases alter-grants apply-schema pkgs
