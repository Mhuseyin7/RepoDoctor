#!/bin/sh
set -eu

# Schema changes are applied before the API accepts traffic. Alembic reads the
# same REPODOCTOR_DATABASE_URL value as the application.
alembic upgrade head
exec repodoctor serve --host 0.0.0.0 --port 8000
