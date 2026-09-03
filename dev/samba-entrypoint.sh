#!/bin/sh
# The image provisions the domain and then execs samba in the foreground, which
# leaves nowhere to seed from. This runs it in the background instead, seeds the
# directory once it answers, and then waits on it so the container still lives
# and dies with samba.
#
# A failed seed is deliberately not fatal. Samba stays up so its log can be read
# with `make lab-logs`, and the marker file the seed never wrote keeps the
# healthcheck red, so the failure surfaces as a lab that will not come up rather
# than as tests failing against a half-seeded directory.
set -e

# Before anything starts: samba reads its TLS files once and keeps them, so the
# certificate has to exist before provisioning rather than be swapped after.
python3 /seed/samba-cert.py

/usr/local/bin/entrypoint.sh &
samba=$!

/seed/samba-seed.sh || echo "padl: seeding failed, the container stays unhealthy" >&2

wait $samba
