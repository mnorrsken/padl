#!/bin/sh
# Bring up the eDirectory half of the lab.
#
# eDirectory is not in dev/docker-compose.yml because there is no public image
# for it: the one you have is licensed to you and must not end up in this
# repository. The image name and the tree password come from dev/edir.env, which
# is gitignored — see dev/edir.env.example.
#
# Without that file this exits quietly and successfully, so `make lab-profiles`
# still brings up everything else.
set -e

here=$(dirname "$0")
if [ -f "$here/edir.env" ]; then
	set -a
	. "$here/edir.env"
	set +a
fi

container=padl-lab-edir

running() {
	[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ]
}

# An eDirectory started by hand from docs/manual-tests.md uses the same ports,
# and configuring a tree takes minutes. Use whatever is already there rather
# than colliding with it.
if running "$container"; then
	echo "edirectory: $container is already running"
	exit 0
fi
if running padl-edir; then
	echo "edirectory: using the padl-edir container you started by hand"
	exit 0
fi

if [ -z "$PADL_EDIR_IMAGE" ] || [ -z "$PADL_EDIR_PASSWORD" ]; then
	echo "edirectory: not configured, leaving it out"
	echo "            cp dev/edir.env.example dev/edir.env and fill it in to include it"
	exit 0
fi

base=${PADL_EDIR_BASE_DN:-o=padl}
bind_dn=${PADL_EDIR_BIND_DN:-cn=admin,$base}
tree=${PADL_EDIR_TREE:-PADLTREE}
server=${PADL_EDIR_SERVER:-edir1}
ldap_port=${PADL_EDIR_LDAP_PORT:-13391}
ldaps_port=${PADL_EDIR_LDAPS_PORT:-13637}

# ndsconfig wants the dotted form of the administrator, with a "." where LDAP
# would put a ",". Getting this wrong fails minutes into the configure step with
# "illegal ds name", which is a long way to go for a typo.
admin_dotted=$(printf '%s' "$bind_dn" | tr ',' '.')

echo "edirectory: configuring a tree in $container — this takes a few minutes"
docker rm -f "$container" >/dev/null 2>&1 || true
docker run -d --name "$container" \
	-p "$ldap_port:389" -p "$ldaps_port:636" \
	"$PADL_EDIR_IMAGE" \
	new -t "$tree" -n "$base" -S "$server" \
	-a "$admin_dotted" -w "$PADL_EDIR_PASSWORD" \
	-i -B 127.0.0.1@524 -L 389 -l 636 --configure-eba-now no >/dev/null

# The first configure is slow, and slower still under emulation on an image
# built for another architecture. Wait rather than hand back a tree that is not
# there yet, but do not wait forever.
echo -n "edirectory: waiting for the tree"
i=0
while :; do
	if docker logs "$container" 2>&1 | grep -qi "successfully configured"; then
		echo " — ready on ldaps://127.0.0.1:$ldaps_port"
		exit 0
	fi
	if ! running "$container"; then
		echo
		echo "edirectory: the container stopped; docker logs $container" >&2
		exit 1
	fi
	i=$((i + 1))
	if [ "$i" -gt 120 ]; then
		echo
		echo "edirectory: still not configured after 10 minutes; docker logs -f $container" >&2
		exit 1
	fi
	echo -n "."
	sleep 5
done
