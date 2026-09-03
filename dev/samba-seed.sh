#!/bin/sh
# Seeds the throwaway Samba AD DC with the same shape as seed.ldif gives
# OpenLDAP: two containers, two people, one group, and one multi-valued
# attribute for the object pane to wrap.
#
# It runs once per container. The marker file is what makes a restart cheap and
# the healthcheck honest — no marker, no healthy container, so a seed that fails
# is reported rather than leaving a directory that is half there.
set -e

marker=/var/lib/samba/.padl-seeded
base="DC=ad,DC=example,DC=com"

[ -f "$marker" ] && exit 0

# Provisioning has finished by the time this runs, but samba still takes a few
# seconds to start listening. Anonymous root DSE reads are allowed, so this
# needs no credentials.
i=0
until ldbsearch -H ldap://localhost --scope=base -b "" defaultNamingContext >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -gt 60 ]; then
		echo "padl: samba never answered on ldap://localhost" >&2
		exit 1
	fi
	sleep 2
done

# The domain had to be provisioned with a complex password because AD insists on
# one for the administrator. Everything seeded from here shares the lab's usual
# password instead, which is what the other two containers use and what is
# bearable to type into the UI by hand.
samba-tool domain passwordsettings set --complexity=off --min-pwd-length=4 \
	--history-length=0 --max-pwd-age=0 >/dev/null

samba-tool ou create "OU=People,$base"
samba-tool ou create "OU=Groups,$base"

samba-tool user create jdoe padl-lab --userou="OU=People" \
	--given-name=John --surname=Doe --mail-address=jdoe@ad.example.com \
	--job-title="Systems Engineer" --department=Engineering
samba-tool user create asmith padl-lab --userou="OU=People" \
	--given-name=Alice --surname=Smith --mail-address=asmith@ad.example.com

samba-tool group add engineers --groupou="OU=Groups" --description="Engineering staff"
samba-tool group addmembers engineers jdoe,asmith

# mail is single-valued in Active Directory, so the second address goes where a
# real deployment puts it. proxyAddresses is in PADL's AD quick-search list too,
# which makes it worth having something in.
ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null <<EOF
dn: CN=John Doe,OU=People,$base
changetype: modify
add: proxyAddresses
proxyAddresses: SMTP:jdoe@ad.example.com
proxyAddresses: smtp:john.doe@ad.example.com
EOF

touch "$marker"
echo "padl: seeded $base"
