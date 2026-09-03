package ldapx

import (
	"fmt"
	"strconv"
	"strings"
)

// Active Directory and Exchange attribute rendering.
//
// Everything here is decoded, not guessed: the flag words and enumerations come
// from Microsoft's own schema documentation, and the shapes were checked against
// the domain controller in dev/docker-compose.yml — which is where the signed
// flag words below came from, because that is not something documentation says
// out loud.

// uacFlags are the userAccountControl bits. Naming them matters because "512"
// versus "514" is the difference between an account that works and one that is
// disabled, and nobody reads that from the number.
var uacFlags = []flag{
	{0x0000001, "SCRIPT"},
	{0x0000002, "ACCOUNTDISABLE"},
	{0x0000008, "HOMEDIR_REQUIRED"},
	{0x0000010, "LOCKOUT"},
	{0x0000020, "PASSWD_NOTREQD"},
	{0x0000040, "PASSWD_CANT_CHANGE"},
	{0x0000080, "ENCRYPTED_TEXT_PWD_ALLOWED"},
	{0x0000100, "TEMP_DUPLICATE_ACCOUNT"},
	{0x0000200, "NORMAL_ACCOUNT"},
	{0x0000800, "INTERDOMAIN_TRUST_ACCOUNT"},
	{0x0001000, "WORKSTATION_TRUST_ACCOUNT"},
	{0x0002000, "SERVER_TRUST_ACCOUNT"},
	{0x0010000, "DONT_EXPIRE_PASSWORD"},
	{0x0020000, "MNS_LOGON_ACCOUNT"},
	{0x0040000, "SMARTCARD_REQUIRED"},
	{0x0080000, "TRUSTED_FOR_DELEGATION"},
	{0x0100000, "NOT_DELEGATED"},
	{0x0200000, "USE_DES_KEY_ONLY"},
	{0x0400000, "DONT_REQ_PREAUTH"},
	{0x0800000, "PASSWORD_EXPIRED"},
	{0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"},
	{0x4000000, "PARTIAL_SECRETS_ACCOUNT"},
}

// groupTypeFlags decide what a group actually is. The lab's global security
// group reports -2147483646, which is 0x80000002: SECURITY_ENABLED and GLOBAL.
var groupTypeFlags = []flag{
	{0x00000001, "SYSTEM"},
	{0x00000002, "GLOBAL"},
	{0x00000004, "DOMAIN_LOCAL"},
	{0x00000008, "UNIVERSAL"},
	{0x00000010, "APP_BASIC"},
	{0x00000020, "APP_QUERY"},
	{0x80000000, "SECURITY_ENABLED"},
}

// instanceTypeFlags say what this replica of the object is. 4 is the ordinary
// writable object; 5 adds "head of a naming context", which is what the domain
// root reports.
var instanceTypeFlags = []flag{
	{0x00000001, "NC_HEAD"},
	{0x00000002, "UNINSTANTIATED"},
	{0x00000004, "WRITABLE"},
	{0x00000008, "NC_ABOVE"},
	{0x00000010, "NC_COMING"},
	{0x00000020, "NC_GOING"},
}

// systemFlagsFlags is the union of the attribute, class and cross-reference
// meanings; the low bits mean different things depending on the object, so they
// are named for the case a browsing user is most likely to be looking at.
var systemFlagsFlags = []flag{
	{0x00000001, "NOT_REPLICATED"},
	{0x00000002, "REQ_PARTIAL_SET_MEMBER"},
	{0x00000004, "CONSTRUCTED"},
	{0x00000008, "OPERATIONAL"},
	{0x00000010, "SCHEMA_BASE_OBJECT"},
	{0x00000020, "IS_RDN"},
	{0x02000000, "DISALLOW_MOVE_ON_DELETE"},
	{0x04000000, "DOMAIN_DISALLOW_MOVE"},
	{0x08000000, "DOMAIN_DISALLOW_RENAME"},
	{0x10000000, "CONFIG_ALLOW_LIMITED_MOVE"},
	{0x20000000, "CONFIG_ALLOW_MOVE"},
	{0x40000000, "CONFIG_ALLOW_RENAME"},
	{0x80000000, "DISALLOW_DELETE"},
}

// searchFlagsFlags is the schema's per-attribute indexing and privacy settings.
var searchFlagsFlags = []flag{
	{0x0001, "INDEXED"},
	{0x0002, "INDEXED_PER_CONTAINER"},
	{0x0004, "ANR"},
	{0x0008, "PRESERVE_ON_DELETE"},
	{0x0010, "COPY_ON_DUPLICATE"},
	{0x0020, "TUPLE_INDEX"},
	{0x0040, "SUBTREE_INDEX"},
	{0x0080, "CONFIDENTIAL"},
	{0x0100, "NEVER_AUDIT_VALUE"},
	{0x0200, "RODC_FILTERED"},
}

// encryptionTypeFlags is msDS-SupportedEncryptionTypes, which is what anyone
// chasing a Kerberos etype mismatch needs to read.
var encryptionTypeFlags = []flag{
	{0x01, "DES-CBC-CRC"},
	{0x02, "DES-CBC-MD5"},
	{0x04, "RC4-HMAC"},
	{0x08, "AES128-CTS-HMAC-SHA1-96"},
	{0x10, "AES256-CTS-HMAC-SHA1-96"},
	{0x20, "AES256-CTS-HMAC-SHA1-96-SK"},
	{0x10000, "FAST-SUPPORTED"},
	{0x20000, "COMPOUND-IDENTITY-SUPPORTED"},
	{0x40000, "CLAIMS-SUPPORTED"},
	{0x80000, "RESOURCE-SID-COMPRESSION-DISABLED"},
}

// samAccountTypes distinguish a user from a computer from a group, which the
// object classes do not do as sharply as people expect.
var samAccountTypes = map[int64]string{
	0x00000000: "SAM_DOMAIN_OBJECT",
	0x10000000: "SAM_GROUP_OBJECT",
	0x10000001: "SAM_NON_SECURITY_GROUP_OBJECT",
	0x20000000: "SAM_ALIAS_OBJECT",
	0x20000001: "SAM_NON_SECURITY_ALIAS_OBJECT",
	0x30000000: "SAM_USER_OBJECT",
	0x30000001: "SAM_MACHINE_ACCOUNT",
	0x30000002: "SAM_TRUST_ACCOUNT",
	0x40000000: "SAM_APP_BASIC_GROUP",
	0x40000001: "SAM_APP_QUERY_GROUP",
}

// functionalLevels name the number in msDS-Behavior-Version and the three
// root-DSE functionality attributes.
var functionalLevels = map[int64]string{
	0:  "Windows 2000",
	1:  "Windows Server 2003 interim",
	2:  "Windows Server 2003",
	3:  "Windows Server 2008",
	4:  "Windows Server 2008 R2",
	5:  "Windows Server 2012",
	6:  "Windows Server 2012 R2",
	7:  "Windows Server 2016",
	8:  "Windows Server 2019",
	9:  "Windows Server 2022",
	10: "Windows Server 2025",
}

// wellKnownRIDs cover primaryGroupID, which is a RID rather than a DN and so
// says nothing on its own. 513 is on nearly every user in a domain.
var wellKnownRIDs = map[int64]string{
	500: "Administrator",
	501: "Guest",
	502: "krbtgt",
	512: "Domain Admins",
	513: "Domain Users",
	514: "Domain Guests",
	515: "Domain Computers",
	516: "Domain Controllers",
	517: "Cert Publishers",
	518: "Schema Admins",
	519: "Enterprise Admins",
	520: "Group Policy Creator Owners",
	521: "Read-only Domain Controllers",
	522: "Cloneable Domain Controllers",
	525: "Protected Users",
	526: "Key Admins",
	527: "Enterprise Key Admins",
	553: "RAS and IAS Servers",
}

var adRenderings = map[string]rendering{
	// Flag words.
	"useraccountcontrol":                 decodeText(bitField(uacFlags)),
	"msds-user-account-control-computed": decodeText(bitField(uacFlags)),
	"grouptype":                          decodeText(bitField(groupTypeFlags)),
	"instancetype":                       decodeText(bitField(instanceTypeFlags)),
	"systemflags":                        decodeText(bitField(systemFlagsFlags)),
	"searchflags":                        decodeText(bitField(searchFlagsFlags)),
	"msds-supportedencryptiontypes":      decodeText(bitField(encryptionTypeFlags)),
	"msds-behavior-version":              decodeText(enumeration(functionalLevels)),
	"domainfunctionality":                decodeText(enumeration(functionalLevels)),
	"forestfunctionality":                decodeText(enumeration(functionalLevels)),
	"domaincontrollerfunctionality":      decodeText(enumeration(functionalLevels)),
	"samaccounttype":                     decodeText(enumeration(samAccountTypes)),
	"primarygroupid":                     decodeText(enumeration(wellKnownRIDs)),

	// Identifiers.
	"objectguid":                    decodeBytes(formatGUID),
	"schemaidguid":                  decodeBytes(formatGUID),
	"attributesecurityguid":         decodeBytes(formatGUID),
	"invocationid":                  decodeBytes(formatGUID),
	"ms-ds-consistencyguid":         decodeBytes(formatGUID),
	"objectsid":                     decodeBytes(formatSID),
	"sidhistory":                    decodeBytes(formatSID),
	"securityidentifier":            decodeBytes(formatSID),
	"tokengroups":                   decodeBytes(formatSID),
	"tokengroupsglobalanduniversal": decodeBytes(formatSID),
	"tokengroupsnogcacceptable":     decodeBytes(formatSID),
	"msds-quotatrustee":             decodeBytes(formatSID),

	// Timestamps: FILETIME ticks since 1601, written out in decimal.
	"pwdlastset":                          decodeText(formatFiletime),
	"lastlogon":                           decodeText(formatFiletime),
	"lastlogontimestamp":                  decodeText(formatFiletime),
	"lastlogoff":                          decodeText(formatFiletime),
	"badpasswordtime":                     decodeText(formatFiletime),
	"accountexpires":                      decodeText(formatFiletime),
	"lockouttime":                         decodeText(formatFiletime),
	"creationtime":                        decodeText(formatFiletime),
	"msds-cachedmembershiptimestamp":      decodeText(formatFiletime),
	"msds-userpasswordexpirytimecomputed": decodeText(formatFiletime),
	"msds-lastsuccessfulinteractivelogontime": decodeText(formatFiletime),
	"msds-lastfailedinteractivelogontime":     decodeText(formatFiletime),
	"ms-mcs-admpwdexpirationtime":             decodeText(formatFiletime),

	// Durations: the domain password policy, stored as negative FILETIME
	// intervals.
	"maxpwdage":                     decodeText(formatFiletimeInterval),
	"minpwdage":                     decodeText(formatFiletimeInterval),
	"lockoutduration":               decodeText(formatFiletimeInterval),
	"lockoutobservationwindow":      decodeText(formatFiletimeInterval),
	"forcelogoff":                   decodeText(formatFiletimeInterval),
	"msds-lockoutduration":          decodeText(formatFiletimeInterval),
	"msds-lockoutobservationwindow": decodeText(formatFiletimeInterval),
	"msds-maximumpasswordage":       decodeText(formatFiletimeInterval),
	"msds-minimumpasswordage":       decodeText(formatFiletimeInterval),

	// generalizedTime, the other spelling AD uses.
	"whencreated":           decodeText(formatGeneralizedTime),
	"whenchanged":           decodeText(formatGeneralizedTime),
	"dscorepropagationdata": decodeText(formatGeneralizedTime),

	// Structured.
	"logonhours":     decodeBytes(formatLogonHours),
	"proxyaddresses": decodeText(formatProxyAddress),
	"targetaddress":  decodeText(formatProxyAddress),
}

// exchangeRenderings are Exchange's own, which is where a mailbox's actual type
// lives: the object classes say "user" for a room, a shared mailbox and a
// person alike.
var exchangeRenderings = map[string]rendering{
	"msexchrecipienttypedetails": decodeText(enumeration(exchangeRecipientTypeDetails)),
	"msexchrecipientdisplaytype": decodeText(enumeration(exchangeRecipientDisplayTypes)),
	"msexchremoterecipienttype":  decodeText(bitField(exchangeRemoteRecipientFlags)),
	"msexchuseraccountcontrol":   decodeText(bitField(uacFlags)),
	"msexchmailboxguid":          decodeBytes(formatGUID),
	"msexcharchiveguid":          decodeBytes(formatGUID),
	"msexchmailboxcontainerguid": decodeBytes(formatGUID),
	"msexchwhenmailboxcreated":   decodeText(formatGeneralizedTime),
}

// exchangeRecipientTypeDetails is the one that actually distinguishes a room
// from a shared mailbox from a remote one.
var exchangeRecipientTypeDetails = map[int64]string{
	1:           "UserMailbox",
	2:           "LinkedMailbox",
	4:           "SharedMailbox",
	8:           "LegacyMailbox",
	16:          "RoomMailbox",
	32:          "EquipmentMailbox",
	64:          "MailContact",
	128:         "MailUser",
	256:         "MailUniversalDistributionGroup",
	512:         "MailNonUniversalGroup",
	1024:        "MailUniversalSecurityGroup",
	2048:        "DynamicDistributionGroup",
	4096:        "PublicFolder",
	8192:        "SystemAttendantMailbox",
	16384:       "SystemMailbox",
	32768:       "MailForestContact",
	65536:       "User",
	131072:      "Contact",
	262144:      "UniversalDistributionGroup",
	524288:      "UniversalSecurityGroup",
	1048576:     "NonUniversalGroup",
	2097152:     "DisabledUser",
	4194304:     "MicrosoftExchange",
	8388608:     "ArbitrationMailbox",
	16777216:    "MailboxPlan",
	33554432:    "LinkedUser",
	268435456:   "RoomList",
	536870912:   "DiscoveryMailbox",
	1073741824:  "RoleGroup",
	2147483648:  "RemoteUserMailbox",
	8589934592:  "RemoteRoomMailbox",
	17179869184: "RemoteEquipmentMailbox",
	34359738368: "RemoteSharedMailbox",
	68719476736: "TeamMailbox",
}

var exchangeRecipientDisplayTypes = map[int64]string{
	0:           "MailboxUser",
	1:           "DistributionGroup",
	2:           "PublicFolder",
	3:           "DynamicDistributionGroup",
	4:           "Organization",
	5:           "PrivateDistributionList",
	6:           "RemoteMailUser",
	7:           "ConferenceRoomMailbox",
	8:           "EquipmentMailbox",
	10:          "ArbitrationMailbox",
	11:          "MailboxPlan",
	12:          "LinkedUser",
	15:          "RoomList",
	-2147483642: "SyncedMailboxUser",
	1073741824:  "ACLableMailboxUser",
	1073741833:  "ACLableDistributionGroup",
}

var exchangeRemoteRecipientFlags = []flag{
	{0x001, "ProvisionMailbox"},
	{0x002, "ProvisionArchive"},
	{0x004, "Migrated"},
	{0x008, "DeprovisionMailbox"},
	{0x010, "DeprovisionArchive"},
	{0x020, "RoomMailbox"},
	{0x040, "EquipmentMailbox"},
	{0x080, "SharedMailbox"},
	{0x100, "TeamMailbox"},
}

// formatProxyAddress labels an Exchange address by its prefix. The case of the
// scheme is the whole point: "SMTP:" is the primary reply address and "smtp:"
// is an alias, which is invisible unless someone says so.
//
// The address is kept as typed and the meaning appended, because this is a
// value people copy.
func formatProxyAddress(s string) (string, bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 {
		return "", false
	}
	scheme := s[:i]
	kind, ok := proxyAddressKinds[strings.ToLower(scheme)]
	if !ok {
		return "", false
	}
	if scheme == strings.ToUpper(scheme) {
		return fmt.Sprintf("%s (primary %s)", s, kind), true
	}
	return fmt.Sprintf("%s (%s alias)", s, kind), true
}

var proxyAddressKinds = map[string]string{
	"smtp":   "SMTP",
	"x400":   "X.400",
	"x500":   "X.500",
	"sip":    "SIP",
	"eum":    "voicemail",
	"notes":  "Lotus Notes",
	"msmail": "MS Mail",
	"ccmail": "cc:Mail",
}

// formatLogonHours summarises the 21-byte weekly bitmap that says when an
// account may log on. All bits set is the default and means nothing at all, so
// it is worth saying that plainly rather than dumping 168 bits.
func formatLogonHours(raw []byte) (string, bool) {
	if len(raw) != 21 {
		return "", false
	}
	allowed := 0
	for _, b := range raw {
		for bit := 0; bit < 8; bit++ {
			if b&(1<<bit) != 0 {
				allowed++
			}
		}
	}
	switch allowed {
	case 168:
		return "all hours", true
	case 0:
		return "no hours (logon blocked)", true
	}
	return strconv.Itoa(allowed) + " of 168 hours", true
}
