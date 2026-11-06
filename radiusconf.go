package main

import (
	"os"
	"path/filepath"
)

// A compact RADIUS dictionary: the standard attributes the panel uses plus the
// Microsoft vendor attributes needed for MS-CHAPv2. Used by pppd's radius plugin and radcli.
const radDictionary = `ATTRIBUTE	User-Name	1	string
ATTRIBUTE	User-Password	2	string
ATTRIBUTE	CHAP-Password	3	string
ATTRIBUTE	NAS-IP-Address	4	ipaddr
ATTRIBUTE	NAS-Port	5	integer
ATTRIBUTE	Service-Type	6	integer
ATTRIBUTE	Framed-Protocol	7	integer
ATTRIBUTE	Framed-IP-Address	8	ipaddr
ATTRIBUTE	Framed-IP-Netmask	9	ipaddr
ATTRIBUTE	Framed-Routing	10	integer
ATTRIBUTE	Filter-Id	11	string
ATTRIBUTE	Framed-MTU	12	integer
ATTRIBUTE	Framed-Compression	13	integer
ATTRIBUTE	Reply-Message	18	string
ATTRIBUTE	State	24	string
ATTRIBUTE	Class	25	string
ATTRIBUTE	Vendor-Specific	26	string
ATTRIBUTE	Session-Timeout	27	integer
ATTRIBUTE	Idle-Timeout	28	integer
ATTRIBUTE	Called-Station-Id	30	string
ATTRIBUTE	Calling-Station-Id	31	string
ATTRIBUTE	NAS-Identifier	32	string
ATTRIBUTE	Acct-Status-Type	40	integer
ATTRIBUTE	Acct-Delay-Time	41	integer
ATTRIBUTE	Acct-Input-Octets	42	integer
ATTRIBUTE	Acct-Output-Octets	43	integer
ATTRIBUTE	Acct-Session-Id	44	string
ATTRIBUTE	Acct-Authentic	45	integer
ATTRIBUTE	Acct-Session-Time	46	integer
ATTRIBUTE	Acct-Input-Packets	47	integer
ATTRIBUTE	Acct-Output-Packets	48	integer
ATTRIBUTE	Acct-Terminate-Cause	49	integer
ATTRIBUTE	Acct-Input-Gigawords	52	integer
ATTRIBUTE	Acct-Output-Gigawords	53	integer
ATTRIBUTE	Event-Timestamp	55	integer
ATTRIBUTE	CHAP-Challenge	60	string
ATTRIBUTE	NAS-Port-Type	61	integer
ATTRIBUTE	Acct-Interim-Interval	85	integer
ATTRIBUTE	NAS-Port-Id	87	string
ATTRIBUTE	Message-Authenticator	80	string

VALUE	Service-Type	Login-User	1
VALUE	Service-Type	Framed-User	2
VALUE	Framed-Protocol	PPP	1
VALUE	Acct-Status-Type	Start	1
VALUE	Acct-Status-Type	Stop	2
VALUE	Acct-Status-Type	Interim-Update	3
VALUE	Acct-Status-Type	Accounting-On	7
VALUE	Acct-Status-Type	Accounting-Off	8
VALUE	NAS-Port-Type	Async	0
VALUE	NAS-Port-Type	Virtual	5
VALUE	Acct-Authentic	RADIUS	1

VENDOR	Microsoft	311
ATTRIBUTE	MS-CHAP-Response	1	string	Microsoft
ATTRIBUTE	MS-CHAP-Error	2	string	Microsoft
ATTRIBUTE	MS-CHAP-CPW-1	3	string	Microsoft
ATTRIBUTE	MS-CHAP-CPW-2	4	string	Microsoft
ATTRIBUTE	MS-CHAP-LM-Enc-PW	5	string	Microsoft
ATTRIBUTE	MS-CHAP-NT-Enc-PW	6	string	Microsoft
ATTRIBUTE	MS-MPPE-Encryption-Policy	7	string	Microsoft
ATTRIBUTE	MS-MPPE-Encryption-Types	8	string	Microsoft
ATTRIBUTE	MS-RAS-Vendor	9	integer	Microsoft
ATTRIBUTE	MS-CHAP-Domain	10	string	Microsoft
ATTRIBUTE	MS-CHAP-Challenge	11	string	Microsoft
ATTRIBUTE	MS-CHAP-MPPE-Keys	12	string	Microsoft
ATTRIBUTE	MS-MPPE-Send-Key	16	string	Microsoft
ATTRIBUTE	MS-MPPE-Recv-Key	17	string	Microsoft
ATTRIBUTE	MS-CHAP2-Response	25	string	Microsoft
ATTRIBUTE	MS-CHAP2-Success	26	string	Microsoft
ATTRIBUTE	MS-Primary-DNS-Server	28	ipaddr	Microsoft
ATTRIBUTE	MS-Secondary-DNS-Server	29	ipaddr	Microsoft
`

// writeRadiusClient writes a radiusclient/radcli config that points a daemon at the
// panel's RADIUS server. pppd's plugin spells the identifier key nas_identifier,
// radcli (ocserv) spells it nas-identifier.
func writeRadiusClient(dir, secret, nasID string, radcli bool) (conf string, err error) {
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	writeIfChanged(filepath.Join(dir, "dictionary"), radDictionary, 0o644)
	writeIfChanged(filepath.Join(dir, "servers"), "127.0.0.1\t"+secret+"\n", 0o600)
	key := "nas_identifier"
	if radcli {
		key = "nas-identifier"
	}
	body := "auth_order\tradius\nlogin_tries\t4\nlogin_timeout\t60\n" +
		"authserver\t127.0.0.1:1812\nacctserver\t127.0.0.1:1813\n" +
		"servers\t" + filepath.Join(dir, "servers") + "\n" +
		"dictionary\t" + filepath.Join(dir, "dictionary") + "\n" +
		"seqfile\t" + filepath.Join(dir, "radius.seq") + "\n" +
		"mapfile\t" + filepath.Join(dir, "port-id-map") + "\n" +
		"default_realm\nradius_timeout\t3\nradius_retries\t2\nradius_deadtime\t0\n" +
		key + "\t" + nasID + "\nbindaddr\t*\n"
	conf = filepath.Join(dir, "radiusclient.conf")
	writeIfChanged(conf, body, 0o600)
	return
}
