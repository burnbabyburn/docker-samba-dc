# FORKED
![Githubg Workflow Image CI](https://img.shields.io/github/workflow/status/burnbabyburn/docker-ubuntu-samba-dc/Docker%20Image%20CI)
* No OpenVPN testing
* Build test via docker actions
* Mount custom Samba [global] parameters to files in /etc/samba/smb.conf.d
* Branches:
  * Bind9	-	Bind9 with ntpd. Branched from My
  * chrony	-	chrony without Bind9. Branched from my
  * test	-	chrony and bind9 Script runs fine on alpine and ubuntu Dockerfile and compose provided
  * My => stable branch without anything of the above.

# Samba Active Directory Domain Controller for Docker

A well documented, tried and tested Samba Active Directory Domain Controller that works with the standard Windows management tools; built from scratch using internal DNS and kerberos and not based on existing containers.

## Environment variables for quick start

| ENVVAR                      | default value                                 |Pdc only| description  |
| --------------------------- | --------------------------------------------- |------------- | ------------- |
| `BIND_INTERFACES_ENABLE`    | false                                         |       | set to true to [bind](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html#BINDINTERFACESONLY) services to interfaces  |  
| `BIND_INTERFACES`           | NONE                                          |       | set [interfaces](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html#INTERFACES) name,ip.. to bind services to. See   |
| `DEBUG_ENABLE`              | false                                         |       | Enables script debug messages |
| `DEBUG_LEVEL`               | 0                                             |       | Level of debug messages from services (e.g. ntpd, samba)|
| `DISABLE_DNS_WPAD_ISATAP`   | false                                         |   X   | Create DNS records for WPAD and ISATAP pointing to localhost|
| `DISABLE_MD5`               | true                                          |       | Disable MD5 Clients (reject md5 clients) and Server (reject md5 servers) |
| `DOMAIN_ACC_LOCK_DURATION`  | 30                                            |   X   | min password length  |
| `DOMAIN_ACC_LOCK_RST_AFTER` | 30                                            |   X   | min password length  |
| `DOMAIN_ACC_LOCK_THRESHOLD` | 0                                             |   X   | min password length  |
| `DOMAIN_NETBIOS`            | SAMDOM                                        |       | WORKGROPUP/NETBIOS Domain Name usally first part of DOMAIN |
| `DOMAIN_PASS`               | youshouldsetapassword                         |       | Domain Administrator Password  |
| `DOMAIN_PWD_COMPLEXITY`     | true                                          |   X   | set to false to disable Password complexity  |
| `DOMAIN_PWD_HISTORY_LENGTH` | 24                                            |   X   | length of password history  |
| `DOMAIN_PWD_MAX_AGE`        | 43                                            |   X   | max password age in days  |
| `DOMAIN_PWD_MIN_AGE`        | 1                                             |   X   | min password age in days  |
| `DOMAIN_PWD_MIN_LENGTH`     | 7                                             |   X   | min password length  |
| `DOMAIN_PWD_ADMIN_NO_EXP`   | true                                          |   X   | If enabled Domain Admin PW will not expire. Auto set to false if FEATURE_SCHEMA_LAPS` is enabled  |
| `DOMAIN_USER`               | Administrator                                 |       | Best leave at default. unknown consequences  |
| `DOMAIN`                    | SAMDOM.LOCAL                                  |       | Your Domain Name            |
| `ENABLE_BIND9`              | false                                         |       | Enable Bind9 - Bind9 is always installed. You may enable it if you need it, otherwise internal DNS is used. INTERNAL_DNS it is not "bleeding" internal docker IPs if used behind RProxy |
| `ENABLE_CUPS`               | false                                         |       | Enable CUPS - cups is not installed but setup in smb.conf modify Dockerfile  |
| `ENABLE_DNSFORWARDER`       | NONE                                          |       | Ip of upstream dns server. If not set, no upstream dns will be avaible.  |
| `ENABLE_DYNAMIC_PORTRANGE`  | 49152-65535                                   |       | Set range of [dynamic rpc ports](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html#RPCSERVERDYNAMICPORTRANGE). Usefull on limited res. or RProxy |
| `ENABLE_INSECURE_DNSUPDATE` | false                                         |       | Enable insecure dns updates (no packet signing)  |
| `ENABLE_INSECURE_LDAP`      | false                                         |       | Enable insecure ldap connections  |
| `ENABLE_LOGS`               | false                                         |       | Enable log files - disabled. log to stdout and ship docker logs |
| `ENABLE_MSCHAPV2`           | false                                         |       | Enable MSCHAP authentication  |
| `ENABLE_RFC2307`            | true                                          |   X   | Enable RFC2307 LDAP Extension in AD |
| `ENABLE_WINS`               | false                                         |       | Enable WINS and also propagiate time server |
| `ENABLE_EVENTLOG_SAMBA`     | false                                         |       | Enable Eventlog for Samba use with ENABLE_LOGS` |
| `FEATURE_KERBEROS_TGT`      | true                                          |   X   | Feature: Change password of krbtgt user (Kerberos Ticket Granting Ticket) to prevent Golden Ticket attacks |
| `FEATURE_RECYCLEBIN`        | true                                          |   X   | Feature: Enable AD RecylceBin|
| `FEATURE_SCHEMA_LAPS`       | false                                         |   X   | Feature: Schema extension for Local Administrator Password Solution  |
| `FEATURE_SCHEMA_SSH`        | false                                         |   X   | Feature: Schema extension for SSH-Keys  |
| `FEATURE_SCHEMA_SUDO`       | false                                         |   X   | Feature: schema extension for SUDO  |
| `HOSTIPV6`                  | NONE                                          |   X   | Set external Host IPv6 if not running in network host mode. Use for splitdns. Samba will use HOSTIP and HOSTNAME to populate internal DNS |
| `HOSTIP`                    | NONE                                          |   X   | Set external Host IP if not running in network host mode. Use for splitdns. Samba will use HOSTIP and HOSTNAME to populate internal DNS |
| `HOSTNAME`                  | $(hostname)                                   |       | Hostname of Samba. Overrides you containers hostname. Only works while proivisioning a domain ! Samba will use HOSTNAME and HOSTIP to populate internal DNS |
| `JOIN_SITE_VPN`             | false                                         |       | Use openvpn config before connection to DC is possible  |
| `JOIN_SITE`                 | Default-First-Site-Name                       |       | Sitename to join to  |
| `JOIN`                      | false                                         |       | Set to true if DC should join Domain  |
| `NTPSERVERLIST`             | 0.pool.ntp.org 1.pool...                      |       | List of NTP Server  |
| `TLS_ENABLE`                | false                                         |       | Enable TLS. Samba will autogen a cert if not provided before first start  |
| `TZ`                        | /Etc/UTC                                      |       | Set Timezone and localtime. Case sensitiv.  |

## Add Reverse DNS Zone
docker exec -it samba-ad-dc "samba-tool dns zonecreate <Your-AD-DNS-Server-IP-or-hostname> <NETADDR>.in-addr.arpa -U<URDOMAIN>\administrator --password=<DOMAINPASS>"
## Add Share Privileges to DomAdmin Group - Set by default
docker exec -it samba-ad-dc "net rpc rights grant "<URDOMAIN>\Domain Admins" SeDiskOperatorPrivilege -U<URDOMAIN>\administrator --password=<DOMAINPASS> "
##Root Cert in der format (.crt) is avaible in NETLOGON share of DC

## Volumes for quick start
* `samba-data:/data` - Stores samba data so the container can be moved to another host if required.
## Downloading and building

```bash
mkdir -p /data/docker/builds
cd /data/docker/builds
git clone https://github.com/Fmstrat/samba-domain.git
cd samba-domain
docker build -t samba-domain .
```

If you plan on using a multi-site VPN, also run:

```bash
mkdir -p /data/docker/containers/samba/config/openvpn
cp /path/to/my/ovpn/MYSITE.ovpn /data/docker/containers/samba/config/openvpn/docker.ovpn
```

## Things to keep in mind
* Make sure your client's DNS is using the DC, or that your mail DNS is relaying for the domain
* Ensure client's are using corp.example.com as the search suffix