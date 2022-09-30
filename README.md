# FORKED
![Githubg Workflow Image CI](https://img.shields.io/github/workflow/status/burnbabyburn/docker-ubuntu-samba-dc/Docker%20Image%20CI)
* No OpenVPN testing
* Build test via docker actions
* Mount custom Samba [global] parameters to files in /etc/samba/smb.conf.d

* Branches:
  * Bind9=>Bind9 with ntpd
  * chrony=>chrony without Bind9
  * test=>chrony,bind9 - script runs fine on alpine and ubuntu Dockerfile and compose provided
  * My => stable branch without anything of the above.

# Samba Active Directory Domain Controller for Docker

A well documented, tried and tested Samba Active Directory Domain Controller that works with the standard Windows management tools; built from scratch using internal DNS and kerberos and not based on existing containers.

## Environment variables for quick start

| ENVVAR                      | default value                                 |dc only| description  |
| --------------------------- | --------------------------------------------- |------------- | ------------- |
| `BIND_INTERFACES_ENABLE`    | false                                         |       | set to true to [bind](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html#BINDINTERFACESONLY) services to interfaces  |  
| `BIND_INTERFACES`           | NONE                                          |       | set [interfaces](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html#INTERFACES) name,ip.. to bind services to. See   |
| `DEBUG_ENABLE`              | false                                         |       | Enables script debug messages |
| `DEBUG_LEVEL`               | 0                                             |       | Level of debug messages from services (e.g. ntpd, samba)|
| `DISABLE_DNS_WPAD_ISATAP`   | false                                         |   X   | Create DNS records for WPAD and ISATAP pointing to localhost|
| `DISABLE_MD5`               | true                                          |   X   | Disable MD5 Clients (reject md5 clients) and Server (reject md5 servers) |
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
| `DOMAIN_USER`               | Administrator                                 |       | Best leave at default. unknown consequences  |
| `DOMAIN`                    | SAMDOM.LOCAL                                  |       | Your Domain Name            |
| `ENABLE_CUPS`               | false                                         |       | Enable CUPS - cups is not installed but setup in smb.conf modify Dockerfile  |
| `ENABLE_DNSFORWARDER`       | NONE                                          |       | Ip of upstream dns server. If not set, no upstream dns will be avaible.  |
| `ENABLE_DYNAMIC_PORTRANGE`  | NONE                                          |       | Set range of [dynamic rpc ports](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html#RPCSERVERDYNAMICPORTRANGE). Can be usefull to limit on smaller systems, especially if behind reverse proxy (default 49152-65535) |
| `ENABLE_INSECURE_DNSUPDATE` | false                                         |       | Enable insecure dns updates (no packet signing)  |
| `ENABLE_INSECURE_LDAP`      | false                                         |       | Enable insecure ldap connections  |
| `ENABLE_LAPS_SCHEMA`        | false                                         |   X   | Setup Local Administrator Password Solution  |
| `ENABLE_LOGS`               | false                                         |       | Enable log files - disabled. log to stdout and ship docker logs |
| `ENABLE_MSCHAPV2`           | false                                         |       | Enable MSCHAP authentication  |
| `ENABLE_RFC2307`            | true                                          |   X   | Enable RFC2307 LDAP Extension in AD |
| `ENABLE_WINS`               | false                                         |   X   | Enable WINS and also propagiate time server |
| `FEATURE_KERBEROS_TGT`      | true                                          |   X   | Feature: Only activate on PDC! Change password of krbtgt user (Kerberos Ticket Granting Ticket) to prevent Golden Ticket attacks |
| `FEATURE_RECYCLEBIN`        | true                                          |   X   | Feature: Enable AD RecylceBin|
| `HOSTIPV6`                  | NONE                                          |   X   | Set external Host IPv6 if not running in network host mode. Use for splitdns. Samba will use HOSTIP and HOSTNAME to populate internal DNS |
| `HOSTIP`                    | NONE                                          |   X   | Set external Host IP if not running in network host mode. Use for splitdns. Samba will use HOSTIP and HOSTNAME to populate internal DNS |
| `HOSTNAME`                  | $(hostname)                                   |       | Hostname of Samba. Overrides you containers hostname. Only works while proivisioning a domain ! Samba will use HOSTNAME and HOSTIP to populate internal DNS |
| `JOIN_SITE_VPN`             | false                                         |       | Use openvpn config before connection to DC is possible  |
| `JOIN_SITE`                 | Default-First-Site-Name                       |       | Sitename to join to  |
| `JOIN`                      | false                                         |       | Set to true if DC should join Domain  |
| `NTPSERVERLIST`             | 0.pool.ntp.org 1.pool...                      |       | List of NTP Server  |
| `TLS_ENABLE`                | false                                         |       | Enable TLS. Samba will autogen a cert if not provided before first start  |
| `TZ`                        | /Etc/UTC                                      |       | Set Timezone and localtime. Case sensitiv.  |

## Add Reverse DNS Zone - IF $HOSTIP is set, DNS-Reverse-Zone gets created on first run. Additional subnets connected to the host are
docker exec -it samba-ad-dc "samba-tool dns zonecreate <Your-AD-DNS-Server-IP-or-hostname> <NETADDR>.in-addr.arpa -U<URDOMAIN>\administrator --password=<DOMAINPASS>"
## Add Share Privileges to DomAdmin Group - Set by default
docker exec -it samba-ad-dc "net rpc rights grant "<URDOMAIN>\Domain Admins" SeDiskOperatorPrivilege -U<URDOMAIN>\administrator --password=<DOMAINPASS> "
## Leave domain on exit of samba member
net ads leave -UAdministrator --password

##Root Cert in der format (.crt) is avaible in NETLOGON share of DC

## Volumes for quick start
* `/etc/timezone:/etc/timezone:ro` - Sets the timezone to match the host
* `/etc/localtime:/etc/localtime:ro` - Sets the timezone to match the host
* `/data/docker/containers/samba/data/:/var/lib/samba` - Stores samba data so the container can be moved to another host if required.
* `/data/docker/containers/samba/gpo/:/gpo` - Stores admx and adml GPO files which get imported to sysvol on first start.
* `/data/docker/containers/samba/config/samba:/etc/samba/external` - Stores the smb.conf so the container can be moved or updates can be easily made.
* `/data/docker/containers/samba/config/openvpn/docker.ovpn:/docker.ovpn` - Optional for connecting to another site via openvpn.
* `/data/docker/containers/samba/config/openvpn/credentials:/credentials` - Optional for connecting to another site via openvpn that requires a username/password. The format for this file should be two lines, with the username on the first, and the password on the second. Also, make sure your ovpn file contains `auth-user-pass /credentials`

## Downloading and building

```bash
mkdir -p /data/docker/builds
cd /data/docker/builds
git clone https://github.com/Fmstrat/samba-domain.git
cd samba-domain
docker build -t samba-domain .
```

Or just use the HUB:

```bash
docker pull nowsci/samba-domain
```

## Setting things up for the container

To set things up you will first want a new IP on your host machine so that ports don't conflict. A domain controller needs a lot of ports, and will likely conflict with things like dnsmasq. The below commands will do this, and set up some required folders.

```bash
ifconfig eno1:1 192.168.3.222 netmask 255.255.255.0 up
mkdir -p /data/docker/containers/samba/data
mkdir -p /data/docker/containers/samba/config/samba
```

If you plan on using a multi-site VPN, also run:

```bash
mkdir -p /data/docker/containers/samba/config/openvpn
cp /path/to/my/ovpn/MYSITE.ovpn /data/docker/containers/samba/config/openvpn/docker.ovpn
```

## Things to keep in mind

* In some cases on Windows clients, you would join with the domain of CORP, but when entering the computer domain you must enter CORP.EXAMPLE.COM. This seems to be the case when using most any samba based DC.
* Make sure your client's DNS is using the DC, or that your mail DNS is relaying for the domain
* Ensure client's are using corp.example.com as the search suffix
* If you're using a VPN, pay close attention to routes. You don't want to force all traffic through the VPN

## Enabling file sharing

While the Samba team does not recommend using a DC as a file server, it's understandable that some may wish to. Once the container is up and running and your `/data/docker/containers/samba/config/samba/smb.conf` file is set up after the first run, you can enable shares by shutting down the container, and making the following changes to the `smb.conf` file.

In the `[global]` section, add:

```conf
        security = user
        passdb backend = ldapsam:ldap://localhost
        ldap suffix = dc=corp,dc=example,dc=com
        ldap user suffix = ou=Users
        ldap group suffix = ou=Groups
        ldap machine suffix = ou=Computers
        ldap idmap suffix = ou=Idmap
        ldap admin dn = cn=Administrator,cn=Users,dc=corp,dc=example,dc=com
        ldap ssl = off
        ldap passwd sync = no
        server string = MYSERVERHOSTNAME
        wins support = yes
        preserve case = yes
        short preserve case = yes
        default case = lower
        case sensitive = auto
        preferred master = yes
        unix extensions = yes
        follow symlinks = yes
        client ntlmv2 auth = yes
        client lanman auth = yes
        mangled names = no
```

Then add a share to the end based on how you mount the volume:

```conf
[storage]
        comment = storage
        path = /storage
        public = no
        read only = no
        writable = yes
        write list = @root NOWSCI\myuser
        force user = root
        force group = root
        guest ok = yes
        valid users = NOWSCI\myuser
```

Check the samba documentation for how to allow groups/etc.

## Keeping things updated

The container is stateless, so you can do a `docker rmi samba-domain` and then restart the container to rebuild packages when a security update occurs. However, this puts load on servers that isn't always required, so below are some scripts that can help minimize things by letting you know when containers have security updates that are required.

This script loops through running containers and sends you an email when security updates are required.

```bash
#!/bin/bash


function needsUpdates() {
        RESULT=$(docker exec ${1} bash -c ' \
                if [[ -f /etc/apt/sources.list ]]; then \
                grep security /etc/apt/sources.list > /tmp/security.list; \
                apt-get update > /dev/null; \
                apt-get upgrade -oDir::Etc::Sourcelist=/tmp/security.list -s; \
                fi; \
                ')
        RESULT=$(echo $RESULT)
        GOODRESULT="Reading package lists... Building dependency tree... Reading state information... Calculating upgrade... 0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."
        if [[ "${RESULT}" != "" ]] && [[ "${RESULT}" != "${GOODRESULT}" ]]; then
                return 0
        else
                return 1
        fi
}

function sendEmail() {
        echo "Container ${1} needs security updates";
        H=`hostname`
        ssh -i /data/keys/<KEYFILE> <USRER>@<REMOTEHOST>.com "{ echo \"MAIL FROM: root@${H}\"; echo \"RCPT TO: <USER>@<EMAILHOST>.com\"; echo \"DATA\"; echo \"Subject: ${H} - ${1} container needs security update\"; echo \"\"; echo -e \"\n${1} container needs update.\n\n\"; echo -e \"docker exec ${1} bash -c 'grep security /etc/apt/sources.list > /tmp/security.list; apt-get update > /dev/null; apt-get upgrade -oDir::Etc::Sourcelist=/tmp/security.list -s'\n\n\"; echo \"Remove the -s to run the update\"; echo \"\"; echo \".\"; echo \"quit\"; sleep 1; } | telnet <SMTPHOST> 25"
}

CONTAINERS=$(docker ps --format "{{.Names}}")
for CONTAINER in $CONTAINERS; do
        echo "Checking ${CONTAINER}"
        if needsUpdates $CONTAINER; then
                sendEmail $CONTAINER
        fi
done
```

And the following script keeps track of when new images are posted to hub.docker.com.

```bash
#!/bin/bash

DATAPATH='/data/docker/updater/data'

if [ ! -d "${DATAPATH}" ]; then
        mkdir "${DATAPATH}";
fi
IMAGES=$(docker ps --format "{{.Image}}")
for IMAGE in $IMAGES; do
        ORIGIMAGE=${IMAGE}
        if [[ "$IMAGE" != *\/* ]]; then
                IMAGE=library/${IMAGE}
        fi
        IMAGE=${IMAGE%%:*}
        echo "Checking ${IMAGE}"
        PARSED=${IMAGE//\//.}
        if [ ! -f "${DATAPATH}/${PARSED}" ]; then
                # File doesn't exist yet, make baseline
                echo "Setting baseline for ${IMAGE}"
                curl -s "https://registry.hub.docker.com/v2/repositories/${IMAGE}/tags/" > "${DATAPATH}/${PARSED}"
        else
                # File does exist, do a compare
                NEW=$(curl -s "https://registry.hub.docker.com/v2/repositories/${IMAGE}/tags/")
                OLD=$(cat "${DATAPATH}/${PARSED}")
                if [[ "${OLD}" == "${NEW}" ]]; then
                        echo "Image ${IMAGE} is up to date";
                else
                        echo ${NEW} > "${DATAPATH}/${PARSED}"
                        echo "Image ${IMAGE} needs to be updated";
                        H=`hostname`
                        ssh -i /data/keys/<KEYFILE> <USER>@<REMOTEHOST>.com "{ echo \"MAIL FROM: root@${H}\"; echo \"RCPT TO: <USER>@<EMAILHOST>.com\"; echo \"DATA\"; echo \"Subject: ${H} - ${IMAGE} needs update\"; echo \"\"; echo -e \"\n${IMAGE} needs update.\n\ndocker pull ${ORIGIMAGE}\"; echo \"\"; echo \".\"; echo \"quit\"; sleep 1; } | telnet <SMTPHOST> 25"
                fi

        fi
done;
```

## Examples with docker run

Keep in mind, for all examples replace `nowsci/samba-domain` with `samba-domain` if you build your own from GitHub.

Start a new domain, and forward non-resolvable queries to the main DNS server

* Local site is `192.168.3.0`
* Local DC (this one) hostname is `LOCALDC` using the host IP of `192.168.3.222`
* Local main DNS is running on `192.168.3.1`

```bash
docker run -t -i \
 -e "DOMAIN=CORP.EXAMPLE.COM" \
 -e "DOMAINPASS=ThisIsMyAdminPassword" \
 -e "DNSFORWARDER=192.168.3.1" \
 -e "HOSTIP=192.168.3.222" \
 -p 192.168.3.222:53:53 \
 -p 192.168.3.222:53:53/udp \
 -p 192.168.3.222:88:88 \
 -p 192.168.3.222:88:88/udp \
 -p 192.168.3.222:135:135 \
 -p 192.168.3.222:137-138:137-138/udp \
 -p 192.168.3.222:139:139 \
 -p 192.168.3.222:389:389 \
 -p 192.168.3.222:389:389/udp \
 -p 192.168.3.222:445:445 \
 -p 192.168.3.222:464:464 \
 -p 192.168.3.222:464:464/udp \
 -p 192.168.3.222:636:636 \
 -p 192.168.3.222:1024-1044:1024-1044 \
 -p 192.168.3.222:3268-3269:3268-3269 \
 -v /etc/localtime:/etc/localtime:ro \
 -v /var/log/samba:/var/log/samba:ro \
 -v /data/docker/containers/samba/data/:/var/lib/samba \
 -v /data/docker/containers/samba/config/samba:/etc/samba/external \
 --dns-search corp.example.com \
 --dns 192.168.3.222 \
 --dns 192.168.3.1 \
 --add-host localdc.corp.example.com:192.168.3.222 \
 -h localdc \
 --name samba \
 --privileged \
 nowsci/samba-domain
```

Join an existing domain, and forward non-resolvable queries to the main DNS server

* Local site is `192.168.3.0`
* Local DC (this one) hostname is `LOCALDC` using the host IP of `192.168.3.222`
* Local existing DC is running DNS and has IP of `192.168.3.201`
* Local main DNS is running on `192.168.3.1`

```bash
docker run -t -i \
 -e "DOMAIN=CORP.EXAMPLE.COM" \
 -e "DOMAINPASS=ThisIsMyAdminPassword" \
 -e "JOIN=true" \
 -e "DNSFORWARDER=192.168.3.1" \
 -e "HOSTIP=192.168.3.222" \
 -p 192.168.3.222:53:53 \
 -p 192.168.3.222:53:53/udp \
 -p 192.168.3.222:88:88 \
 -p 192.168.3.222:88:88/udp \
 -p 192.168.3.222:135:135 \
 -p 192.168.3.222:137-138:137-138/udp \
 -p 192.168.3.222:139:139 \
 -p 192.168.3.222:389:389 \
 -p 192.168.3.222:389:389/udp \
 -p 192.168.3.222:445:445 \
 -p 192.168.3.222:464:464 \
 -p 192.168.3.222:464:464/udp \
 -p 192.168.3.222:636:636 \
 -p 192.168.3.222:1024-1044:1024-1044 \
 -p 192.168.3.222:3268-3269:3268-3269 \
 -v /etc/localtime:/etc/localtime:ro \
 -v /data/docker/containers/samba/data/:/var/lib/samba \
 -v /data/docker/containers/samba/config/samba:/etc/samba/external \
 --dns-search corp.example.com \
 --dns 192.168.3.222 \
 --dns 192.168.3.1 \
 --dns 192.168.3.201 \
 --add-host localdc.corp.example.com:192.168.3.222 \
 -h localdc \
 --name samba \
 --privileged \
 nowsci/samba-domain
```

Join an existing domain, forward DNS, remove security features, and connect to a remote site via openvpn

* Local site is `192.168.3.0`
* Local DC (this one) hostname is `LOCALDC` using the host IP of `192.168.3.222`
* Local existing DC is running DNS and has IP of `192.168.3.201`
* Local main DNS is running on `192.168.3.1`
* Remote site is `192.168.6.0`
* Remote DC hostname is `REMOTEDC` with IP of `192.168.6.222` (notice the DNS and host entries)

```bash
docker run -t -i \
 -e "DOMAIN=CORP.EXAMPLE.COM" \
 -e "DOMAINPASS=ThisIsMyAdminPassword" \
 -e "JOIN=true" \
 -e "DNSFORWARDER=192.168.3.1" \
 -e "MULTISITE=true" \
 -e "NOCOMPLEXITY=true" \
 -e "INSECURELDAP=true" \
 -e "HOSTIP=192.168.3.222" \
 -p 192.168.3.222:53:53 \
 -p 192.168.3.222:53:53/udp \
 -p 192.168.3.222:88:88 \
 -p 192.168.3.222:88:88/udp \
 -p 192.168.3.222:135:135 \
 -p 192.168.3.222:137-138:137-138/udp \
 -p 192.168.3.222:139:139 \
 -p 192.168.3.222:389:389 \
 -p 192.168.3.222:389:389/udp \
 -p 192.168.3.222:445:445 \
 -p 192.168.3.222:464:464 \
 -p 192.168.3.222:464:464/udp \
 -p 192.168.3.222:636:636 \
 -p 192.168.3.222:1024-1044:1024-1044 \
 -p 192.168.3.222:3268-3269:3268-3269 \
 -v /etc/localtime:/etc/localtime:ro \
 -v /data/docker/containers/samba/data/:/var/lib/samba \
 -v /data/docker/containers/samba/config/samba:/etc/samba/external \
 -v /data/docker/containers/samba/config/openvpn/docker.ovpn:/docker.ovpn \
 -v /data/docker/containers/samba/config/openvpn/credentials:/credentials \
 --dns-search corp.example.com \
 --dns 192.168.3.222 \
 --dns 192.168.3.1 \
 --dns 192.168.6.222 \
 --dns 192.168.3.201 \
 --add-host localdc.corp.example.com:192.168.3.222 \
 --add-host remotedc.corp.example.com:192.168.6.222 \
 --add-host remotedc:192.168.6.222 \
 -h localdc \
 --name samba \
 --privileged \
 --cap-add=NET_ADMIN --device /dev/net/tun \
 nowsci/samba-domain
```

## Examples with docker compose

Keep in mind for all examples `DOMAINPASS` can be removed after the first run.

Start a new domain, and forward non-resolvable queries to the main DNS server

* Local site is `192.168.3.0`
* Local DC (this one) hostname is `LOCALDC` using the host IP of `192.168.3.222`
* Local main DNS is running on `192.168.3.1`

```yaml
version: '2'

networks:
  extnet:
    external: true

services:

# ----------- samba begin ----------- #

  samba:
    image: nowsci/samba-domain
    container_name: samba
    volumes:
      - /etc/localtime:/etc/localtime:ro
      - /data/docker/containers/samba/data/:/var/lib/samba
      - /data/docker/containers/samba/config/samba:/etc/samba/external
    environment:
      - DOMAIN=CORP.EXAMPLE.COM
      - DOMAINPASS=ThisIsMyAdminPassword
      - DNSFORWARDER=192.168.3.1
      - HOSTIP=192.168.3.222
    networks:
      - extnet
    ports:
      - 192.168.3.222:53:53
      - 192.168.3.222:53:53/udp
      - 192.168.3.222:88:88
      - 192.168.3.222:88:88/udp
      - 192.168.3.222:135:135
      - 192.168.3.222:137-138:137-138/udp
      - 192.168.3.222:139:139
      - 192.168.3.222:389:389
      - 192.168.3.222:389:389/udp
      - 192.168.3.222:445:445
      - 192.168.3.222:464:464
      - 192.168.3.222:464:464/udp
      - 192.168.3.222:636:636
      - 192.168.3.222:1024-1044:1024-1044
      - 192.168.3.222:3268-3269:3268-3269
    dns_search:
      - corp.example.com
    dns:
      - 192.168.3.222
      - 192.168.3.1
    extra_hosts:
      - localdc.corp.example.com:192.168.3.222
    hostname: localdc
    cap_add:
      - NET_ADMIN
      - SYS_NICE
      - SYS_RESOURCE
      - SYS_TIME
    devices:
      - /dev/net/tun
    privileged: true
    restart: always

# ----------- samba end ----------- #
```

Join an existing domain, and forward non-resolvable queries to the main DNS server

* Local site is `192.168.3.0`
* Local DC (this one) hostname is `LOCALDC` using the host IP of `192.168.3.222`
* Local existing DC is running DNS and has IP of `192.168.3.201`
* Local main DNS is running on `192.168.3.1`

```yaml
version: '2'

networks:
  extnet:
    external: true

services:

# ----------- samba begin ----------- #

  samba:
    image: nowsci/samba-domain
    container_name: samba
    volumes:
      - /etc/localtime:/etc/localtime:ro
      - /data/docker/containers/samba/data/:/var/lib/samba
      - /data/docker/containers/samba/config/samba:/etc/samba/external
    environment:
      - DOMAIN=CORP.EXAMPLE.COM
      - DOMAINPASS=ThisIsMyAdminPassword
      - JOIN=true
      - DNSFORWARDER=192.168.3.1
      - HOSTIP=192.168.3.222
    networks:
      - extnet
    ports:
      - 192.168.3.222:53:53
      - 192.168.3.222:53:53/udp
      - 192.168.3.222:88:88
      - 192.168.3.222:88:88/udp
      - 192.168.3.222:135:135
      - 192.168.3.222:137-138:137-138/udp
      - 192.168.3.222:139:139
      - 192.168.3.222:389:389
      - 192.168.3.222:389:389/udp
      - 192.168.3.222:445:445
      - 192.168.3.222:464:464
      - 192.168.3.222:464:464/udp
      - 192.168.3.222:636:636
      - 192.168.3.222:1024-1044:1024-1044
      - 192.168.3.222:3268-3269:3268-3269
    dns_search:
      - corp.example.com
    dns:
      - 192.168.3.222
      - 192.168.3.1
      - 192.168.3.201
    extra_hosts:
      - localdc.corp.example.com:192.168.3.222
    hostname: localdc
    cap_add:
      - NET_ADMIN
      - SYS_NICE
      - SYS_RESOURCE
      - SYS_TIME
    devices:
      - /dev/net/tun
    privileged: true
    restart: always

# ----------- samba end ----------- #
```

Join an existing domain, forward DNS, remove security features, and connect to a remote site via openvpn

* Local site is `192.168.3.0`
* Local DC (this one) hostname is `LOCALDC` using the host IP of `192.168.3.222`
* Local existing DC is running DNS and has IP of `192.168.3.201`
* Local main DNS is running on `192.168.3.1`
* Remote site is `192.168.6.0`
* Remote DC hostname is `REMOTEDC` with IP of `192.168.6.222` (notice the DNS and host entries)

```yaml
version: '2'

networks:
  extnet:
    external: true

services:

# ----------- samba begin ----------- #

  samba:
    image: nowsci/samba-domain
    container_name: samba
    volumes:
      - /etc/localtime:/etc/localtime:ro
      - /data/docker/containers/samba/data/:/var/lib/samba
      - /data/docker/containers/samba/config/samba:/etc/samba/external
      - /data/docker/containers/samba/config/openvpn/docker.ovpn:/docker.ovpn
      - /data/docker/containers/samba/config/openvpn/credentials:/credentials
    environment:
      - DOMAIN=CORP.EXAMPLE.COM
      - DOMAINPASS=ThisIsMyAdminPassword
      - JOIN=true
      - DNSFORWARDER=192.168.3.1
      - MULTISITE=true
      - NOCOMPLEXITY=true
      - INSECURELDAP=true
      - HOSTIP=192.168.3.222
    networks:
      - extnet
    ports:
      - 192.168.3.222:53:53
      - 192.168.3.222:53:53/udp
      - 192.168.3.222:88:88
      - 192.168.3.222:88:88/udp
      - 192.168.3.222:135:135
      - 192.168.3.222:137-138:137-138/udp
      - 192.168.3.222:139:139
      - 192.168.3.222:389:389
      - 192.168.3.222:389:389/udp
      - 192.168.3.222:445:445
      - 192.168.3.222:464:464
      - 192.168.3.222:464:464/udp
      - 192.168.3.222:636:636
      - 192.168.3.222:1024-1044:1024-1044
      - 192.168.3.222:3268-3269:3268-3269
    dns_search:
      - corp.example.com
    dns:
      - 192.168.3.222
      - 192.168.3.1
      - 192.168.6.222
      - 192.168.3.201
    extra_hosts:
      - localdc.corp.example.com:192.168.3.222
      - remotedc.corp.example.com:192.168.6.222
      - remotedc:192.168.6.222
    hostname: localdc
    cap_add:
      - NET_ADMIN
      - SYS_NICE
      - SYS_RESOURCE
      - SYS_TIME
    devices:
      - /dev/net/tun
    privileged: true
    restart: always

# ----------- samba end ----------- #
```

## Joining the domain with Ubuntu

For joining the domain with any client, everything should work just as you would expect if the active directory server was Windows based. For Ubuntu, there are many guides availble for joining, but to make things easier you can find an easily configurable script for joining your domain here: <https://raw.githubusercontent.com/Fmstrat/samba-domain/master/ubuntu-join-domain.sh>

## Troubleshooting

The most common issue is when running multi-site and seeing the below DNS replication error when checking replication with `docker exec samba samba-tool drs showrepl`

```log
CN=Schema,CN=Configuration,DC=corp,DC=example,DC=local
        Default-First-Site-Name\REMOTEDC via RPC
                DSA object GUID: faf297a8-6cd3-4162-b204-1945e4ed5569
                Last attempt @ Thu Jun 29 10:49:45 2017 EDT failed, result 2 (WERR_BADFILE)
                4 consecutive failure(s).
                Last success @ NTTIME(0)
```

This has nothing to do with docker, but does happen in samba setups. The key is to put the GUID host entry into the start script for docker, and restart the container. For instance, if you saw the above error, Add this to you docker command:

```bash
--add-host faf297a8-6cd3-4162-b204-1945e4ed5569._msdcs.corp.example.com:192.168.6.222 \
```

Where `192.168.6.222` is the IP of `REMOTEDC`. You could also do this in `extra_hosts` in docker-compose.
