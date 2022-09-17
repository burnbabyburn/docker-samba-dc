#!/bin/sh

DEBUG_ENABLE=${DEBUG_ENABLE:-false}
if [ "${DEBUG_ENABLE}" = true ] ; then set -x ; fi
#  if [ "$DEBUG_ENABLE" = "true" ] ; then set -x ; else set -e ; fi
#Trap SIGTERM
trap 'backupConfig' SIGTERM

#Todo:
# ID_Map replication: https://wiki.samba.org/index.php/Joining_a_Samba_DC_to_an_Existing_Active_Directory#Built-in_User_.26_Group_ID_Mappings
# SYSVOL replication
# Write a service for a wireguard mesh network between two docker containers on different sites as an "overlay-network" - https://www.scaleway.com/en/docs/tutorials/wireguard-mesh-vpn/
# https://github.com/samba-team/samba/blob/master/docs-xml/Samba-EventLog-HOWTO.txt <= Didn't work
# https://wiki.samba.org/index.php/Setting_up_Audit_Logging

config() {
  # Set variables
  DOMAIN=${DOMAIN:-SAMDOM.LOCAL}
  LDOMAIN=$(printf "%s" "$DOMAIN" | tr '[:upper:]' '[:lower:]')
  UDOMAIN=$(printf "%s" "$LDOMAIN" | tr '[:lower:]' '[:upper:]')
  URDOMAIN=$(printf "%s" "$UDOMAIN" | cut -d "." -f1)
  BIND_INTERFACES=${BIND_INTERFACES:-127.0.0.1} # Can be a list of interfaces seperated by spaces
  BIND_INTERFACES_ENABLE=${BIND_INTERFACES_ENABLE:-false}
  DEBUG_LEVEL=${DEBUG_LEVEL:-0}
  DISABLE_DNS_WPAD_ISATAP=${DISABLE_DNS_WPAD_ISATAP:-false}
  DISABLE_MD5=${DISABLE_MD5:-true}
  DOMAIN_ACC_LOCK_DURATION=${DOMAIN_ACC_LOCK_DURATION:-30}
  DOMAIN_ACC_LOCK_RST_AFTER=${DOMAIN_ACC_LOCK_RST_AFTER:-30}
  DOMAIN_ACC_LOCK_THRESHOLD=${DOMAIN_ACC_LOCK_THRESHOLD:-0}
  DOMAIN_NETBIOS=${DOMAIN_NETBIOS:-$URDOMAIN}
  DOMAIN_PASS=${DOMAIN_PASS:-youshouldsetapassword}
  DOMAIN_PWD_COMPLEXITY=${DOMAIN_PWD_COMPLEXITY:-true}
  DOMAIN_PWD_HISTORY_LENGTH=${DOMAIN_PWD_HISTORY_LENGTH:-24}
  DOMAIN_PWD_MAX_AGE=${DOMAIN_PWD_MAX_AGE:-43}
  DOMAIN_PWD_MIN_AGE=${DOMAIN_PWD_MIN_AGE:-1}
  DOMAIN_PWD_MIN_LENGTH=${DOMAIN_PWD_MIN_LENGTH:-7}
  DOMAIN_USER=${DOMAIN_USER:-Administrator}
  ENABLE_CUPS=${ENABLE_CUPS:-false}
  ENABLE_DNSFORWARDER=${ENABLE_DNSFORWARDER:-NONE}
  ENABLE_DYNAMIC_PORTRANGE=${ENABLE_DYNAMIC_PORTRANGE:-NONE}
  ENABLE_INSECURE_DNSUPDATE=${ENABLE_INSECURE_DNSUPDATE:-false}
  ENABLE_INSECURE_LDAP=${ENABLE_INSECURE_LDAP:-false}
  ENABLE_LAPS_SCHEMA=${ENABLE_LAPS_SCHEMA:-false}
  ENABLE_LOGS=${ENABLE_LOGS:-false}
  ENABLE_MSCHAPV2=${ENABLE_MSCHAPV2:-false}
  ENABLE_RFC2307=${ENABLE_RFC2307:-true}
  ENABLE_WINS=${ENABLE_WINS:-false}
  FEATURE_KERBEROS_TGT=${FEATURE_KERBEROS_TGT:-false}
  FEATURE_RECYCLEBIN=${FEATURE_RECYCLEBIN:-true}
  HOSTIP=${HOSTIP:-NONE}
  HOSTIPV6=${HOSTIPV6:-NONE}
  HOSTNAME=${HOSTNAME:-$(hostname)} # Only hostname, no FQDN
  JOIN=${JOIN:-false}
  JOIN_SITE=${JOIN_SITE:-Default-First-Site-Name}
  JOIN_SITE_VPN=${JOIN_SITE_VPN:-false}
  NTPSERVERLIST=${NTPSERVERLIST:-0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org}
  TLS_ENABLE=${TLS_ENABLE:-false}
  TLS_PKI=${TLS_PKI:-false}
  TLS_PKI_CN=${PKI_CN:-Simple Samba Root CA}
  TLS_PKI_O=${PKI_O:-Simple Root CA}
  TLS_PKI_OU=${PKI_OU:-Samba}
  TZ=${TZ:-/Etc/UTC}

  # Min Counter Values for NIS Attributes. Set in docker-compose
  # does nothing on DCs as they shall not use idmap settings.
  # idmap config {{ URDOMAIN }} : range = {{ IDMIN }}-{{ IDMAX }}
  IMAP_ID_START=${IMAP_UID_START:-10000}
  IMAP_UID_START=${IMAP_UID_START:-$IMAP_ID_START}
  IMAP_GID_START=${IMAP_GID_START:-$IMAP_ID_START}

  # DIR_GPO, DIR_SAMBA_CONF, DIR_LDIF and DIR_SCRIPTS need to be changed in the Dockerfile
  #DIR_LDIF=/ldif
  #DIR_SCRIPTS=/scripts
  #DIR_SAMBA_CONF=/etc/samba/smb.conf.d/
  #DIR_GPO=/gpo
  DIR_CHRONY_LOG=/var/log/chrony
  DIR_CHRONY_NTSDUMP=/var/lib/chrony
  DIR_CHRONY_SRC=/etc/chrony/sources.d
  DIR_CHRONY_CONF=/etc/chrony/conf.d
  DIR_CHRONY_SOCK=/var/lib/samba/ntp_signd
  DIR_CHRONY_RUN=/run/chrony
  DIR_SAMBA_DATA_PREFIX=/var/lib/samba
  DIR_SAMBA_ETC=/etc/samba
  DIR_SAMBA_CSHARE=/var/lib/samba/share_c
  FILE_SAMBA_LOG=/var/log/samba/%m.log
  FILE_KRB5=/etc/krb5.conf
  FILE_KRB5_WINBINDD=/var/lib/samba/private/krb5.conf
  FILE_NSSWITCH=/etc/nsswitch.conf
  FILE_CHRONY_DRIFT=/var/lib/chrony/chrony.drift
  FILE_CHRONY=/etc/chrony/chrony.conf
  #FILE_CHRONY_RTC=/var/lib/chrony/rtc
  FILE_CHRONY_KEY=/etc/chrony/chrony.keys
  FILE_OPENVPNCONF=/docker.ovpn
  FILE_SUPERVISORD_CONF=/etc/supervisor/supervisord.conf
  FILE_SUPERVISORD_CUSTOM_CONF=/etc/supervisor/conf.d/supervisord.conf

  DIR_SAMBA_SYSVOL="${DIR_SAMBA_DATA_PREFIX}/sysvol/${LDOMAIN}"
  DIR_SAMBA_NETLOGON="${DIR_SAMBA_DATA_PREFIX}/sysvol/scripts"
  DIR_SAMBA_EVENTLOG="${DIR_SAMBA_CSHARE}/windows/system32/config"
  DIR_SAMBA_ADMIN="${DIR_SAMBA_CSHARE}/windows"
  DIR_EXTERNAL="${DIR_SAMBA_ETC}/external"
  DIR_SAMBA_PRINTDRIVER="${DIR_SAMBA_CSHARE}/windows/system32/spool/drivers"
  DIR_SAMBA_PRIVATE="${DIR_SAMBA_DATA_PREFIX}/private"
  FILE_CHRONY_PID="${DIR_CHRONY_RUN}/chronyd.pid"
  FILE_EXTERNAL_KRB5_CONF="${DIR_EXTERNAL}/krb5.conf"
  FILE_EXTERNAL_NSSWITCH="${DIR_EXTERNAL}/nsswitch.conf"
  FILE_EXTERNAL_CHRONY_CONF="${DIR_EXTERNAL}/chrony.conf"
  FILE_PKI_CA="${DIR_SAMBA_PRIVATE}/tls/ca.pem"
  FILE_PKI_CERT="${DIR_SAMBA_PRIVATE}/tls/cert.pem"
  FILE_PKI_CRL="${DIR_SAMBA_PRIVATE}/tls/crl.pem"
  FILE_PKI_DH="${DIR_SAMBA_PRIVATE}/tls/dh.key"
  FILE_PKI_INT="${DIR_SAMBA_PRIVATE}/tls/intermediate.pem"
  FILE_PKI_KEY="${DIR_SAMBA_PRIVATE}/tls/key.pem"
  FILE_SAMBA_CONF="${DIR_SAMBA_ETC}/smb.conf"
  FILE_EXTERNAL_SAMBA_CONF="${DIR_EXTERNAL}/smb.conf"
#  FILE_SAMBA_INCLUDES="${DIR_SAMBA_ETC}/includes.conf"
  FILE_SAMBA_SCHEMA_LAPS1="${DIR_LDIF}/laps-1.ldif"
  FILE_SAMBA_SCHEMA_LAPS2="${DIR_LDIF}/laps-2.ldif"
  FILE_SAMBA_SCHEMA_SSH1="${DIR_LDIF}/ssh-1.ldif"
  FILE_SAMBA_SCHEMA_SSH2="${DIR_LDIF}/ssh-2.ldif"
  FILE_SAMBA_SCHEMA_SSH3="${DIR_LDIF}/ssh-3.ldif"
  FILE_SAMBA_SCHEMA_SUDO1="${DIR_LDIF}/sudo-1.ldif"
  FILE_SAMBA_SCHEMA_SUDO2="${DIR_LDIF}/sudo-2.ldif"
  FILE_SAMBA_SCHEMA_RFC="${DIR_LDIF}/RFC_Domain_User_Group.ldif"
  FILE_SAMBA_SCHEMA_WINSREPL="${DIR_LDIF}/wins.ldif"
  FILE_SAMBA_USER_MAP="${DIR_SAMBA_ETC}/user.map"
  FILE_SAMBA_WINSLDB="${DIR_SAMBA_PRIVATE}/wins_config.ldb"
  FILE_SAMLDB="${DIR_SAMBA_PRIVATE}/sam.ldb"
  FILE_EXTERNAL_SUPERVISORD_CONF="${DIR_EXTERNAL}/supervisord.conf"

  # if hostname contains FQDN cut the rest
  if printf "%s" "${HOSTNAME}" | grep -q "\."; then HOSTNAME=$(printf "%s" "${HOSTNAME}" | cut -d "." -f1) ; fi
  
  #DN for LDIF
  LDAP_SUFFIX=""
  IFS='.'
  # Qouting LDMAIN will break the loop
  for dn in ${LDOMAIN}; do
    LDAP_SUFFIX="${LDAP_SUFFIX},DC=${dn}"
  done
  IFS=$(printf ' \n\t')
  LDAP_DN="${HOSTNAME}${LDAP_SUFFIX}"

  # exports for other scripts and TLS_PKI
  export HOSTNAME="${HOSTNAME}"
  export LDAP_DN="${LDAP_DN}"
  export LDAP_SUFFIX="${LDAP_SUFFIX}"
  export DIR_SCRIPTS="${DIR_SCRIPTS}"
  # Export if we don't source helper.sh in the future. These vars are needed from helper script
  export FILE_EXTERNAL_SUPERVISORD_CONF="${FILE_EXTERNAL_SUPERVISORD_CONF}"
  export FILE_EXTERNAL_SAMBA_CONF="${FILE_EXTERNAL_SAMBA_CONF}"
  export FILE_EXTERNAL_CHRONY_CONF="${FILE_EXTERNAL_CHRONY_CONF}"
  export FILE_EXTERNAL_NSSWITCH="${FILE_EXTERNAL_NSSWITCH}"
#  export FILE_SAMBA_INCLUDES="${FILE_SAMBA_INCLUDES}"

  # shellcheck source=/dev/null
  . /"${DIR_SCRIPTS}"/helper.sh
}

appSetup () {
  set -- "--dns-backend=SAMBA_INTERNAL" \
         "--option=add group script=/usr/sbin/groupadd %g" \
         "--option=add machine script=/usr/sbin/useradd -N -M -g Domain-Computer -d /dev/null -s /bin/false %u" \
         "--option=add user to group script=/usr/sbin/adduser %u %g" \
         "--option=delete group script=/usr/sbin/groupdel %g" \
         "--option=delete user from group script=/usr/sbin/deluser %u %g" \
         "--option=delete user script=/usr/sbin/deluser %u" \
         "--option=dns update command = /usr/sbin/samba_dnsupdate --use-samba-tool"

  if ! grep 'Domain-Computer' /etc/group ; then /usr/sbin/groupadd Domain-Computer ; fi

  # https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html#NAMERESOLVEORDER
  set -- "$@" "--option=name resolve order = wins host bcast"

  # https://samba.tranquil.it/doc/en/samba_advanced_methods/samba_active_directory_higher_security_tips.html#generating-additional-password-hashes
  set -- "$@" "--option=password hash userPassword schemes = CryptSHA256 CryptSHA512"
  # Template settings for users without ''unixHomeDir'' and ''loginShell'' attributes also for idmap
  set -- "$@" "--option=template shell = /bin/false" "--option=template homedir = /dev/null"
  
  # Setup ACLs correctly https://github.com/thctlo/samba4/blob/master/samba-setup-share-folders.sh
#  if [[ ! -d "$DIR_SAMBA_DATA_PREFIX/unixhome/" ]]; then mkdir -p "$DIR_SAMBA_DATA_PREFIX/unixhome/" ; fi
  # Test
  set -- "$@" "--option=eventlog list = Application System Security SyslogLinux Webserver"

  set -- "$@" "-d ${DEBUG_LEVEL}"
  NTP_DEBUG_OPTION="-D ${DEBUG_LEVEL}"
  SAMBADAEMON_DEBUG_OPTION="--debug-stdout -d ${DEBUG_LEVEL}"
  SAMBA_DEBUG_OPTION="-d ${DEBUG_LEVEL}"
  CHRONY_DEBUG_OPTION="d"

  if [ ! -f /etc/timezone ] && [ -n "${TZ}" ]; then
    printf 'Set timezone'
    cp "/usr/share/zoneinfo/${TZ}" /etc/localtime
    printf "%s" "${TZ}" >/etc/timezone
  fi

  sed -e "s:{{ NTP_DEBUG_OPTION }}:${NTP_DEBUG_OPTION}:" -i "${FILE_SUPERVISORD_CUSTOM_CONF}"
  sed -e "s:{{ SAMBADAEMON_DEBUG_OPTION }}:${SAMBADAEMON_DEBUG_OPTION}:" -i "${FILE_SUPERVISORD_CUSTOM_CONF}"
  sed -e "s:{{ CHRONY_DEBUG_OPTION }}:${CHRONY_DEBUG_OPTION}:" -i "${FILE_SUPERVISORD_CUSTOM_CONF}"

  if [ ! -f "${FILE_KRB5}" ] ; then rm -f "${FILE_KRB5}" ; fi

  if [ ! -d "${DIR_CHRONY_LOG}" ]; then mkdir "${DIR_CHRONY_LOG}"; fi
  chown _chrony:_chrony "${DIR_CHRONY_LOG}"
  if [ ! -d "${DIR_CHRONY_RUN}" ]; then mkdir "${DIR_CHRONY_RUN}"; fi
  chmod 750 "${DIR_CHRONY_RUN}";

  # If used on azure image chrony breaks (github actions)
  # Fatal error : Could not open /run/chrony/chronyd.pid : Permission denied
 # INFO exited: chrony (exit status 1; not expected)
  if ! uname -a | grep -q "azure"; then
    # Wrong owner of /run/chrony (UID != 102) - the azure image complains but with a chowned dir chrony just crashes
    chown _chrony:_chrony "${DIR_CHRONY_RUN}"
  fi
  if grep -q "{{ DIR_CHRONY_CONF }}" "${FILE_CHRONY}"; then sed -e "s:{{ DIR_CHRONY_CONF }}:${DIR_CHRONY_CONF}:" -i "${FILE_CHRONY}"; fi
  if grep -q "{{ DIR_CHRONY_LOG }}" "${FILE_CHRONY}"; then sed -e "s:{{ DIR_CHRONY_LOG }}:${DIR_CHRONY_LOG}:" -i "${FILE_CHRONY}"; fi
  if grep -q "{{ DIR_CHRONY_NTSDUMP }}" "${FILE_CHRONY}"; then sed -e "s:{{ DIR_CHRONY_NTSDUMP }}:${DIR_CHRONY_NTSDUMP}:" -i "${FILE_CHRONY}"; fi
  if grep -q "{{ DIR_CHRONY_SOCK }}" "${FILE_CHRONY}"; then sed -e "s:{{ DIR_CHRONY_SOCK }}:${DIR_CHRONY_SOCK}:" -i "${FILE_CHRONY}"; fi
  if grep -q "{{ DIR_CHRONY_SRC }}" "${FILE_CHRONY}"; then sed -e "s:{{ DIR_CHRONY_SRC }}:${DIR_CHRONY_SRC}:" -i "${FILE_CHRONY}"; fi
  if grep -q "{{ FILE_CHRONY_DRIFT }}" "${FILE_CHRONY}"; then sed -e "s:{{ FILE_CHRONY_DRIFT }}:${FILE_CHRONY_DRIFT}:" -i "${FILE_CHRONY}"; fi
  if grep -q "{{ FILE_CHRONY_KEY }}" "${FILE_CHRONY}"; then sed -e "s:{{ FILE_CHRONY_KEY }}:${FILE_CHRONY_KEY}:" -i "${FILE_CHRONY}"; fi
  if grep -q "{{ FILE_CHRONY_PID }}" "${FILE_CHRONY}"; then sed -e "s:{{ FILE_CHRONY_PID }}:${FILE_CHRONY_PID}:" -i "${FILE_CHRONY}"; fi

  if  [ ! -f "${DIR_CHRONY_SRC}/my.sources" ]; then
    DCs=$(echo "$NTPSERVERLIST" | tr " " "\n")
    for DC in $DCs
    do
	  # valid entries need to end with newline (\n)
      printf "server %s iburst\n" "${DC}" >> "${DIR_CHRONY_SRC}/my.sources"
    done
  fi

  if [ ! -d "${DIR_EXTERNAL}" ]; then mkdir "${DIR_EXTERNAL}" ; fi
  #Check if DOMAIN_NETBIOS <15 chars and contains no "."
  if [ "${#DOMAIN_NETBIOS}" -gt 15 ]; then printf "DOMAIN_NETBIOS too long => exiting" ; exit 1 ; fi
  if printf "%s" "${DOMAIN_NETBIOS}" | grep -q "\." ; then printf "DOMAIN_NETBIOS contains forbiden char    .     => exiting" ; exit 1 ; fi
  if [ "${HOSTIP}" != "NONE" ]; then set -- "$@" "--host-ip=${HOSTIP%/*}" ; fi
  if [ "${HOSTIPV6}" != "NONE" ]; then set -- "$@" "--host-ip6=${HOSTIPV6}" ;  fi
  if [ "${JOIN_SITE}" != "Default-First-Site-Name" ]; then set -- "$@" "--site=${JOIN_SITE}" ; fi
  if [ "${ENABLE_DNSFORWARDER}" != "NONE" ]; then set -- "$@" "--option=dns forwarder=${ENABLE_DNSFORWARDER}" ; fi
  if [ "${ENABLE_DYNAMIC_PORTRANGE}" != "NONE" ]; then set -- "$@" "--option=rpc server dynamic port range=${ENABLE_DYNAMIC_PORTRANGE}" ; fi
  if [ "${ENABLE_MSCHAPV2}" = true ]; then set -- "$@" "--option=ntlm auth=mschapv2-and-ntlmv2-only" ; fi
  if [ "${ENABLE_INSECURE_DNSUPDATE}" = true ]; then set -- "$@" "--option=allow dns updates  = nonsecure" ; fi
  if [ "${ENABLE_INSECURE_LDAP}" = true ]; then set -- "$@" "--option=ldap server require strong auth = no" ; fi

  # If multi-site, we need to connect to the VPN before joining the domain
  if [ "${JOIN_SITE_VPN}" = true ]; then
    /usr/sbin/openvpn --config ${FILE_OPENVPNCONF} &
    VPNPID=$!
    printf "Sleeping 30s to ensure VPN connects %s" "($VPNPID)";
    sleep 30s
  fi
  if [ "${ENABLE_RFC2307}" = true ]; then
    if [ "${JOIN}" = true ]; then OPTION_RFC='--option=idmap_ldb:use rfc2307 = yes' ; else OPTION_RFC='--use-rfc2307' ; fi
    set -- "$@" "${OPTION_RFC}"
  fi
  if [ "${BIND_INTERFACES_ENABLE}" = true ]; then
    if ! printf "%s" "${BIND_INTERFACES}" | grep "127.0.0.1\|lo\|::1" >> /dev/null; then
      printf "
       127.0.0.1 missing from BIND_INTERFACES.
       If bind interfaces only is set and the network address 127.0.0.1 is not added to the interfaces parameter list smbpasswd(8) may not work as expected due to the reasons covered below.
       To change a users SMB password, the smbpasswd by default connects to the localhost - 127.0.0.1 address as an SMB client to issue the password change request.
       If bind interfaces only is set then unless the network address 127.0.0.1 is added to the interfaces parameter list then smbpasswd will fail to connect in it's default mode.
       smbpasswd can be forced to use the primary IP interface of the local host by using its smbpasswd(8) -r remote machine parameter, with remote machine set to the IP name of the primary interface of the local host. "
       BIND_INTERFACES="${BIND_INTERFACES},lo"
    fi
    set -- "$@" "--option=interfaces=${BIND_INTERFACES}"
    set -- "$@" "--option=bind interfaces only = yes"
  fi
  if [ "${DISABLE_MD5}" = true ]; then
    # Prevent downgrade attacks to md5
    set -- "$@" "--option=reject md5 clients = yes"
    set -- "$@" "--option=reject md5 servers = yes"
  fi
  if [ "${ENABLE_WINS}" = true ]; then
    set -- "$@" "--option=wins support = yes"
    set -- "$@" "--option=time server = yes"
  fi

  if [ "${ENABLE_LOGS}" = true ]; then
    set -- "$@" "--option=log file = ${FILE_SAMBA_LOG}"
    set -- "$@" "--option=max log size = 10000"
    set -- "$@" "--option=log level = ${DEBUG_LEVEL}"
    sed -i '/log[[:space:]]/s/^#//g' "$FILE_CHRONY"
  fi

  # nsswitch anpassen
  sed -i "s,passwd:.*,passwd:         files winbind,g" "${FILE_NSSWITCH}"
  sed -i "s,group:.*,group:          files winbind,g" "${FILE_NSSWITCH}"
  sed -i "s,hosts:.*,hosts:          files dns,g" "${FILE_NSSWITCH}"
  sed -i "s,networks:.*,networks:      files dns,g" "${FILE_NSSWITCH}"

  # If external/smb.conf doesn't exist, this is new container with empty volume, we're not just moving to a new container
  if [ ! -f "${FILE_EXTERNAL_SAMBA_CONF}" ]; then
    if [ -f "${FILE_SAMBA_CONF}" ]; then mv "${FILE_SAMBA_CONF}" "${FILE_SAMBA_CONF}".orig ; fi
      # Optional params encased with "" will break the command
    if [ "${JOIN}" = true ]; then
#     if [ "$(dig +short -t srv _ldap._tcp.$LDOMAIN.)" ] && printf "got answer"
      s=1
      set -- "$@" "${LDOMAIN}"
      set -- "$@" "DC"
      set -- "$@" "-U${DOMAIN_NETBIOS}\\${DOMAIN_USER}"
      set -- "$@" "--password=${DOMAIN_PASS}"
      until [ $s = 0 ]
      do
        samba-tool domain join "$@" && s=0 && break || s=$? && sleep 60s
      done; (exit $s)
      # Prevent https://wiki.samba.org/index.php/Samba_Member_Server_Troubleshooting => SeDiskOperatorPrivilege can't be set
      if [ ! -f "${FILE_SAMBA_USER_MAP}" ]; then
        printf '!'"root = %s\\%s" > "${FILE_SAMBA_USER_MAP}" , "${DOMAIN_NETBIOS}","${DOMAIN_USER}"
        set -- "$@" "--option=username map = ${FILE_SAMBA_USER_MAP}"
      fi
      # Netlogon & sysvol readonly on secondary DC
      if [ ! -d "${DIR_SAMBA_NETLOGON}" ]; then mkdir "${DIR_SAMBA_NETLOGON}" ; fi
      if [ ! -d "${DIR_SAMBA_SYSVOL}" ]; then mkdir "${DIR_SAMBA_SYSVOL}" ; fi
      {
        printf '\n'
        printf '[netlogon]\n'
        printf 'path = %s\n' "${DIR_SAMBA_NETLOGON}"
        printf 'read only = Yes\n'
        printf '\n'
        printf '[sysvol]\n'
        printf 'path = %s\n' "${DIR_SAMBA_SYSVOL}"
        printf 'read only = Yes\n'
      } >> "${FILE_SAMBA_CONF}"

      #Check if Join was successfull
      if host -t A "$HOSTNAME"."$LDOMAIN".;then
        printf "found DNS host record"
      else
        printf "no DNS host record found. Pls see https://wiki.samba.org/index.php/Verifying_and_Creating_a_DC_DNS_Record#Verifying_and_Creating_the_objectGUID_Record"
      fi
    # domain provision
    else
      set -- "$@" "--server-role=dc"
      set -- "$@" "--host-name=${HOSTNAME}"
      set -- "$@" "--adminpass=${DOMAIN_PASS}"
      set -- "$@" "--realm=${UDOMAIN}"
      set -- "$@" "--domain=${DOMAIN_NETBIOS}"

      samba-tool domain provision "$@"

      samba-tool user setexpiry Administrator --noexpiry
      if [ ! -d "${DIR_SAMBA_CSHARE}" ]; then
        mkdir -p "${DIR_SAMBA_EVENTLOG}"
        mkdir -p "${DIR_SAMBA_ADMIN}"
        #ln -s "$DIR_SAMBA_SYSVOL" "$DIR_SAMBA_CSHARE/sysvol"
      fi
      {
        printf '\n'
        printf '[C$]\n'
        printf 'path = %s\n' "${DIR_SAMBA_CSHARE}"
        printf 'read only = no\n'
        printf 'valid users = @\"Domain Admins\"\n'
        printf '\n'
        printf '[ADMIN$]\n'
        printf 'path = %s\n' "${DIR_SAMBA_ADMIN}"
        printf 'read only = no\n'
        printf 'valid users = @\"Domain Admins\"\n'
      } >> "${FILE_SAMBA_CONF}"

      # https://gitlab.com/samba-team/samba/-/blob/master/source4/scripting/bin/enablerecyclebin
      if [ "${FEATURE_RECYCLEBIN}" = true ]; then
        python3 /"${DIR_SCRIPTS}"/enablerecyclebin.py "${FILE_SAMLDB}"
        if ldbsearch -H /var/lib/samba/private/sam.ldb -s base -b "CN=NTDS Settings,CN=${HOSTNAME},CN=Servers,CN=${JOIN_SITE},CN=Sites,CN=Configuration${LDAP_SUFFIX}" msDS-EnabledFeature | grep -q 'CN=Recycle Bin Feature' ; then printf "Optional Feature Recycle Bin Feature OK" ; else printf "FAILED" ; exit 1 ; fi
      fi

      if [ "${FEATURE_KERBEROS_TGT}" = true ]; then EnableChangeKRBTGTSupervisord ; fi

      # Set default uid and gid for ad user and groups, based on IMAP_GID_START value
      if [ "${ENABLE_RFC2307}" = true ]; then
        setupSchemaRFC2307File
        ldbmodify -H "${FILE_SAMLDB}" "${FILE_SAMBA_SCHEMA_RFC}" -U "${DOMAIN_USER}" "${SAMBA_DEBUG_OPTION}"
        if ldbsearch -H /var/lib/samba/private/sam.ldb -s base -b CN="${DOMAIN_NETBIOS}",CN=ypservers,CN=ypServ30,CN=RpcServices,CN=System"${LDAP_SUFFIX}" | grep 'returned 1 records'; then
          printf "Add RFC2307 Attributes for default AD users" ; else printf 'FAILED' ; exit 1 ; fi
      fi
      # https://fy.blackhats.net.au/blog/html/2018/04/18/making_samba_4_the_default_ldap_server.html?highlight=samba
      # https://blog.laslabs.com/2016/08/storing-ssh-keys-in-active-directory/
      # https://wiki.samba.org/index.php/Samba_AD_schema_extensions
	  # https://gist.github.com/hsw0/5132d5dabd4384108b48
#     if [[ true = true ]]; then
        sed -e "s: {{ LDAP_SUFFIX }}:${LDAP_SUFFIX}:g" \
        "${FILE_SAMBA_SCHEMA_SSH1}.j2" > "${FILE_SAMBA_SCHEMA_SSH1}"
        sed -e "s: {{ LDAP_SUFFIX }}:${LDAP_SUFFIX}:g" \
        "${FILE_SAMBA_SCHEMA_SSH2}.j2" > "${FILE_SAMBA_SCHEMA_SSH2}"
        sed -e "s: {{ LDAP_SUFFIX }}:${LDAP_SUFFIX}:g" \
        "${FILE_SAMBA_SCHEMA_SSH3}.j2" > "${FILE_SAMBA_SCHEMA_SSH3}"
        ldbmodify -H "${FILE_SAMLDB}" --option="dsdb:schema update allowed"=true "${FILE_SAMBA_SCHEMA_SSH1}" -U "${DOMAIN_USER}" "${SAMBA_DEBUG_OPTION}"
        ldbmodify -H "${FILE_SAMLDB}" --option="dsdb:schema update allowed"=true "${FILE_SAMBA_SCHEMA_SSH2}" -U "${DOMAIN_USER}" "${SAMBA_DEBUG_OPTION}"
		ldbmodify -H "${FILE_SAMLDB}" --option="dsdb:schema update allowed"=true "${FILE_SAMBA_SCHEMA_SSH3}" -U "${DOMAIN_USER}" "${SAMBA_DEBUG_OPTION}"
#      fi

        sed -e "s: {{ LDAP_SUFFIX }}:${LDAP_SUFFIX}:g" \
        "${FILE_SAMBA_SCHEMA_SUDO1}.j2" > "${FILE_SAMBA_SCHEMA_SUDO1}"
        sed -e "s: {{ LDAP_SUFFIX }}:${LDAP_SUFFIX}:g" \
        "${FILE_SAMBA_SCHEMA_SUDO2}.j2" > "${FILE_SAMBA_SCHEMA_SUDO2}"
        ldbmodify -H "${FILE_SAMLDB}" --option="dsdb:schema update allowed"=true "${FILE_SAMBA_SCHEMA_SUDO1}" -U "${DOMAIN_USER}" "${SAMBA_DEBUG_OPTION}"
        ldbmodify -H "${FILE_SAMLDB}" --option="dsdb:schema update allowed"=true "${FILE_SAMBA_SCHEMA_SUDO2}" -U "${DOMAIN_USER}" "${SAMBA_DEBUG_OPTION}"

      # https://www.microsoft.com/en-us/download/confirmation.aspx?id=103507'
      # Microsoft Local Administrator Password Solution (LAPS) https://www.microsoft.com/en-us/download/details.aspx?id=46899
      if [ "${ENABLE_LAPS_SCHEMA}" = true ]; then
        sed -e "s: {{ LDAP_SUFFIX }}:${LDAP_SUFFIX}:g" \
          "${FILE_SAMBA_SCHEMA_LAPS1}.j2" > "${FILE_SAMBA_SCHEMA_LAPS1}"
        sed -e "s: {{ LDAP_SUFFIX }}:${LDAP_SUFFIX}:g" \
          "${FILE_SAMBA_SCHEMA_LAPS2}.j2" > "${FILE_SAMBA_SCHEMA_LAPS2}"
        ldbadd -H "${FILE_SAMLDB}" --option="dsdb:schema update allowed"=true "${FILE_SAMBA_SCHEMA_LAPS1}" -U "${DOMAIN_USER}" "${SAMBA_DEBUG_OPTION}"
        ldbmodify -H "${FILE_SAMLDB}" --option="dsdb:schema update allowed"=true "${FILE_SAMBA_SCHEMA_LAPS2}" -U "${DOMAIN_USER}" "${SAMBA_DEBUG_OPTION}"
      fi

      if [ "${DOMAIN_PWD_HISTORY_LENGTH}" != 24 ]; then samba-tool domain passwordsettings set --history-length="$DOMAIN_PWD_HISTORY_LENGTH" "${SAMBA_DEBUG_OPTION}" ; fi
      if [ "${DOMAIN_PWD_MAX_AGE}" != 43 ]; then samba-tool domain passwordsettings set --max-pwd-age="$DOMAIN_PWD_MAX_AGE" "${SAMBA_DEBUG_OPTION}" ; fi
      if [ "${DOMAIN_PWD_MIN_AGE}" != 1 ]; then samba-tool domain passwordsettings set --min-pwd-age="$DOMAIN_PWD_MIN_AGE" "${SAMBA_DEBUG_OPTION}" ; fi
      if [ "${DOMAIN_PWD_MIN_LENGTH}" != 7 ]; then samba-tool domain passwordsettings set --min-pwd-length="$DOMAIN_PWD_MIN_LENGTH" "${SAMBA_DEBUG_OPTION}" ; fi
      if [ "${DOMAIN_PWD_COMPLEXITY}" = false ]; then samba-tool domain passwordsettings set --complexity="$DOMAIN_PWD_COMPLEXITY" "${SAMBA_DEBUG_OPTION}" ; fi

      if [ "${DOMAIN_ACC_LOCK_DURATION}" != 30 ]; then samba-tool domain passwordsettings set --account-lockout-duration="$DOMAIN_ACC_LOCK_DURATION" "${SAMBA_DEBUG_OPTION}" ; fi
      if [ "${DOMAIN_ACC_LOCK_THRESHOLD}" != 0 ]; then samba-tool domain passwordsettings set --account-lockout-threshold="$DOMAIN_ACC_LOCK_THRESHOLD" "${SAMBA_DEBUG_OPTION}" ; fi
      if [ "${DOMAIN_ACC_LOCK_RST_AFTER}" != 30 ]; then samba-tool domain passwordsettings set --reset-account-lockout-after="$DOMAIN_ACC_LOCK_RST_AFTER" "${SAMBA_DEBUG_OPTION}" ; fi
    fi

    # https://wiki.samba.org/index.php/Setting_up_Automatic_Printer_Driver_Downloads_for_Windows_Clients
    # https://wiki.samba.org/index.php/Setting_up_Samba_as_a_Print_Server
    if [ "${ENABLE_CUPS}" = true ]; then
      SetKeyValueFilePattern 'load printers' 'yes'
      SetKeyValueFilePattern 'printing' 'cups'
      SetKeyValueFilePattern 'printcap name' 'cups'
      SetKeyValueFilePattern 'show add printer wizard' 'no'
      SetKeyValueFilePattern 'cups encrypt' 'no'
      SetKeyValueFilePattern 'cups options' '\"raw media=a4\"'
      SetKeyValueFilePattern '#cups server' "${CUPS_SERVER}:${CUPS_PORT}"
      if [ ! -d "${DIR_SAMBA_PRINTDRIVER}" ]; then mkdir -p "${DIR_SAMBA_PRINTDRIVER}" ; fi
      {
        printf '\n'
        printf '[printers]\n'
        printf 'comment = All Printers\n'
        printf 'path = /var/spool/samba\n'
        printf 'printable = yes\n'
        printf 'use client driver = Yes\n'
        printf 'guest ok = Yes\n'
        printf 'browseable = No\n'
        printf '\n'
        printf '[PRINT$]\n'
        printf 'path = %s\n' , "${DIR_SAMBA_PRINTDRIVER}"
        printf 'read only = no\n'
        printf 'write list = @\"Domain Admins\"\n'
      } >> "${FILE_SAMBA_CONF}"
    else
      SetKeyValueFilePattern 'load printers' 'no'
      SetKeyValueFilePattern 'printing' 'bsd'
      SetKeyValueFilePattern 'printcap name' '/dev/null'
      SetKeyValueFilePattern 'disable spoolss' 'yes'
    fi

  if [ "${TLS_ENABLE}" = true ]; then
    if [ ! -f "${FILE_PKI_CERT}" ] && [ ! -f "${FILE_PKI_KEY}" ] && [ ! -f "${FILE_PKI_CA}" ]; then printf "No custom CA found. Samba will autogenerate one" ; fi
    if [ ! -f "${FILE_PKI_DH}" ]; then openssl dhparam -out "${FILE_PKI_DH}" 2048 ; fi
    set -- "$@" "--option=tls enabled = yes"
    set -- "$@" "--option=tls keyfile = $FILE_PKI_KEY"
    set -- "$@" "--option=tls certfile = $FILE_PKI_CERT"
    set -- "$@" "--option=tls cafile = $FILE_PKI_CA"
    set -- "$@" "--option=tls dh params file = $FILE_PKI_DH"
#    set -- "$@" "--option=tls crlfile = $FILE_PKI_CRL"
#    set -- "$@" "--option=tls verify peer = ca_and_name"
  else
    set -- "$@" "--option=tls enabled = no"
  fi

    # Once we are set up, we'll make a file so that we know to use it if we ever spin this up again
    backupConfig
  else
    restoreConfig
  fi

  cp "${FILE_KRB5_WINBINDD}" "${FILE_KRB5}"

  if [ ! -d "${DIR_CHRONY_SOCK}" ]; then mkdir -p "${DIR_CHRONY_SOCK}" ; fi
  chmod 750 "${DIR_CHRONY_SOCK}"
  chown root:root "${DIR_CHRONY_SOCK}"
  # Stop VPN & write supervisor service
  if [ "${JOIN_SITE_VPN}" = true ]; then
    if [ -n "${VPNPID}" ]; then kill "${VPNPID}" ; fi
    EnableOpenvpnSupervisord
  fi
  appFirstStart
}

appFirstStart () {
  for file in /etc/samba/conf.d/*.conf; do
    SetKeyValueFilePattern 'include' "$file"
  done
  update-ca-certificates
  /usr/bin/supervisord -c "${FILE_SUPERVISORD_CONF}" &

  if [ "${JOIN}" = false ]; then
    # Better check if net rpc is rdy
    sleep 30s
	GetAllCidrCreateSubnet
    RDNSZonefromCIDR
      #admxdir=$(find /tmp/ -name PolicyDefinitions)
      admxdir="${DIR_GPO}"
      # Import Samba. admx&adml gpo
      printf "%s" "${DOMAIN_PASS}" | samba-tool gpo admxload -U Administrator "${SAMBA_DEBUG_OPTION}"
      # Import Windows admx&adml
      printf "%s" "${DOMAIN_PASS}" | samba-tool gpo admxload -U Administrator --admx-dir="${admxdir}" "${SAMBA_DEBUG_OPTION}"

    #https://technet.microsoft.com/en-us/library/cc794902%28v=ws.10%29.aspx
    if [ "${DISABLE_DNS_WPAD_ISATAP}" = true ]; then
      samba-tool dns add "$(hostname -s)" "${LDOMAIN}" wpad A 127.0.0.1 -P "${SAMBA_DEBUG_OPTION}"
      samba-tool dns add "$(hostname -s)" "${LDOMAIN}" isatap A 127.0.0.1 -P "${SAMBA_DEBUG_OPTION}"
    fi
    #Test - e.g. https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller
    printf "rpcclient: Connect as %s" "${DOMAIN_USER}" ; if rpcclient -cgetusername "-U${DOMAIN_USER}%${DOMAIN_PASS}" "${SAMBA_DEBUG_OPTION}" 127.0.0.1 ; then printf 'OK' ; else printf 'FAILED' ; exit 1 ; fi
    printf "smbclient: Connect as anonymous user" ; if smbclient -N -L LOCALHOST "${SAMBA_DEBUG_OPTION}" | grep 'Anonymous login successful' ; then printf 'OK' ; else printf 'FAILED' ; exit 1 ; fi
    printf "smbclient: Connect as %s" "${DOMAIN_USER}" ; if smbclient --debug-stdout -d 4 -U"${DOMAIN_USER}%${DOMAIN_PASS}" -L LOCALHOST | grep '[[:blank:]]session setup ok' ; then printf 'OK' ; else printf 'FAILED' ; exit 1 ; fi
    printf "Kerberos: Connect as %s" "${DOMAIN_USER}" ; if printf "%s" "${DOMAIN_PASS}" | kinit "${DOMAIN_USER}" ; then printf 'OK' ; klist ; kdestroy ; else printf 'FAILED' ; exit 1 ; fi
    echo "check chrony"; chronyc sources; chronyc tracking
    printf "Check DNS _ldap._tcp"; host -t SRV _ldap._tcp."${LDOMAIN}"
    printf "Check DNS _kerberos._tcp"; host -t SRV _kerberos._udp."${LDOMAIN}"
    printf "Check Host record"; host -t A "${HOSTNAME}.${LDOMAIN}"
    printf "Check Reverse DNS resolution"; dig -x "${IP}"

    #Copy root cert as der to netlogon
    #openssl x509 -outform der -in /var/lib/samba/private/tls/ca.pem -out /var/lib/samba/sysvol/"$LDOMAIN"/scripts/root.crt
    #You want to set SeDiskOperatorPrivilege on your member server to manage your share permissions:
    printf "%s" "${DOMAIN_PASS}" | net rpc rights grant "${UDOMAIN}\\Domain Admins" "-d ${DEBUG_LEVEL}" "-U${UDOMAIN}\\${DOMAIN_USER}" "SeDiskOperatorPrivilege"
    if [ "${ENABLE_CUPS}" = true ]; then net rpc rights grant "${UDOMAIN}\\Domain Admins" "-d ${DEBUG_LEVEL}" "-U${UDOMAIN}\\${DOMAIN_USER}" "SePrintOperatorPrivilege" ; fi
  # if JOIN=true
  else
  #ERROR?`{{DC_IP}}:$LDAP_SUFFIX:g {DC_DNS}}:$LDAP_SUFFIX:g
    if [ -f "${FILE_SAMBA_WINSLDB}" ] && [ "${ENABLE_WINS}" = true ];then
      sed -e "s: {{DC_IP}}:${LDAP_SUFFIX}:g" \
          -e "s: {{DC_DNS}}:${HOSTNAME}:g" \
          "${FILE_SAMBA_SCHEMA_WINSREPL}.j2" > "${FILE_SAMBA_SCHEMA_WINSREPL}"
    ldbadd -H "${FILE_SAMBA_WINSLDB}" "${FILE_SAMBA_SCHEMA_WINSREPL}"
    fi
  fi
  wait
  # source /scripts/firstrun.sh
}

appStart () {
  update-ca-certificates
  restoreConfig
  /usr/bin/supervisord -c "${FILE_SUPERVISORD_CONF}"
}

######### BEGIN MAIN function #########
config

# If the supervisor conf isn't there, we're spinning up a new container
if [ -f "${FILE_EXTERNAL_SAMBA_CONF}" ]; then
  appStart
else
  appSetup || exit 1
fi

exit 0
######### END MAIN function #########