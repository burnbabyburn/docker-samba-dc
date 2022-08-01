#!/bin/bash

set -x

config() {
  # Set variables
  DOMAIN=${DOMAIN:-SAMDOM.LOCAL}
  LDOMAIN=$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]')
  UDOMAIN=$(echo "$LDOMAIN" | tr '[:lower:]' '[:upper:]')
  URDOMAIN=$(echo "$UDOMAIN" | cut -d "." -f1)

  DOMAIN_USER=${DOMAIN_USER:-Administrator}
  DOMAIN_PASS=${DOMAIN_PASS:-youshouldsetapassword}
  DOMAIN_NETBIOS=${DOMAIN_NETBIOS:-$URDOMAIN}

  HOSTIP=${HOSTIP:-NONE}
  #Change if hostname includes DNS/DOMAIN SUFFIX e.g. host.example.com - it should only display host
  HOSTNAME=${HOSTNAME:-$(hostname)}
  
  # if hostname contains FQDN cut the rest
  if [[ $HOSTNAME == *"."* ]]; then
  HOSTNAME=$(echo "$HOSTNAME" | cut -d "." -f1)
  fi

  #DN for LDIF
  LDAP_SUFFIX=""
  local IFS='.'
  for dn in ${LDOMAIN}; do
    LDAP_SUFFIX="${LDAP_SUFFIX},DC=$dn"
  done
  local IFS=' '
  LDAP_DN=$HOSTNAME$LDAP_SUFFIX

  CHANGE_KRB_TGT_PW=${CHANGE_KRB_TGT_PW:-false}
  JOIN=${JOIN:-false}
  JOIN_SITE=${JOIN_SITE:-Default-First-Site-Name}
  # One could write a service to acomplish a wireguard mesh network between docker container on different sites as an "overlay-network" - https://www.scaleway.com/en/docs/tutorials/wireguard-mesh-vpn/
  JOIN_SITE_VPN=${JOIN_SITE_VPN:-false}
  NTPSERVERLIST=${NTPSERVERLIST:-0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org}
  RECYCLEBIN=${RECYCLEBIN:-true}

  DISABLE_DNS_WPAD_ISATAP=${DISABLE_PW_COMPLEXITY:-false}
  DISABLE_MD5=${DISABLE_MD5:-true}
  DISABLE_PW_COMPLEXITY=${DISABLE_PW_COMPLEXITY:-false}

  ENABLE_CUPS=${ENABLE_CUPS:-false}
  ENABLE_DNSFORWARDER=${ENABLE_DNSFORWARDER:-NONE}
  ENABLE_DYNAMIC_PORTRANGE=${ENABLE_DYNAMIC_PORTRANGE:-NONE}
  ENABLE_INSECURE_DNSUPDATE=${ENABLE_INSECURE_DNSUPDATE:-false}
  ENABLE_INSECURE_LDAP=${ENABLE_INSECURE_LDAP:-false}
  ENABLE_LAPS_SCHEMA=${ENABLE_LAPS_SCHEMA:-true}
  ENABLE_LOGS=${ENABLE_LOGS:-false}
  ENABLE_MSCHAPV2=${ENABLE_MSCHAPV2:-false}
  ENABLE_RFC2307=${ENABLE_RFC2307:-true}
  ENABLE_WINS=${ENABLE_WINS:-false}

  ENABLE_TLS=${ENABLE_TLS:-false}
  TLS_PKI=${TLS_PKI:-false}
  PKI_CN=${PKI_CN:-Simple Samba Root CA}
  PKI_O=${PKI_O:-Simple Root CA}
  PKI_OU=${PKI_OU:-Samba}

  ENABLE_DEBUG=${ENABLE_DEBUG:-false}
  DEBUG_LEVEL=${DEBUG_LEVEL:-0}

  ENABLE_BIND_INTERFACE=${ENABLE_BIND_INTERFACE:-false}
  BIND_INTERFACES=${BIND_INTERFACES:-127.0.0.1} # Can be a list of interfaces seperated by spaces

  if [[ "$ENABLE_BIND_INTERFACE" = true ]] && ! echo "$BIND_INTERFACES" | grep "127.0.0.1" >> /dev/null; then
    echo "127.0.0.1 missing from BIND_INTERFACES. 
	 If bind interfaces only is set and the network address 127.0.0.1 is not added to the interfaces parameter list smbpasswd(8) may not work as expected due to the reasons covered below.
     To change a users SMB password, the smbpasswd by default connects to the localhost - 127.0.0.1 address as an SMB client to issue the password change request. 
	 If bind interfaces only is set then unless the network address 127.0.0.1 is added to the interfaces parameter list then smbpasswd will fail to connect in it's default mode. 
	 smbpasswd can be forced to use the primary IP interface of the local host by using its smbpasswd(8)	-r remote machine parameter, with remote machine set to the IP name of the primary interface of the local host. "
	 BIND_INTERFACES+=,127.0.0.1
  fi
  # Min Counter Values for NIS Attributes. Set in docker-compose if you want a different start
  # IT does nothing on DCs as they shall not use idmap settings.
  # Using the same Start and stop values on members however gets the RFC2307 attributs (NIS) rights
  # idmap config {{ URDOMAIN }} : range = {{ IDMIN }}-{{ IDMAX }}
  IMAP_ID_START=${IMAP_UID_START:-10000}
  IMAP_UID_START=${IMAP_UID_START:-$IMAP_ID_START}
  IMAP_GID_START=${IMAP_GID_START:-$IMAP_ID_START}

  #file variables
  # DIR_SAMBA_CONF and DIR_SCRIPTS also need to be changed in the Dockerfile
  DIR_LDIF=/ldif
  DIR_NTP_SOCK=/var/lib/samba/ntp_signd
  DIR_SAMBA_DATA_PREFIX=/var/lib/samba
  DIR_SAMBA_ETC=/etc/samba
  DIR_SCRIPTS=/scripts

  DIR_SAMBA_CONF=$DIR_SAMBA_ETC/smb.conf.d
  DIR_SAMBA_EXTERNAL=$DIR_SAMBA_ETC/external
  DIR_SAMBA_PRIVATE=$DIR_SAMBA_DATA_PREFIX/private

  FILE_KRB5=/etc/krb5.conf
  FILE_NSSWITCH=/etc/nsswitch.conf
  FILE_NTP=/etc/ntp.conf
  FILE_NTP_DRIFT=/var/lib/ntp/ntp.drift
  FILE_OPENVPNCONF=/docker.ovpn
  FILE_SUPERVISORD_CONF=/etc/supervisor/supervisord.conf
  FILE_SUPERVISORD_CUSTOM_CONF=/etc/supervisor/conf.d/supervisord.conf

  FILE_KRB5_CONF_EXTERNAL=$DIR_SAMBA_EXTERNAL/krb5.conf
  FILE_NSSWITCH_EXTERNAL=$DIR_SAMBA_EXTERNAL/nsswitch.conf
  FILE_NTP_CONF_EXTERNAL=$DIR_SAMBA_EXTERNAL/ntp.conf
  FILE_PKI_CA=$DIR_SAMBA_PRIVATE/tls/ca.pem
  FILE_PKI_CERT=$DIR_SAMBA_PRIVATE/tls/cert.pem
  FILE_PKI_CRL=$DIR_SAMBA_PRIVATE/tls/crl.pem
  FILE_PKI_DH=$DIR_SAMBA_PRIVATE/tls/dh.key
  FILE_PKI_INT=$DIR_SAMBA_PRIVATE/tls/intermediate.pem
  FILE_PKI_KEY=$DIR_SAMBA_PRIVATE/tls/key.pem
  FILE_SAMBA_CONF=$DIR_SAMBA_ETC/smb.conf
  FILE_SAMBA_CONF_EXTERNAL=$DIR_SAMBA_EXTERNAL/smb.conf
  FILE_SAMBA_INCLUDES=$DIR_SAMBA_ETC/includes.conf
  FILE_SAMBA_SCHEMA_LAPS1=$DIR_LDIF/laps-1.ldif
  FILE_SAMBA_SCHEMA_LAPS2=$DIR_LDIF/laps-2.ldif
  FILE_SAMBA_SCHEMA_RFC=$DIR_LDIF/RFC_Domain_User_Group.ldif
  FILE_SAMBA_SCHEMA_WINSREPL=$DIR_LDIF/wins.ldif
  FILE_SAMBA_USER_MAP=$DIR_SAMBA_ETC/user.map
  FILE_SAMBA_WINSLDB=$DIR_SAMBA_PRIVATE/wins_config.ldb
  FILE_SAMLDB=$DIR_SAMBA_PRIVATE/sam.ldb
  FILE_SUPERVISORD_CONF_EXTERNAL=$DIR_SAMBA_EXTERNAL/supervisord.conf

  # exports for other scripts and TLS_PKI
  export HOSTNAME="$HOSTNAME"
  export LDAP_DN="$LDAP_DN"
  export LDAP_SUFFIX="$LDAP_SUFFIX"
  export DIR_SCRIPTS="$DIR_SCRIPTS"
}

appSetup () {
  ARGS_SAMBA_TOOL=()
  ARGS_SAMBA_TOOL+=("--dns-backend=SAMBA_INTERNAL")
  if [[ $DEBUG_LEVEL -gt 0 ]]; then
    SAMBA_DEBUG_OPTION="-d $DEBUG_LEVEL"
    ARGS_SAMBA_TOOL+=("${SAMBA_DEBUG_OPTION}")
  fi

  SAMBADAEMON_DEBUG_OPTION="--debug-stdout -d $DEBUG_LEVEL"
  NTP_DEBUG_OPTION="-D $DEBUG_LEVEL"
  sed -e "s:{{ SAMBADAEMON_DEBUG_OPTION }}:$SAMBADAEMON_DEBUG_OPTION:" -i "${FILE_SUPERVISORD_CUSTOM_CONF}"
  sed -e "s:{{ NTP_DEBUG_OPTION }}:$NTP_DEBUG_OPTION:" -i "${FILE_SUPERVISORD_CUSTOM_CONF}"

  sed -e "s:{{ UDOMAIN }}:$UDOMAIN:" \
      -e "s:{{ LDOMAIN }}:$LDOMAIN:" \
      -e "s:{{ HOSTNAME }}:$HOSTNAME:" \
  -i "$FILE_KRB5"

  #NTP Settings - Instead of just touch the file write a float to the file to get rid of "format error frequency file /var/lib/ntp/ntp.drift" error message
  if [[ ! -f "$FILE_NTP_DRIFT" ]]; then
    echo 0.0 > "$FILE_NTP_DRIFT"
  fi
  chown root:root "$FILE_NTP_DRIFT"
  if grep "{{ NTPSERVER }}" "$FILE_NTP"; then
    DCs=$(echo "$NTPSERVERLIST" | tr " " "\n")
    NTPSERVER=""
    NTPSERVERRESTRICT=""
    local IFS=$'\n'
    for DC in $DCs
    do
      NTPSERVER="$NTPSERVER server ${DC}    iburst prefer\n"
      NTPSERVERRESTRICT="$NTPSERVERRESTRICT restrict ${DC} mask 255.255.255.255    nomodify notrap nopeer noquery\n"
    done
    local IFS=' '
    sed -e "s:{{ NTPSERVER }}:$NTPSERVER:" -i "$FILE_NTP"
    sed -e "s:{{ NTPSERVERRESTRICT }}:$NTPSERVERRESTRICT:" -i "$FILE_NTP"
  fi
  if [[ ! -f "$DIR_NTP_SOCK" ]]; then
    mkdir -p "$DIR_NTP_SOCK"
  fi
  chmod 750 "$DIR_NTP_SOCK"
  chown root:root "$DIR_NTP_SOCK"
  if [[ ! -d "$DIR_SAMBA_EXTERNAL" ]]; then
    mkdir "$DIR_SAMBA_EXTERNAL"
  fi
  #Check if DOMAIN_NETBIOS <15 chars and contains no "."
  if [[ ${#DOMAIN_NETBIOS} -gt 15 ]]; then
    echo "DOMAIN_NETBIOS too long => exiting" && exit 1
  fi
  if [[ $DOMAIN_NETBIOS == *"."* ]]; then
    echo "DOMAIN_NETBIOS contains forbiden char    .     => exiting" && exit 1
  fi
  # If multi-site, we need to connect to the VPN before joining the domain
  if [[ ${JOIN_SITE_VPN,,} = true ]]; then
    /usr/sbin/openvpn --config ${FILE_OPENVPNCONF} &
    VPNPID=$!
    echo "Sleeping 30s to ensure VPN connects ($VPNPID)";
    sleep 30
  fi
  if [[ ${ENABLE_RFC2307,,} = true ]]; then
    if [[ "$JOIN" = true ]]; then
      OPTION_RFC=--option='idmap_ldb:use rfc2307 = yes'
    else
      OPTION_RFC=--use-rfc2307
    fi
    ARGS_SAMBA_TOOL+=("${OPTION_RFC}")
  fi
  if [[ "$HOSTIP" != "NONE" ]]; then
	ARGS_SAMBA_TOOL+=("--host-ip=${HOSTIP%/*}")
  fi
  if [[ "$JOIN_SITE" != "Default-First-Site-Name" ]]; then
	ARGS_SAMBA_TOOL+=("--site=${JOIN_SITE}")
  fi
  if [[ ${ENABLE_BIND_INTERFACE,,} = true ]]; then
    ARGS_SAMBA_TOOL+=("--option=interfaces=${BIND_INTERFACES,,} lo")
    ARGS_SAMBA_TOOL+=("--option=bind interfaces only = yes")
  fi
  if [[ "$ENABLE_DNSFORWARDER" != "NONE" ]]; then
    ARGS_SAMBA_TOOL+=("--option=dns forwarder=${ENABLE_DNSFORWARDER}")
  fi
  if [[ "$ENABLE_DYNAMIC_PORTRANGE" != "NONE" ]]; then
    ARGS_SAMBA_TOOL+=("--option=rpc server dynamic port range=${ENABLE_DYNAMIC_PORTRANGE}")
  fi
  if [[ ${ENABLE_MSCHAPV2,,} = true ]]; then
    ARGS_SAMBA_TOOL+=("--option=ntlm auth=mschapv2-and-ntlmv2-only")
  fi
  if [[ ${DISABLE_MD5,,} = true ]]; then
    # Prevent downgrade attacks to md5
	ARGS_SAMBA_TOOL+=("--option=reject md5 clients = yes")
	ARGS_SAMBA_TOOL+=("--option=reject md5 servers = yes")
  fi
  if [[ ${ENABLE_INSECURE_LDAP,,} = true ]]; then
	ARGS_SAMBA_TOOL+=("--option=ldap server require strong auth = no")
  fi
  if [[ ${ENABLE_WINS,,} = true ]]; then
    ARGS_SAMBA_TOOL+=("--option=wins support = yes")
	ARGS_SAMBA_TOOL+=("--option=time server = yes")
  fi
  if [ "${ENABLE_INSECURE_DNSUPDATE,,}" = true ]; then
    ARGS_SAMBA_TOOL+=("--option=allow dns updates  = nonsecure")
  fi

  # If the finished file (external/smb.conf) doesn't exist, this is new container with empty volume, we're not just moving to a new container
  if [[ ! -f "${FILE_SAMBA_CONF_EXTERNAL}" ]]; then
    if [[ -f "${FILE_SAMBA_CONF}" ]]; then
      mv "${FILE_SAMBA_CONF}" "${FILE_SAMBA_CONF}".orig
    fi
    # Optional params encased with "" will break the command
    if [[ ${JOIN,,} = true ]]; then
#     if [ "$(dig +short -t srv _ldap._tcp.$LDOMAIN.)" ] && echo "got answer"
      s=1
      until [ $s = 0 ]
      do
	    ARGS_SAMBA_TOOL+=("${LDOMAIN}")
		ARGS_SAMBA_TOOL+=("DC")
		ARGS_SAMBA_TOOL+=("-U${DOMAIN_NETBIOS}\\${DOMAIN_USER}")
		ARGS_SAMBA_TOOL+=("--password=${DOMAIN_PASS}")
        samba-tool domain join "${ARGS_SAMBA_TOOL[@]}" && s=0 && break || s=$? && sleep 60
      done; (exit $s)
#      # Netlogon & sysvol readonly on secondary DC
#      {
#        echo " "
#        echo "[netlogon]"
#        echo "path = /var/lib/samba/sysvol/test.dom/scripts"
#        echo "read only = Yes"
#        echo " "
#        echo "[sysvol]"
#        echo "path = /var/lib/samba/sysvol"
#        echo "read only = Yes"
#      } >> "${FILE_SAMBA_CONF}"

      #Check if Join was successfull
      if host -t A "$HOSTNAME"."$LDOMAIN".;then
        echo "found DNS host record"
      else
        echo "no DNS host record found. Pls see https://wiki.samba.org/index.php/Verifying_and_Creating_a_DC_DNS_Record#Verifying_and_Creating_the_objectGUID_Record"
      fi
    # domain provision
    else
      ARGS_SAMBA_TOOL+=("--server-role=dc")
      ARGS_SAMBA_TOOL+=("--host-name=${HOSTNAME}")
      ARGS_SAMBA_TOOL+=("--adminpass=${DOMAIN_PASS}")
      ARGS_SAMBA_TOOL+=("--realm=${UDOMAIN}")
      ARGS_SAMBA_TOOL+=("--domain=${DOMAIN_NETBIOS}")
      ARGS_SAMBA_TOOL+=("--option=add machine script=/usr/sbin/useradd -N -M -g machines -d /dev/null -s /bin/false %u")
	  ARGS_SAMBA_TOOL+=("--option=add group script=/usr/sbin/groupadd %g")
	  ARGS_SAMBA_TOOL+=("--option=add user to group script=/usr/sbin/adduser %u %g")
	  ARGS_SAMBA_TOOL+=("--option=delete group script=/usr/sbin/groupdel %g")
	  ARGS_SAMBA_TOOL+=("--option=delete user from group script=/usr/sbin/deluser %u %g")
	  ARGS_SAMBA_TOOL+=("--option=delete user script=/usr/sbin/deluser %u")
	  
	  
	  ARGS_SAMBA_TOOL+=("--option=dns update command = /usr/sbin/samba_dnsupdate --use-samba-tool")
	  
      samba-tool domain provision "${ARGS_SAMBA_TOOL[@]}"

      if [[ "$RECYCLEBIN" = true ]]; then
        # https://gitlab.com/samba-team/samba/-/blob/master/source4/scripting/bin/enablerecyclebin
        python3 /scripts/enablerecyclebin.py "${FILE_SAMLDB}"
      fi

      if [[ "$CHANGE_KRB_TGT_PW" = true ]]; then
        {
          echo ""
          echo "[program:ChangeKRBTGT]"
          echo "command=/bin/sh /scripts/chgkrbtgtpass.sh"
          echo "stdout_logfile=/dev/fd/1"
          echo "stdout_logfile_maxbytes=0"
          echo "stdout_logfile_backups=0"
          echo "redirect_stderr=true"
          echo "priority=99"
        } >> "${FILE_SUPERVISORD_CUSTOM_CONF}"
      fi

      if [[ ! -d /var/lib/samba/sysvol/"$LDOMAIN"/Policies/PolicyDefinitions/ ]]; then
        mkdir -p /var/lib/samba/sysvol/"$LDOMAIN"/Policies/PolicyDefinitions/en-US
        mkdir /var/lib/samba/sysvol/"$LDOMAIN"/Policies/PolicyDefinitions/de-DE
      fi

      # Set default uid and gid for ad user and groups, based on IMAP_GID_START value
      if [[ ${ENABLE_RFC2307,,} = true ]]; then
        GID_DOM_USER=$((IMAP_GID_START))
        GID_DOM_ADMIN=$((IMAP_GID_START+1))
        GID_DOM_COMPUTERS=$((IMAP_GID_START+2))
        GID_DOM_DC=$((IMAP_GID_START+3))
        GID_DOM_GUEST=$((IMAP_GID_START+4))
        GID_SCHEMA=$((IMAP_GID_START+5))
        GID_ENTERPRISE=$((IMAP_GID_START+6))
        GID_GPO=$((IMAP_GID_START+7))
        GID_RDOC=$((IMAP_GID_START+8))
        GID_DNSUPDATE=$((IMAP_GID_START+9))
        GID_ENTERPRISE_RDOC=$((IMAP_GID_START+10))
        GID_DNSADMIN=$((IMAP_GID_START+11))
        GID_ALLOWED_RDOC=$((IMAP_GID_START+12))
        GID_DENIED_RDOC=$((IMAP_GID_START+13))
        GID_RAS=$((IMAP_GID_START+14))
        GID_CERT=$((IMAP_GID_START+15))

        UID_KRBTGT=$((IMAP_UID_START))
        UID_GUEST=$((IMAP_UID_START+1))
        UID_ADMINISTRATOR=$((IMAP_UID_START+2))

        #Next Counter value uesd by ADUC for NIS Extension GID and UID
        IMAP_GID_END=$((IMAP_GID_START+16))
        IMAP_UID_END=$((IMAP_UID_START+3))

        sed -e "s: {{ LDAP_SUFFIX }}:$LDAP_SUFFIX:g" \
          -e "s:{{ NETBIOS }}:${DOMAIN_NETBIOS,,}:g" \
          -e "s:{{ GID_DOM_USER }}:$GID_DOM_USER:g" \
          -e "s:{{ GID_DOM_ADMIN }}:$GID_DOM_ADMIN:g" \
          -e "s:{{ GID_DOM_COMPUTERS }}:$GID_DOM_COMPUTERS:g" \
          -e "s:{{ GID_DOM_DC }}:$GID_DOM_DC:g" \
          -e "s:{{ GID_DOM_GUEST }}:$GID_DOM_GUEST:g" \
          -e "s:{{ GID_SCHEMA }}:$GID_SCHEMA:g" \
          -e "s:{{ GID_ENTERPRISE }}:$GID_ENTERPRISE:g" \
          -e "s:{{ GID_GPO }}:$GID_GPO:g" \
          -e "s:{{ GID_RDOC }}:$GID_RDOC:g" \
          -e "s:{{ GID_DNSUPDATE }}:$GID_DNSUPDATE:g" \
          -e "s:{{ GID_ENTERPRISE_RDOC }}:$GID_ENTERPRISE_RDOC:g" \
          -e "s:{{ GID_DNSADMIN }}:$GID_DNSADMIN:g" \
          -e "s:{{ GID_ALLOWED_RDOC }}:$GID_ALLOWED_RDOC:g" \
          -e "s:{{ GID_DENIED_RDOC }}:$GID_DENIED_RDOC:g" \
          -e "s:{{ GID_RAS }}:$GID_RAS:g" \
          -e "s:{{ GID_CERT }}:$GID_CERT:g" \
          -e "s:{{ UID_KRBTGT }}:$UID_KRBTGT:g" \
          -e "s:{{ UID_GUEST }}:$UID_GUEST:g" \
          -e "s:{{ UID_ADMINISTRATOR }}:$UID_ADMINISTRATOR:g" \
          -e "s:{{ IMAP_UID_END }}:$IMAP_UID_END:g" \
          -e "s:{{ IMAP_GID_END }}:$IMAP_GID_END:g" \
          "${FILE_SAMBA_SCHEMA_RFC}.j2" > "${FILE_SAMBA_SCHEMA_RFC}"

        ldbmodify -H "${FILE_SAMLDB}" "${FILE_SAMBA_SCHEMA_RFC}" -U "${DOMAIN_USER}"
      fi

      #Microsoft Local Administrator Password Solution (LAPS)
      if [[ ${ENABLE_LAPS_SCHEMA,,} = true ]]; then
        sed -e "s: {{ LDAP_SUFFIX }}:$LDAP_SUFFIX:g" \
          "${FILE_SAMBA_SCHEMA_LAPS1}.j2" > "${FILE_SAMBA_SCHEMA_LAPS1}"
        sed -e "s: {{ LDAP_SUFFIX }}:$LDAP_SUFFIX:g" \
          "${FILE_SAMBA_SCHEMA_LAPS2}.j2" > "${FILE_SAMBA_SCHEMA_LAPS2}"
        ldbadd -H "${FILE_SAMLDB}" --option="dsdb:schema update allowed"=true "${FILE_SAMBA_SCHEMA_LAPS1}" -U "${DOMAIN_USER}"
        ldbmodify -H "${FILE_SAMLDB}" --option="dsdb:schema update allowed"=true "${FILE_SAMBA_SCHEMA_LAPS2}" -U "${DOMAIN_USER}"
      fi

      if [[ ${DISABLE_PW_COMPLEXITY,,} = true ]]; then
        samba-tool domain passwordsettings set --complexity=off "${SAMBA_DEBUG_OPTION}"
        samba-tool domain passwordsettings set --history-length=0 "${SAMBA_DEBUG_OPTION}"
        samba-tool domain passwordsettings set --min-pwd-age=0 "${SAMBA_DEBUG_OPTION}"
        samba-tool domain passwordsettings set --max-pwd-age=0 "${SAMBA_DEBUG_OPTION}"
      fi
    fi

    #Prevent https://wiki.samba.org/index.php/Samba_Member_Server_Troubleshooting => SeDiskOperatorPrivilege can't be set
    if [ ! -f "${FILE_SAMBA_USER_MAP}" ]; then
      echo '!'"root = ${DOMAIN_NETBIOS}\\${DOMAIN_USER}" > "${FILE_SAMBA_USER_MAP}"
      sed -i "/\[global\]/a \
        \\\tusername map = ${FILE_SAMBA_USER_MAP}\
      " "${FILE_SAMBA_CONF}"
    fi

    if [[ ${ENABLE_CUPS,,} = true ]]; then
      sed -i "/\[global\]/a \
        \\\tload printers = yes\\n\
        printing = cups\\n\
        printcap name = cups\\n\
        show add printer wizard = no\\n\
        cups encrypt = no\\n\
        cups options = \"raw media=a4\"\\n\
        #cups server = ${CUPS_SERVER}:${CUPS_PORT}\
      " "${FILE_SAMBA_CONF}"
      {
        echo ""
        echo "[printers]"
        echo "comment = All Printers"
        echo "path = /var/spool/samba"
        echo "printable = yes"
        echo "use client driver = Yes"
        echo "guest ok = Yes"
        echo "browseable = No"
      } >> "${FILE_SAMBA_CONF}"
    else
      sed -i "/\[global\]/a \
        \\\tload printers = no\\n\
        printing = bsd\\n\
        printcap name = /dev/null\\n\
        disable spoolss = yes\
      " "${FILE_SAMBA_CONF}"
    fi

    # https://samba.tranquil.it/doc/en/samba_advanced_methods/samba_active_directory_higher_security_tips.html#generating-additional-password-hashes
    sed -i "/\[global\]/a \
      \\\tpassword hash userPassword schemes = CryptSHA256 CryptSHA512\\n\
      # Template settings for login shell and home directory\\n\
      template shell = /bin/bash\\n\
      template homedir = /home/%U\
    " "${FILE_SAMBA_CONF}"

    # nsswitch anpassen
    sed -i "s,passwd:.*,passwd:         files winbind,g" "$FILE_NSSWITCH"
    sed -i "s,group:.*,group:          files winbind,g" "$FILE_NSSWITCH"
    sed -i "s,hosts:.*,hosts:          files dns,g" "$FILE_NSSWITCH"
    sed -i "s,networks:.*,networks:      files dns,g" "$FILE_NSSWITCH"

    # Once we are set up, we'll make a file so that we know to use it if we ever spin this up again
    cp -f "${FILE_SAMBA_CONF}" "${FILE_SAMBA_CONF_EXTERNAL}"
    cp -f "${FILE_SUPERVISORD_CUSTOM_CONF}" "${FILE_SUPERVISORD_CONF_EXTERNAL}"
    cp -f "${FILE_NTP}" "${FILE_NTP_CONF_EXTERNAL}"
    cp -f "${FILE_KRB5}" "${FILE_KRB5_CONF_EXTERNAL}"
    cp -f "${FILE_NSSWITCH}" "${FILE_NSSWITCH_EXTERNAL}"
  else
    cp -f "${FILE_SAMBA_CONF_EXTERNAL}" "${FILE_SAMBA_CONF}"
    cp -f "${FILE_SUPERVISORD_CONF_EXTERNAL}" "${FILE_SUPERVISORD_CUSTOM_CONF}"
    cp -f "${FILE_NTP_CONF_EXTERNAL}" "${FILE_NTP}"
    cp -f "${FILE_KRB5_CONF_EXTERNAL}" "${FILE_KRB5}"
    cp -f "${FILE_NSSWITCH_EXTERNAL}" "${FILE_NSSWITCH}"
  fi

  # Stop VPN & write supervisor service
  if [[ ${JOIN_SITE_VPN,,} = true ]]; then
    if [[ -n "$VPNPID" ]]; then
      kill "$VPNPID"
    fi
    {
      echo ""
      echo "[program:openvpn]"
      echo "command=/usr/sbin/openvpn --config $FILE_OPENVPNCONF"
      echo "stdout_logfile=/dev/fd/1"
      echo "stdout_logfile_maxbytes=0"
      echo "stdout_logfile_backups=0"
      echo "redirect_stderr=true"
      echo "priority=1"
    } >> "${FILE_SUPERVISORD_CUSTOM_CONF}"
  fi

  if [ "${ENABLE_TLS,,}" = true ]; then
    if [ ! -f tls/key.pem ] && [ ! -f tls/key.pem ] && [ ! -f tls/cert.pem ]; then
      echo "No custom CA found. Samba will autogenerate one"
    fi
    if [ ! -f "$FILE_PKI_DH" ]; then
      openssl dhparam -out "$FILE_PKI_DH" 2048
    fi
    sed -i "/\[global\]/a \
        \\\ttls enabled  = yes\\n\
        tls keyfile  = tls/key.pem\\n\
        tls certfile = tls/cert.pem\\n\
        #tls cafile   = tls/intermediate.pem\\n\
        tls cafile   = tls/ca.pem\\n\
        tls dh params file = tls/dh.key\\n\
        #tls crlfile   = tls/crl.pem\\n\
        #tls verify peer = ca_and_name\
    " "${FILE_SAMBA_CONF}"
  fi

  if [[ ${ENABLE_LOGS,,} = true ]]; then
    sed -i "/\[global\]/a \
      \\\tlog file = /var/log/samba/%m.log\\n\
      max log size = 10000\\n\
      log level = ${DEBUG_LEVEL}\
    " /etc/samba/smb.conf
    sed -i '/FILE:/s/^#//g' "$FILE_KRB5"
    sed -i '/FILE:/s/^#_//g' "$FILE_NTP"
  fi

  appFirstStart
}

appFirstStart () {
  loadconfdir
  update-ca-certificates
  /usr/bin/supervisord -c "${FILE_SUPERVISORD_CONF}" &

  if [ "${JOIN,,}" = false ]; then
    # Better check if net rpc is rdy
    sleep 30s
    #https://technet.microsoft.com/en-us/library/cc794902%28v=ws.10%29.aspx
    if [ "${DISABLE_DNS_WPAD_ISATAP,,}" = true ]; then
      samba-tool dns add $(hostname -s) "$LDOMAIN" wpad A 127.0.0.1 -P
      samba-tool dns add $(hostname -s) "$LDOMAIN" isatap A 127.0.0.1 -P
	fi
	#Copy root cert as der to netlogon
	#openssl x509 -outform der -in /var/lib/samba/private/tls/ca.pem -out /var/lib/samba/sysvol/"$LDOMAIN"/scripts/root.crt
	# If HostIP is set fix DNS
	IP=0
	MASK=0
    if [[ "$HOSTIP" != "NONE" ]]; then
      if grep '/' <<< "$HOSTIP" ; then
        IP=$(echo "$HOSTIP" | cut -d "/" -f1)
		MASK=$(echo "$HOSTIP" | cut -d "/" -f1)
        samba-tool sites subnet create "$HOSTIP" "$JOIN_SITE"
      else
        IP=$HOSTIP
      fi
      #this removes all internal docker IPs from samba DNS
      #samba_dnsupdate --current-ip="${HOSTIP%/*}"
	  if $(($MASK >= 1 && $MASK <= 8)); then
        IP_REVERSE=$(echo "$IP" | awk -F. '{print $1}')
	  fi
	  if (($MASK >= 9 && $MASK <= 16)); then
        IP_REVERSE=$(echo "$IP" | awk -F. '{print $2"."$1}')
	  fi
	  if (($MASK >= 17 && $MASK <= 24)); then
        IP_REVERSE=$(echo "$IP" | awk -F. '{print $3"." $2"."$1}')
	  fi
      echo "${DOMAIN_PASS}" | samba-tool dns zonecreate 127.0.0.1 "$IP_REVERSE".in-addr.arpa -UAdministrator
      dig -x "$IP"
    fi

    echo "Check NTP $(ntpq -c sysinfo)"
    echo "ckeck DNS _ldap._tcp"; host -t SRV _ldap._tcp."$LDOMAIN"
    echo "ckeck DNS _kerberos._tcp"; host -t SRV _kerberos._udp."$LDOMAIN"
    echo "check Host record"; host -t A "$HOSTNAME.$LDOMAIN"

    # https://stackoverflow.com/questions/5281341/get-local-network-interface-addresses-using-only-proc
    # https://stackoverflow.com/questions/50413579/bash-convert-netmask-in-cidr-notation
    ft_local=$(awk '$1=="Local:" {flag=1} flag' <<< "$(</proc/net/fib_trie)")
    for IF in $(ls /sys/class/net/); do
      networks=$(awk '$1=="'$IF'" && $3=="00000000" && $8!="FFFFFFFF" {printf $2 $8 "\n"}' <<< "$(</proc/net/route)" )
      for net_hex in $networks; do
        net_dec=$(awk '{gsub(/../, "0x& "); printf "%d.%d.%d.%d\n", $4, $3, $2, $1}' <<< $net_hex)
        mask_dec=$(awk '{gsub(/../, "0x& "); printf "%d.%d.%d.%d\n", $8, $7, $6, $5}' <<< $net_hex)
        c=0 x=0$( printf '%o' ${mask_dec//./ } )
        while [ $x -gt 0 ]; do
          let c+=$((x%2)) 'x>>=1'
        done
        CIDR=$net_dec/$c
        echo "Found the following network: $CIDR - Trying to create Subnet and add to $JOIN_SITE"
        samba-tool sites subnet create "$CIDR" "$JOIN_SITE"
      done
    done
	
    #You want to set SeDiskOperatorPrivilege on your member server to manage your share permissions:
	ARGS_NET_RPC=()
	ARGS_NET_RPC+=("$UDOMAIN\\Domain Admins")
	ARGS_NET_RPC+=("SeDiskOperatorPrivilege")
	ARGS_NET_RPC+=("-U$UDOMAIN\\${DOMAIN_USER,,}")
	ARGS_NET_RPC+=("-d $DEBUG_LEVEL")
    echo "${DOMAIN_PASS}" | net rpc rights grant "${ARGS_NET_RPC[@]}"
  else
  #ERROR?`{{DC_IP}}:$LDAP_SUFFIX:g {DC_DNS}}:$LDAP_SUFFIX:g
    if [ -f "$FILE_SAMBA_WINSLDB" ] && [ "${ENABLE_WINS}" = true ];then
      sed -e "s: {{DC_IP}}:$LDAP_SUFFIX:g" \
          -e "s: {{DC_DNS}}:$LDAP_SUFFIX:g" \
          "${FILE_SAMBA_SCHEMA_WINSREPL}.j2" > "${FILE_SAMBA_SCHEMA_WINSREPL}"
    ldbadd -H "$FILE_SAMBA_WINSLDB" "$FILE_SAMBA_SCHEMA_WINSREPL"
    fi
  fi
  # https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller
  #Test Kerberos
  if echo "${DOMAIN_PASS}" | kinit "${DOMAIN_USER}";then
    echo " kinit successfull"
    klist
  fi
  # Verify Samba Fileserver is working
  smbclient -L localhost -N
  # Test Samba Auth
  smbclient //localhost/netlogon -U"${DOMAIN_USER}" -c 'ls' --password "${DOMAIN_PASS}"
  wait
  # source /scripts/firstrun.sh
}

appStart () {
  update-ca-certificates
  loadconfdir
  /usr/bin/supervisord -c "${FILE_SUPERVISORD_CONF}"
}

#https://gist.github.com/meetnick/fb5587d25d4174d7adbc8a1ded642d3c
loadconfdir () {
# adds includes.conf file existance to smb.conf file
  if ! grep -q 'include = '"${FILE_SAMBA_INCLUDES}" "${FILE_SAMBA_CONF}" ; then
    sed -i "/\[global\]/a \
      \\\tinclude = ${FILE_SAMBA_INCLUDES}\
    " "${FILE_SAMBA_CONF}"
  fi

  # create directory smb.conf.d to store samba .conf files
  mkdir -p "$DIR_SAMBA_CONF"

  # populates includes.conf with files (type -f) in smb.conf.d directory
  find "${DIR_SAMBA_CONF}" -maxdepth 1 -type f| sed -e 's/^/include = /' > "$FILE_SAMBA_INCLUDES"
}

#Todo:
# ID_Map replication: https://wiki.samba.org/index.php/Joining_a_Samba_DC_to_an_Existing_Active_Directory#Built-in_User_.26_Group_ID_Mappings
# SYSVOL replication

######### BEGIN MAIN function #########
config
# If the supervisor conf isn't there, we're spinning up a new container
if [[ -f "${FILE_SAMBA_CONF_EXTERNAL}" ]]; then
  cp -f "${FILE_SAMBA_CONF_EXTERNAL}" "${FILE_SAMBA_CONF}"
  cp -f "${FILE_SUPERVISORD_CONF_EXTERNAL}" "${FILE_SUPERVISORD_CUSTOM_CONF}"
  cp -f "${FILE_NTP_CONF_EXTERNAL}" "${FILE_NTP}"
  cp -f "${FILE_KRB5_CONF_EXTERNAL}" "${FILE_KRB5}"
  cp -f "${FILE_NSSWITCH_EXTERNAL}" "${FILE_NSSWITCH}"
  appStart
else
  appSetup
fi

exit 0
######### END MAIN function #########