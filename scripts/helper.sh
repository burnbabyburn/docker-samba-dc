#!/bin/bash
# https://docs.microsoft.com/de-de/archive/blogs/activedirectoryua/identity-management-for-unix-idmu-is-deprecated-in-windows-server
# https://wiki.samba.org/index.php/Maintaining_Unix_Attributes_in_AD_using_ADUC
# Improvements: e.g. set memberofid
setupSchemaRFC2307File() {
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

  # https://wiki.samba.org/index.php/Setting_up_Samba_as_a_Domain_Member#Mapping_the_Domain_Administrator_Account_to_the_Local_root_User
  # When using the ad ID mapping back end, never set a uidNumber attribute for the domain Administrator account.
  # If the account has the attribute set, the value will override the local UID 0 of the root user on Samba AD DC's and thus the mapping fails.
  #UID_ADMINISTRATOR=$((IMAP_UID_START+2))

  # https://wiki.samba.org/index.php/Setting_up_a_Share_Using_Windows_ACLs#Granting_the_SeDiskOperatorPrivilege_Privilege
  # If you use the winbind 'ad' backend on Unix domain members and you add a gidNumber attribute to the Domain Admins group in AD,
  # you will break the mapping in idmap.ldb. Domain Admins is mapped as ID_TYPE_BOTH in idmap.ldb, this is to allow the group to own files in Sysvol on a Samba AD DC.
  # It is suggested you create a new AD group (Unix Admins for instance),
  # give this group a gidNumber attribute and add it to the Administrators group and then, on Unix, use the group wherever you would normally use Domain Admins

  #Next Counter value uesd by ADUC for NIS Extension GID and UID
  IMAP_GID_END=$((IMAP_GID_START+15))
  IMAP_UID_END=$((IMAP_UID_START+1))

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
}

# AddSetKeyValueSMBCONF workgroup MYWORKGROUPNAME
# https://stackoverflow.com/questions/407523/escape-a-string-for-a-sed-replace-pattern
# https://fabianlee.org/2019/10/05/bash-setting-and-replacing-values-in-a-properties-file-use-sed/

SetKeyValueFilePattern() {
  PATTERN=${4:-[global]}
  FILE=${3:-"$FILE_SAMBA_CONF"}
  ESCAPED_PATTERN=$(printf '%s\n' "$PATTERN" | sed -e 's/[]\/$*.^[]/\\&/g')
  ESCAPED_REPLACE=$(printf '%s\n' "$2" | sed -e 's/[\/&]/\\&/g')
  echo "$ESCAPED_PATTERN"
  echo "$ESCAPED_REPLACE"
  if ! grep -R "^[#]*\s*$1[[:space:]]=.*" "$FILE" > /dev/null; then
    echo "Key: $1 not found. APPENDING $1 = $2 after $PATTERN"
    sed -i "/^$ESCAPED_PATTERN"'/a\\t'"$1 = $ESCAPED_REPLACE" "$FILE"
  else
    echo "Key: $1 found. SETTING $1 = $2"
    sed -ir "s/^[#]*\s*$1[[:space:]]=.*/\\t$1 = $ESCAPED_REPLACE/" "$FILE"
  fi
}

# https://stackoverflow.com/questions/41451159/how-to-execute-a-script-when-i-terminate-a-docker-container
backupConfig () {
  cp -f "${FILE_SAMBA_CONF}" "${FILE_SAMBA_CONF_EXTERNAL}"
  cp -f "${FILE_SUPERVISORD_CUSTOM_CONF}" "${FILE_SUPERVISORD_CONF_EXTERNAL}"
  cp -f "${FILE_NTP}" "${FILE_NTP_CONF_EXTERNAL}"
  cp -f "${FILE_KRB5}" "${FILE_KRB5_CONF_EXTERNAL}"
  cp -f "${FILE_NSSWITCH}" "${FILE_NSSWITCH_EXTERNAL}"
  cp -f "/etc/passwd" "${DIR_SAMBA_EXTERNAL}/passwd"
  cp -f "/etc/group" "${DIR_SAMBA_EXTERNAL}/group"
  cp -f "/etc/shadow" "${DIR_SAMBA_EXTERNAL}/shadow"
}
restoreConfig () {
  cp -f "${FILE_SAMBA_CONF_EXTERNAL}" "${FILE_SAMBA_CONF}"
  cp -f "${FILE_SUPERVISORD_CONF_EXTERNAL}" "${FILE_SUPERVISORD_CUSTOM_CONF}"
  cp -f "${FILE_NTP_CONF_EXTERNAL}" "${FILE_NTP}"
  cp -f "${FILE_KRB5_CONF_EXTERNAL}" "${FILE_KRB5}"
  cp -f "${FILE_NSSWITCH_EXTERNAL}" "${FILE_NSSWITCH}"
  cp -f "${DIR_SAMBA_EXTERNAL}/passwd" "/etc/passwd"
  cp -f "${DIR_SAMBA_EXTERNAL}/group" "/etc/group"
  cp -f "${DIR_SAMBA_EXTERNAL}/shadow" "/etc/shadow"
}

# If Hostname is in CIDR notaion, create a reverse DNS zone and a subnet in $JOIN_SITE (default-First-Site-Name)
RDNSZonefromCIDR () {
  IP=''
  MASK=''
  IP_REVERSE=''
  IP_NET=''
  if [[ "$HOSTIP" != "NONE" ]]; then
    if grep '/' <<< "$HOSTIP" ; then
      IP=$(echo "$HOSTIP" | cut -d "/" -f1)
      MASK=$(echo "$HOSTIP" | cut -d "/" -f2)
      # https://stackoverflow.com/questions/13777387/check-for-ip-validity
      if [[ $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        if ((MASK >= 1 && MASK <= 8)); then
          IP_REVERSE=$(echo "$IP" | awk -F. '{print $1}')
          IP_NET=$(echo "$IP" | awk -F. '{print $1".0.0.0"}')
        fi
        if ((MASK >= 9 && MASK <= 16)); then
          IP_REVERSE=$(echo "$IP" | awk -F. '{print $2"."$1}')
          IP_NET=$(echo "$IP" | awk -F. '{print $1"."$2".0.0"}')
        fi
        if ((MASK >= 17 && MASK <= 24)); then
          IP_REVERSE=$(echo "$IP" | awk -F. '{print $3"." $2"."$1}')
          IP_NET=$(echo "$IP" | awk -F. '{print $1"."$2"."$3".0"}')
        fi
        samba-tool sites subnet create "${IP_NET}/${MASK}" "$JOIN_SITE" "${SAMBA_DEBUG_OPTION}"
        echo "${DOMAIN_PASS}" | samba-tool dns zonecreate 127.0.0.1 "$IP_REVERSE".in-addr.arpa -UAdministrator "${SAMBA_DEBUG_OPTION}"
      else
        echo "Cant not create subnet: ${HOSTIP} for site: $JOIN_SITE. Invalid IP parameter ... exiting" ; exit 1 ; fi
      fi
      #this removes all internal docker IPs from samba DNS
      #samba_dnsupdate --current-ip="${HOSTIP%/*}"
    fi

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
      if [[ $net_dec =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then samba-tool sites subnet create "$CIDR" "$JOIN_SITE" "${SAMBA_DEBUG_OPTION}"
      else echo "Cant not create subnet: $CIDR for site: $JOIN_SITE. Invalid parameter ... exiting" ; exit 1 ; fi
    done
  done
}
EnableChangeKRBTGTSupervisord () {
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
}

EnableOpenvpnSupervisord () {
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
}