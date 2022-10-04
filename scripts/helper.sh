#!/bin/sh
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
    -e "s:{{ NETBIOS }}:$(printf "%s" "$DOMAIN_NETBIOS" | tr '[:upper:]' '[:lower:]'):g" \
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
  if [ "${DEBUG_ENABLE}" = true ]; then printf "%s" "$ESCAPED_PATTERN"; echo "$ESCAPED_REPLACE"; fi
  if ! grep -R "^[#]*\s*$1[[:space:]]=.*" "$FILE" > /dev/null; then
    echo "Key: $1 not found. APPENDING $1 = $2 after $PATTERN"
    sed ${SED_PARAM}  "/^$ESCAPED_PATTERN"'/a\\t'"$1 = $ESCAPED_REPLACE" -i "$FILE"
  else
    echo "Key: $1 found. SETTING $1 = $2"
    sed ${SED_PARAM} -r "s/^[#]*\s*$1[[:space:]]=.*/\\t$1 = $ESCAPED_REPLACE/" -i "$FILE"
  fi
}

# https://stackoverflow.com/questions/41451159/how-to-execute-a-script-when-i-terminate-a-docker-container
backupConfig () {
  if [ ! -d "${DIR_DATA}/etc" ]; then mkdir "${DIR_DATA}/etc"; fi
  cp -afv "${DIR_BIND9}" "${DIR_DATA}${DIR_BIND9}"
  cp -afv "${DIR_CHRONY}" "${DIR_DATA}${DIR_CHRONY}"
  cp -afv "${DIR_SAMBA_ETC}" "${DIR_DATA}${DIR_SAMBA_ETC}"
  cp -afv "${DIR_SUPERVISOR}" "${DIR_DATA}${DIR_SUPERVISOR}"
  cp -afv "${FILE_KRB5}" "${DIR_DATA}${FILE_KRB5}"
  cp -afv "${FILE_NSSWITCH}" "${DIR_DATA}${FILE_NSSWITCH}"
  if [ ! -d "${DIR_DATA}/var/lib" ]; then mkdir -p "${DIR_DATA}/var/lib"; fi
  cp -afv "${DIR_SAMBA_DATA_PREFIX}" "${DIR_DATA}${DIR_SAMBA_DATA_PREFIX}"
}
restoreConfig () {
  cp -avf "${DIR_DATA}/etc" "/"
  cp -avf "${DIR_DATA}/var" "/"
}

# If Hostname is in CIDR notaion, create a reverse DNS zone and a subnet in $JOIN_SITE (default-First-Site-Name)
RDNSZonefromCIDR () {
  IP=''
  MASK=''
  IP_REVERSE=''
  IP_NET=''
  if [ "$HOSTIP" != "NONE" ]; then
    if echo "$HOSTIP" | grep -q '/' ; then
      IP=$(echo "$HOSTIP" | cut -d "/" -f1)
      MASK=$(echo "$HOSTIP" | cut -d "/" -f2)
      # https://stackoverflow.com/questions/13777387/check-for-ip-validity
      if echo "$IP" | grep -E '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b'; then
        if [ "${MASK}" -ge 1 ] && [ "${MASK}" -le 8 ];then
          IP_REVERSE=$(echo "$IP" | awk -F. '{print $1}')
          IP_NET=$(echo "$IP" | awk -F. '{print $1".0.0.0"}')
        fi
        if [ "${MASK}" -ge 9 ] && [ "${MASK}" -le 16 ];then
          IP_REVERSE=$(echo "$IP" | awk -F. '{print $2"."$1}')
          IP_NET=$(echo "$IP" | awk -F. '{print $1"."$2".0.0"}')
        fi
        if [ "${MASK}" -ge 17 ] && [ "${MASK}" -le 24 ];then
          IP_REVERSE=$(echo "$IP" | awk -F. '{print $3"." $2"."$1}')
          IP_NET=$(echo "$IP" | awk -F. '{print $1"."$2"."$3".0"}')
        fi
        samba-tool sites subnet create "${IP_NET}/${MASK}" "$JOIN_SITE" "${SAMBA_DEBUG_OPTION}"
        echo "${DOMAIN_PASS}" | samba-tool dns zonecreate 127.0.0.1 "$IP_REVERSE".in-addr.arpa -UAdministrator "${SAMBA_DEBUG_OPTION}" && printf "Reverse DNS Zone %s.in-addr.arpa for site %s created\n" "${IP_REVERSE}" "${JOIN_SITE}"
      else
        printf "Cant not create subnet: %s for site: %s. Invalid IP parameter ... exiting\n" "${HOSTIP}" "${JOIN_SITE}"; exit 1 ; fi
      fi
      #this removes all internal docker IPs from samba DNS
      #samba_dnsupdate --current-ip="${HOSTIP%/*}"
    fi
}
GetAllCidrCreateSubnet () {
  # https://stackoverflow.com/questions/5281341/get-local-network-interface-addresses-using-only-proc
  # https://stackoverflow.com/questions/50413579/bash-convert-netmask-in-cidr-notation
  #ft_local=$(awk '$1=="Local:" {flag=1} flag' <<< "$(</proc/net/fib_trie)")
  for IF in /sys/class/net/*; do
    IF=$(echo "$IF" | cut -d / -f5)
    if [ "$IF" != lo ]; then
      networks=$(awk '$1=="'"$IF"'" && $3=="00000000" && $8!="FFFFFFFF" {printf $2 $8 "\n"}' /proc/net/route)
    else
      break
    fi
    for net_hex in $networks; do
      net_dec=$(echo "$net_hex" | awk '{gsub(/../, "0x& "); printf "%d.%d.%d.%d\n", $4, $3, $2, $1}' )
      mask_dec=$(echo "$net_hex" | awk '{gsub(/../, "0x& "); printf "%d.%d.%d.%d\n", $8, $7, $6, $5}')
      c="$(mask2cdr "$mask_dec")"
      CIDR=$net_dec/$c
      if echo "$net_dec" | grep -E '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b'; then samba-tool sites subnet create "$CIDR" "$JOIN_SITE" "${SAMBA_DEBUG_OPTION}"
      else echo "Cant not create subnet: $CIDR for site: $JOIN_SITE. Invalid parameter ... exiting" ; exit 1 ; fi
    done
  done
}

mask2cdr ()
{
   # Assumes there's no "255." after a non-255 byte in the mask
   x=${1##*255.}
   set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) "${x%%.*}"
   x=${1%%"$3"*}
   echo $(( $2 + (${#x}/4) ))
}
 
cdr2mask ()
{
   # Number of args to shift, 255..255, first non-255 byte, zeroes
   set -- $(( 5 - ($1 / 8) )) 255 255 255 255 $(( (255 << (8 - ($1 % 8))) & 255 )) 0 0 0
   [ "$1" -gt 1 ] && shift "$1" || shift
   echo "${1-0}"."${2-0}"."${3-0}"."${4-0}"
}

EnableChangeKRBTGTSupervisord () {
  {
    echo ""
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

EnableEventlogSupervisord () {
  {
    echo ""
	echo ""
    echo "[program:Eventlog_Samba]"
    echo "command=/usr/bin/tail -f ${FILE_SAMBA_LOG} | parselog.pl | eventlogadm -o write ${EVENTLOG_SAMBA}"
    echo "stdout_logfile=/dev/fd/1"
    echo "stdout_logfile_maxbytes=0"
    echo "stdout_logfile_backups=0"
    echo "redirect_stderr=true"
    echo "priority=1"
  } >> "${FILE_SUPERVISORD_CUSTOM_CONF}"
}

EnableBind9 () {
  {
    echo ""
	echo ""
    echo "[program:bind9]"
    echo "command=/usr/sbin/named {{ BIND9_START_PARAM }}"
    echo "stdout_logfile=/dev/fd/1"
    echo "stdout_logfile_maxbytes=0"
    echo "stdout_logfile_backups=0"
    echo "redirect_stderr=true"
    echo "priority=10"
  } >> "${FILE_SUPERVISORD_CUSTOM_CONF}"
}