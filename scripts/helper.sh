#!/bin/bash

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
}

# AddSetKeyValueSMBCONF workgroup MYWORKGROUPNAME
https://stackoverflow.com/questions/407523/escape-a-string-for-a-sed-replace-pattern
https://fabianlee.org/2019/10/05/bash-setting-and-replacing-values-in-a-properties-file-use-sed/
AddSetKeyValueSMBCONF() {
PATTERN="[global]"
ESCAPED_PATTERN=$(printf '%s\n' "$PATTERN" | sed -e 's/[]\/$*.^[]/\\&/g')
ESCAPED_REPLACE=$(printf '%s\n' "$2" | sed -e 's/[\/&]/\\&/g')
echo $ESCAPED_PATTERN
echo $ESCAPED_REPLACE
if ! grep -R "^[#]*\s*$1[[:space:]]=.*" "${FILE_SAMBA_CONF}" > /dev/null; then
  echo "Key: $1 not found. APPENDING $1 = $2 after $PATTERN"
  sed -i "/^$ESCAPED_PATTERN"'/a\\t'"$1 = $ESCAPED_REPLACE" "${FILE_SAMBA_CONF}"
else
  echo "Key: $1 found. SETTING $1 = $2"
  sed -ir "s/^[#]*\s*$1[[:space:]]=.*/\\t$1 = $ESCAPED_REPLACE/" "${FILE_SAMBA_CONF}"
fi
}

https://stackoverflow.com/questions/41451159/how-to-execute-a-script-when-i-terminate-a-docker-container
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