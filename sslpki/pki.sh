#!/bin/bash

export BASEDIR=/sslpki

ca=ca               # CA name
dir=$ENV::BASEDIR         # Top dir
CRLURL=http://crl.example.com/example.com.crl
DC=$ENV::HOSTNAME
DCGUID=$ENV::HEXGUID
name_opt=multiline,-esc_msb,utf8 # Display UTF-8 characters

#COUNTRY     = $ENV::C
#STATE       = $ENV::S
#LOCALITY    = $ENV::L
#ORG         = $ENV::O
#OU          = $ENV::OU
#DOMAIN      = $ENV::DOMAIN

DCpart=$(echo "$DOMAIN" | awk -F '.' '{for(i = 1; i <= NF; i++) {printf ",DC=" $i}}')
BASE="OU=Domain Controllers${DCpart}"

GUID=$(ldbsearch  -H /var/lib/samba/private/sam.ldb --basedn="$BASE" "CN=${HOSTNAME}" objectGUID \
  | grep '^objectGUID:' \
  | awk '{print $2}' \
)

DN=$(ldbsearch  -H /var/lib/samba/private/sam.ldb --basedn="$BASE" "CN=${HOSTNAME}" distinguishedName \
  | grep dn: \
  | cut -d ':' -f2 \
  | sed -e 's/^[ \t]*//'
)

HEXGUID="$(convertToHex "$GUID" | awk '{print $3}' | tr '[:lower:]' '[:upper:]')" 
export HEXGUID=$HEXGUID

ROOT_CERT="$BASEDIR/ca.pem"
ROOT_KEY="$BASEDIR/private/ca.key"
ROOT_CNF="$BASEDIR/root.cnf"

MKDCS_CERT="$BASEDIR/certs/$HOSTNAME.pem"
MKDCS_KEY="$BASEDIR/private/$HOSTNAME.key"
MKDCS_REQ="$BASEDIR/newcerts/$HOSTNAME.req"
MKDCS_CNF="$BASEDIR/samba.cnf"

if [ ! -d $BASEDIR ]; then
  mkdir -p $BASEDIR
  mkdir -p $BASEDIR/private $BASEDIR/db $BASEDIR/crl $BASEDIR/certs $BASEDIR/newcerts
  chmod 700 -R $BASEDIR/private

  cp /dev/null $BASEDIR/db/db
  cp /dev/null $BASEDIR/db/db.attr
  echo 00 > $BASEDIR/db/crt.serial
  echo 00 > $BASEDIR/db/crl.serial
fi

if ! [ -f $ROOT_CERT ] && [ -f $ROOT_KEY ]; then
  if ! grep -q '\[ ca_dn \]' "$ROOT_CNF"; then
    echo " ">> "$ROOT_CNF"
    echo "[ ca_dn ]" >> "$ROOT_CNF"
    IFS='.'
    c=0
    for i in $DOMAIN
    do
	  j=$(echo "$i" | tr -d ' ')
      echo "$c.domainComponent=\"$j\"" >> "$ROOT_CNF"
	  echo "\"commonName=Samba Active Directory CA\""
      c=$((c+=1))
    done
  IFS=' '
  fi
  #CA
  openssl req -new -x509 -sha256 -newkey rsa:4096 -days 3650 -nodes -keyout $ROOT_KEY -out $ROOT_CERT  -config "$ROOT_CNF"
  # Print CA 
  openssl x509 -in $ROOT_CERT -text
fi

if ! [ -f "$MKDCS_CERT" ] && [ -f "$MKDCS_KEY" ]; then
  if ! grep -q '\[ ca_dn \]' "$MKDCS_CNF"; then
    echo " ">> "$MKDCS_CNF"
    echo "[ ca_dn ]" >> "$MKDCS_CNF"
    IFS='.'
    c=0
    for i in $DOMAIN
    do
      echo "$c.domainComponent=\"$i\"" >> "$MKDCS_CNF"
      c=$((c+=1))
    done
    IFS=' '
    {
      #echo "organizationName        = \"$TLS_PKI_O\""
      echo "organizationalUnitName=\"Domain Controllers\""
      echo "commonName=\"$DN\""
    } >> "$MKDCS_CNF"
  fi
  openssl req -new -sha256 -newkey rsa:4096 -days 735 -nodes -keyout "$MKDCS_KEY" -out "$MKDCS_REQ" -config "$MKDCS_CNF"
  openssl ca -extensions mskdc_ext -config "$ROOT_CNF" -in "$MKDCS_REQ" -out "$MKDCS_CERT"
fi

convertToHex() {
  # Inspired by https://docs.microsoft.com/en-us/troubleshoot/windows-server/admin-development/convert-string-guid-to-hexadecimal-string
  RAW="$1"
  GUID=$(echo "$RAW" | sed 's/\-//g')

  HEX="${GUID:6:2}"
  HEX="${HEX}${GUID:4:2}"
  HEX="${HEX}${GUID:2:2}"
  HEX="${HEX}${GUID:0:2}"
  HEX="${HEX}${GUID:10:2}"
  HEX="${HEX}${GUID:8:2}"
  HEX="${HEX}${GUID:14:2}"
  HEX="${HEX}${GUID:12:2}"
  len=${#HEX}
  HEX="${HEX}${GUID:16:${len}}"

  echo "$RAW -> $HEX"
}