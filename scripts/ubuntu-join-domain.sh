#!/bin/sh

# If run in container u need to start it with --security-opt seccomp=unconfined
# https://docs.docker.com/engine/security/seccomp/
# https://gist.github.com/nathabonfim59/b088db8752673e1e7acace8806390242

# Configure here
# ======================================
DOMAIN=${DOMAIN_ACC_LOCK_THRESHOLD:-SAM.DOM}
PROVISIONINGUSER=${PROVISIONINGUSER:-Administrator}
PROVISIONINGPASSWORD=${PROVISIONINGPASSWORD:-Pa11w0rd!}
SUDOUSERS=${SUDOUSERS:-Administrator!}
OSNAME=$(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | cut -d '(' -f1)
OSVERSION=$(grep VERSION_ID /etc/os-release | cut -d '=' -f2 | tr -d '"')
TZ=Europe/Berlin
# ======================================

export DEBIAN_FRONTEND=noninteractive

UP_DOMAIN=$(printf "%s" "$DOMAIN" | tr '[:lower:]' '[:upper:]')
LO_DOMAIN=$(printf "%s" "$DOMAIN" | tr '[:upper:]' '[:lower:]')

if [ ! -f /etc/timezone ] && [ -n "${TZ}" ]; then
  printf 'Set timezone'
  cp "/usr/share/zoneinfo/${TZ}" /etc/localtime
  printf "%s" "${TZ}" >/etc/timezone
  dpkg-reconfigure tzdata
fi

#https://access.redhat.com/discussions/3370851
#RDNS option see above
{
echo "" > /etc/krb5.conf
echo "[libdefaults]"
echo "	default_realm = ${UP_DOMAIN}"
echo "	kdc_timesync = 1"
echo "	ccache_type = 4"
echo "	forwardable = true"
echo "	proxiable = true"
echo "	fcc-mit-ticketflags = true"
echo "	rdns = false"

echo ""
echo "[realms]"
echo "$UP_DOMAIN = {"
echo "        default_domain = $LO_DOMAIN"
echo "}"
echo ""
echo "[domain_realm]"
echo "$LO_DOMAIN = $UP_DOMAIN"
echo ".$LO_DOMAIN = $UP_DOMAIN"
} > /etc/krb5.conf

{
echo " "
echo "[active-directory]"
echo " default-client = sssd"
echo " os-name = ${OSNAME}"
echo " os-version = ${OSVERSION}"
echo " "
echo "[service]"
echo " automatic-install = no"
echo " "
echo "[${UP_DOMAIN}]"
echo " fully-qualified-names = yes"
echo " automatic-id-mapping = no"
echo " user-principal = yes"
echo " manage-system = yes"
} > /etc/realmd.conf

echo "auto-create home directory in the next configuration screen."
pam-auth-update --enable mkhomedir

echo "Time to test..."
echo "Discovering..."
realm -v discover "${UP_DOMAIN}" --install=/
echo "Testing admin connection..."
printf "%s" "${PROVISIONINGPASSWORD}" | kinit "${PROVISIONINGUSER}"
klist
kdestroy 

echo ""
echo "Joining domain"
printf "%s" "${PROVISIONINGPASSWORD}" | realm join --verbose --user="${PROVISIONINGUSER}"  "${UP_DOMAIN}" --install=/

echo "Allowing users to log in"
realm permit --all --install=/

echo "Adding domain users to sudoers..."
for U in $SUDOUSERS; do
	echo "Adding ${UP_DOMAIN}\\${U}..."
	sed -i "s/# User privilege specification/# User privilege specification\n${U} ALL=(ALL) ALL/g" /etc/sudoers
done

sssd -i --logger=stderr