#!/bin/bash

# Configure here
# ======================================
HOSTNAME=VirtualUbuntu
DOMAIN=corp.example.com
COMPUTEROU="DC=corp,DC=example,DC=com"
PROVISIONINGUSER=administrator
OSNAME="Ubuntu Workstation"
OSVERSION=18.04
SUDOUSERS="user1 administrator"
USEDOMAININHOMEDIR="False"
# ======================================

UP_DOMAIN=${DOMAIN^^}
LO_DOMAIN=${DOMAIN,,}

echo "Setting hostnames..."
hostnamectl set-hostname ${HOSTNAME}

DEBIAN_FRONTEND=noninteractive
{
echo "" > /etc/krb5.conf
echo "[libdefaults]"
echo "	default_realm = ${UP_DOMAIN}"
echo "	kdc_timesync = 1"
echo "	ccache_type = 4"
echo "	forwardable = true"
echo "	proxiable = true"
echo "	fcc-mit-ticketflags = true"
echo ""
echo "[realms]"
} >> /etc/krb5.conf

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
} >> /etc/realmd.conf

echo "Now, check off the box for auto-create home directory in the next configuration screen."
echo -n "Press enter to continue..."
#read E
read -r E
pam-auth-update

echo "Time to test..."
echo "Discovering..."
realm discover ${UP_DOMAIN}
echo "Testing admin connection..."
kinit ${PROVISIONINGUSER}
klist
kdestroy 

echo ""
echo -n "If the above test didn't error, press ENTER to join the domain."
#read E
read -r E

echo ""
echo "Joining domain"
realm join --verbose --user=${PROVISIONINGUSER} --computer-ou=${COMPUTEROU} ${UP_DOMAIN}

echo "Configuring SSSD..."
if [ -f /etc/sssd/sssd.conf ]; then
rm /etc/sssd/sssd.conf
fi
touch /etc/sssd/sssd.conf


{
echo "[sssd]"     
echo "domains = ${LO_DOMAIN}"
echo "config_file_version = 2"
echo "services = nss, pam"
echo ""
echo "[domain/${LO_DOMAIN}]"
echo "ad_domain = ${LO_DOMAIN}"
echo "krb5_realm = ${UP_DOMAIN}"
echo "realmd_tags = manages-system joined-with-adcli"
echo "cache_credentials = True"
echo "id_provider = ad"
echo "krb5_store_password_if_offline = True"
echo "default_shell = /bin/bash"
echo "ldap_id_mapping = True"        
} >> /etc/sssd/sssd.conf

if [ $USEDOMAININHOMEDIR == "False" ]; then
	echo "fallback_homedir = /home/%u" >> /etc/sssd/sssd.conf
else
	echo "fallback_homedir = /home/%d/%u" >> /etc/sssd/sssd.conf
fi
echo "access_provider = ad" >> /etc/sssd/sssd.conf

echo "Allowing users to log in"
realm permit --all

if [ $USEDOMAININHOMEDIR == "True" ]; then
	echo "Now, enter '/home/${LO_DOMAIN}/' with the trailing slash in the next configuration screen."
	echo -n "Press enter to continue..."
	#read E
	read -r E
	#SC2034 (warning): E appears unused. Verify use (or export if used externally).
	dpkg-reconfigure apparmor
fi

echo "Adding domain users to sudoers..."
for U in $SUDOUSERS; do
	echo "Adding ${UP_DOMAIN}\\${U}..."
	sed -i "s/# User privilege specification/# User privilege specification\n${U} ALL=(ALL) ALL/g" /etc/sudoers
done

echo "All done! Time to reboot!"
