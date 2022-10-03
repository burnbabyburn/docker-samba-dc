#FROM ubuntu:devel as builder
#ENV DEBIAN_FRONTEND noninteractive

#RUN apt-get update \
#    && apt-get upgrade -y \
#    && apt-get install -y msitools wget curl \
#    && admxurl=$(curl -s 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=103507' | grep -o -m1 -E "url=http.*msi" | cut -d '=' -f2) \
#    && wget -O admx.msi "$admxurl" \
#    && msiextract -C /tmp/ admx.msi

FROM ubuntu:devel

ENV DEBIAN_FRONTEND=noninteractive \
	DIR_DATA=/data \
	DIR_GPO=$DIR_DATA/gpo \
	DIR_LDIF=/ldif \
	DIR_SCRIPTS=/scripts

RUN apt-get update \
    && apt-get upgrade -y \
	&& apt-get install -y bind9 chrony pkg-config attr acl samba smbclient tdb-tools ldb-tools ldap-utils winbind libnss-winbind libpam-winbind libpam-krb5 krb5-user supervisor dnsutils nano python3-setproctitle \
	#openssl for dh key \
    # line below is for multi-site config (ping is for testing later) \
    #&& apt-get install -y openvpn inetutils-ping \  
	&& apt-get clean autoclean \
    && apt-get autoremove --yes \
    && rm -rf /var/lib/apt /var/lib/dpkg /var/lib/cache /var/lib/log/ \
	&& rm -rf /tmp/* /var/tmp/*	\
	&& rm -rf /etc/bind /etc/chrony /etc/krb5.conf /etc/nsswitch.conf /etc/samba /etc/supervisor /var/cache/bind /var/cache/samba /var/lib/bind /var/lib/chrony /var/lib/samba /var/log/bind /var/log/chrony /var/log/samba /var/log/supervisor \
	&& mkdir /etc/bind /etc/chrony /etc/krb5.conf /etc/nsswitch.conf /etc/samba /etc/supervisor /var/cache/bind /var/cache/samba /var/lib/bind /var/lib/chrony /var/lib/samba /var/log/bind /var/log/chrony /var/log/samba /var/log/supervisor $DIR_DATA

COPY $DIR_LDIF $DIR_LDIF
COPY /etc /etc
COPY $DIR_SCRIPTS $DIR_SCRIPTS
COPY $DIR_GPO $DIR_GPO
#COPY --from=builder ${src} $DIR_GPO

RUN chmod -R +x $DIR_SCRIPTS

EXPOSE 42 53 53/udp 88 88/udp 135 137-138/udp 139 389 389/udp 445 464 464/udp 636 3268-3269 49152-65535

WORKDIR /

HEALTHCHECK CMD smbcontrol smbd num-children || exit 1
ENTRYPOINT ["sh", "/scripts/init.sh"]