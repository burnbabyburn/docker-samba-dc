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
	DIR_GPO=/gpo \
	DIR_LDIF=/ldif \
	DIR_SAMBA_CONF=$DIR_DATA/etc/samba/conf.d \
	DIR_SCRIPTS=/scripts

RUN apt-get update \
    && apt-get upgrade -y \
	&& apt-get install -y bind9 chrony pkg-config attr acl samba smbclient tdb-tools ldb-tools ldap-utils winbind libnss-winbind libpam-winbind libpam-krb5 krb5-user supervisor dnsutils nano python3-setproctitle\
	#openssl for dh key \
    # line below is for multi-site config (ping is for testing later) \
    #&& apt-get install -y openvpn inetutils-ping \  
	&& apt-get clean autoclean \
    && apt-get autoremove --yes \
    && rm -rf /var/lib/apt /var/lib/dpkg /var/lib/cache /var/lib/log/ \
	&& rm -rf /tmp/* /var/tmp/*	\
	&& mkdir /backup /backup/etc /backup/lib /backup/log /backup/cache \
	&& rm -rf /etc/bind /etc/chrony /etc/krb5.conf /etc/nsswitch.conf /etc/samba /etc/supervisor /var/cache/bind /var/cache/samba /var/lib/bind /var/lib/chrony /var/lib/samba /var/log/bind /var/log/chrony /var/log/samba /var/log/supervisor \
	&& mkdir -p $DIR_DATA/etc/bind $DIR_DATA/etc/chrony $DIR_DATA/etc/samba $DIR_DATA/etc/supervisor $DIR_DATA/cache/bind $DIR_DATA/cache/samba $DIR_DATA/lib/bind $DIR_DATA/lib/chrony $DIR_DATA/lib/samba $DIR_DATA/log/bind \
	            $DIR_DATA/log/chrony $DIR_DATA/log/samba $DIR_DATA/log/supervisor \
	# Symlink crashes github actions works fine otherwise
	&& ln -s $DIR_DATA/etc/bind /etc/bind \
	&& ln -s $DIR_DATA/etc/chrony /etc/chrony \
	&& ln -s $DIR_DATA/etc/nsswitch.conf /etc/ \
	&& ln -s $DIR_DATA/etc/krb5.conf /etc/ \
	&& ln -s $DIR_DATA/etc/samba /etc/samba \
	&& ln -s $DIR_DATA/etc/supervisor /etc/supervisor \
	&& ln -s $DIR_DATA/lib/bind /var/lib/bind \
	&& ln -s $DIR_DATA/lib/chrony /var/lib/chrony \
	&& ln -s $DIR_DATA/lib/samba /var/lib/samba \
	&& ln -s $DIR_DATA/log/bind /var/log/bind \
	&& ln -s $DIR_DATA/log/chrony /var/log/chrony \
    && ln -s $DIR_DATA/log/samba /var/log/samba \
	&& ln -s $DIR_DATA/log/supervisor /var/log/supervisor \
	&& ln -s $DIR_DATA/cache/bind /var/cache/bind \
	&& ln -s $DIR_DATA/cache/samba /var/cache/samba

COPY /ldif $DIR_LDIF
COPY /etc $DIR_DATA/etc
COPY /scripts $DIR_SCRIPTS
COPY /conf.d/ $DIR_SAMBA_CONF
COPY /gpo $DIR_GPO
#COPY --from=builder ${src} /tmp/

RUN chmod -R +x $DIR_SCRIPTS

VOLUME $DIR_DATA

EXPOSE 42 53 53/udp 88 88/udp 135 137-138/udp 139 389 389/udp 445 464 464/udp 636 3268-3269 49152-65535

WORKDIR /

HEALTHCHECK CMD smbcontrol smbd num-children || exit 1
ENTRYPOINT ["sh", "/scripts/init.sh"]