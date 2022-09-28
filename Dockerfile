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
#    DIR_SAMBA_CONF=/data/etc/samba/conf.d \
	DIR_SCRIPTS=/data/scripts \
	DIR_LDIF=/data/ldif \
	DIR_GPO=/data/gpo 

RUN apt-get update \
    && apt-get upgrade -y \
	&& apt-get install -y bind9 chrony pkg-config attr acl samba smbclient tdb-tools ldb-tools ldap-utils winbind libnss-winbind libpam-winbind libpam-krb5 krb5-user supervisor dnsutils nano \
	#openssl for dh key \
    # line below is for multi-site config (ping is for testing later) \
    #&& apt-get install -y openvpn inetutils-ping \   
    && apt-get clean autoclean \
    && apt-get autoremove --yes \
#    && rm -rf /var/lib/{apt,dpkg,cache,log}/ \
	&& rm -rf /tmp/* /var/tmp/* \
    && rm -rf /var/lib/{apt,dpkg,cache,log,samba}/ \
	&& rm -rf /etc/bind /etc/chrony /etc/chrony /etc/nsswitch.conf /etc/samba /etc/supervisor /var/cache/bind /var/cache/samba /var/lib/bind /var/lib/chrony /var/lib/samba /var/log/bind /var/log/chrony /var/log/samba /var/log/supervisor \
	&& mkdir -p /data/etc/bind /data/etc/chrony /data/etc/samba /data/etc/supervisor /data/cache/bind /data/cache/samba /data/lib/bind /data/lib/chrony /data/lib/samba /data/log/bind /data/log/chrony /data/log/samba /data/log/supervisor \
	&& ln -s /data/etc/bind /etc/bind \
	&& ln -s /data/etc/chrony /etc/chrony \
	&& ln -s /data/etc/nsswitch.conf /etc/ \
	&& ln -s /data/etc/samba /etc/samba \
	&& ln -s /data/etc/supervisor /etc/supervisor \
	&& ln -s /data/lib/bind /var/lib/bind \
	&& ln -s /data/lib/chrony /var/lib/chrony \
	&& ln -s /data/lib/samba /var/lib/samba \
	&& ln -s /data/log/bind /var/log/bind \
	&& ln -s /data/log/chrony /var/log/chrony \
    && ln -s /data/log/samba /var/log/samba \
	&& ln -s /data/log/supervisor /var/log/supervisor \
	&& ln -s /data/cache/bind /var/cache/bind \
	&& ln -s /data/cache/samba /var/cache/samba

COPY /ldif $DIR_LDIF
COPY /etc /data/etc
COPY /scripts $DIR_SCRIPTS
#COPY /conf.d/ $DIR_SAMBA_CONF
COPY /gpo $DIR_GPO
#COPY --from=builder ${src} /tmp/

RUN chmod -R +x /data/scripts/

EXPOSE 42 53 53/udp 88 88/udp 135 137-138/udp 139 389 389/udp 445 464 464/udp 636 3268-3269 49152-65535

WORKDIR /

HEALTHCHECK CMD smbcontrol smbd num-children || exit 1
ENTRYPOINT ["sh", "/data/scripts/init.sh"]