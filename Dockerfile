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
    DIR_SAMBA_CONF=/etc/samba/conf.d \
	DIR_SCRIPTS=/scripts \
	DIR_LDIF=/ldif \
	DIR_GPO=/gpo 

RUN apt-get update \
    && apt-get upgrade -y \
	#openssl for dh key
    && apt-get install -y bind9 chrony pkg-config attr acl samba smbclient tdb-tools ldb-tools ldap-utils winbind libnss-winbind libpam-winbind libpam-krb5 krb5-user supervisor dnsutils \
    # line below is for multi-site config (ping is for testing later) \
    #&& apt-get install -y openvpn inetutils-ping \   
    && apt-get clean autoclean \
    && apt-get autoremove --yes \
    && rm -rf /var/lib/{apt,dpkg,cache,log,samba}/ \
    && rm -rf /tmp/* /var/tmp/* \
	&& rm -rf /etc/samba \
    && rm -rf /var/log/samba \
    && ln -s /samba/etc /etc/samba \
    && ln -s /samba/lib /var/lib/samba \
    && ln -s /samba/log /var/log/samba \
	&& ln -s /samba/bind /etc/bind \
	&& ln -s /samba/log/bind /var/log/bind \
	&& ln -s /samba/chrony /etc/chrony \
	&& ln -s /samba/log/chrony /var/log/chrony \
	&& ln -s /samba/supervisor /etc/supervisor

COPY /ldif $DIR_LDIF
COPY /etc /etc/
COPY /scripts $DIR_SCRIPTS
COPY /conf.d/ $DIR_SAMBA_CONF
COPY /gpo /$DIR_GPO
#COPY --from=builder ${src} /tmp/

RUN chmod -R +x /scripts/

EXPOSE 42 53 53/udp 88 88/udp 135 137-138/udp 139 389 389/udp 445 464 464/udp 636 3268-3269 49152-65535

WORKDIR /

HEALTHCHECK CMD smbcontrol smbd num-children || exit 1

ENTRYPOINT ["sh", "/scripts/init.sh"]