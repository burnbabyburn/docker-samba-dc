FROM ubuntu:devel as builder
WORKDIR /tmp/
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y msitools wget curl \
    && admxurl=$(curl -s 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=103507' | grep -o -m1 -E "url=http.*msi" | cut -d '=' -f2) \
    && wget -O admx.msi "$admxurl" \
    && msiextract -C /tmp admx.msi

FROM ubuntu:devel

LABEL maintainer="Fmstrat <fmstrat@NOSPAM.NO>"

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update \
    && apt-get upgrade -y \
	#openssl for dh key
    && apt-get install -y ntp pkg-config attr acl samba smbclient tdb-tools ldb-tools ldap-utils winbind libnss-winbind libpam-winbind libpam-krb5 krb5-user supervisor dnsutils \
    # line below is for multi-site config (ping is for testing later) \
    #&& apt-get install -y openvpn inetutils-ping \   
    && apt-get clean autoclean \
    && apt-get autoremove --yes \
    && rm -rf /var/lib/{apt,dpkg,cache,log}/ \
    && rm -fr /tmp/* /var/tmp/*

COPY /ldif /ldif/
COPY /etc /etc/
COPY /scripts /scripts/
COPY /smb.conf.d/ /etc/samba/smb.conf.d/
COPY --from=builder /tmp/Program\ Files/Microsoft\ Group\ Policy/ /tmp/

RUN chmod -R +x /scripts/

EXPOSE 42 53 53/udp 88 88/udp 135 137-138/udp 139 389 389/udp 445 464 464/udp 636 3268-3269 49152-65535

WORKDIR /

HEALTHCHECK CMD smbcontrol smbd num-children || exit 1

ENTRYPOINT ["bash", "/scripts/init.sh"]