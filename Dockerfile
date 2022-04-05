FROM ubuntu:focal

LABEL maintainer="Fmstrat <fmstrat@NOSPAM.NO>"

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update \
    && apt-get upgrade -y \
    # Install all required packages \
	#openssl for dh key
    && apt-get install -y ntp pkg-config attr acl samba smbclient tdb-tools ldb-tools ldap-utils winbind libnss-winbind libpam-winbind libpam-krb5 krb5-user supervisor dnsutils \
    # line below is for multi-site config (ping is for testing later) \
    #&& apt-get install -y openvpn inetutils-ping \
    # Set up script \
    #&& chmod 755 init.sh \
    # cleanup \
    && apt-get clean autoclean \
    && apt-get autoremove --yes \
    && rm -rf /var/lib/{apt,dpkg,cache,log}/ \
    && rm -fr /tmp/* /var/tmp/*

COPY init.sh /init.sh
COPY ldif/ /root/ldif/
COPY /etc /etc/

CMD /init.sh setup
