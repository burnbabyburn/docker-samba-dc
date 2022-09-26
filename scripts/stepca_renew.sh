#!/bin/bash
while (true)
do
  samba_cert=/var/lib/samba/private/tls/cert.pem
  samba_int=/var/lib/samba/private/tls/intermediate.pem
  samba_comb=/var/lib/samba/private/tls/cert-combined.pem
  samba_key=/var/lib/samba/private/tls/key.pem
  samba_root=/var/lib/samba/private/tls/ca.pem
  smallstep_url=${SMALLSTEP_URL:-stepca:9000}
  smallstep_provisioner=${SMALLSTEP_PROVISIONER:-defaultprovisioner}
  smallstep_pwfile=/var/lib/samba/private/tls/prov-pw
  smallstep_bin=${SMALLSTEP_BIN:-/usr/bin/step}

  supervisorctl stop samba

  "$smallstep_bin" ca renew "$samba_comb" "$samba_key" --ca-url "$smallstep_url" --password-file "$smallstep_pwfile" --root "$samba_root" --daemon

  if [[ $? -eq 1 ]]; then
    "$smallstep_bin" ca certificate "$(hostname).${DOMAIN,,}" "$samba_comb" "$samba_key" --san= --san= --san= --ca-url="$smallstep_url" --root="$samba_root" --provisioner="$smallstep_provisioner" --provisioner-password-file="$smallstep_pwfile" --kty RSA --size 2048 --force
  fi

  cp "$samba_comb" /tmp/
  csplit -f /tmp/cert- /tmp/cert-combined.pem '/-----BEGIN CERTIFICATE-----/' '{*}'
  cp -f /tmp/cert-01 $samba_cert
  cp -f /tmp/cert-02 $samba_int
  rm /tmp/cert-0*

  supervisorctl start samba
  sleep 4h
done