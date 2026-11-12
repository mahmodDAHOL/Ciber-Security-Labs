FROM debian:bookworm-slim

# Samba AD DC + tools. DEBIAN_FRONTEND avoids the interactive krb5 realm prompt.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        samba samba-common-bin samba-ad-provision samba-dsdb-modules samba-vfs-modules \
        smbclient winbind krb5-user ldb-tools ldap-utils python3 procps iproute2 dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY provision.sh /usr/local/bin/provision.sh
RUN chmod +x /usr/local/bin/provision.sh

EXPOSE 53 88 389 445 464 636 3268
ENTRYPOINT ["/usr/local/bin/provision.sh"]
