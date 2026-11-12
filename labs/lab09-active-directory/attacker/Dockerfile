FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
# AD enumeration + initial-access toolkit: Kerberos client, LDAP + SMB tools,
# impacket (samrdump/rpcdump enumeration), and kerbrute (user enum + password spraying).
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-impacket \
        krb5-user ldap-utils smbclient \
        curl ca-certificates iproute2 dnsutils iputils-ping netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# kerbrute (user enumeration + password spraying) from GitHub release
RUN curl -fsSL -o /usr/local/bin/kerbrute \
        https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 \
    && chmod +x /usr/local/bin/kerbrute

COPY wordlist.txt /root/wordlist.txt
COPY users.txt /root/users.txt
COPY krb5.conf /etc/krb5.conf

WORKDIR /root
