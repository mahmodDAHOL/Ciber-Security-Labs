#!/bin/sh
FLAG="FLAG{ftp_$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
echo "$FLAG" > /flag
cat > /var/ftp/pub/it-notes.txt <<EOF
IT notes
--------
The intranet portal on 10.10.10.50 still uses plain HTTP with Basic auth.
Workstation ws01 polls it automatically with alice's account every few seconds.
We really need to move it to HTTPS...

$FLAG
EOF
echo "nothing to see here" > /var/ftp/pub/readme.txt
exec vsftpd /etc/vsftpd.conf
