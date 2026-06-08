#!/bin/bash

DATE=$(date +%Y%m%d)
HOST=$(hostname)

WORKDIR="/tmp/${HOST}_${DATE}"
ARCHIVE="backup_${HOST}_${DATE}.tar.gz"

MOUNT_POINT="/mnt/backupshare"
SHARE="//IP_DC_HQ/Backups"

LOGFILE="/var/log/backup.log"

echo "[$(date)] Backup started on $HOST" >> "$LOGFILE"

mkdir -p "$WORKDIR/$HOST/$DATE"

#
# nginx
#

mkdir -p "$WORKDIR/$HOST/$DATE/nginx"

cp -a /etc/nginx/conf.d/*.conf \
"$WORKDIR/$HOST/$DATE/nginx/" 2>/dev/null

#
# Network
#

mkdir -p "$WORKDIR/$HOST/$DATE/network"

cp -a /etc/sysconfig/network-scripts/ifcfg-* \
"$WORKDIR/$HOST/$DATE/network/" 2>/dev/null

cp -a /etc/NetworkManager/system-connections/* \
"$WORKDIR/$HOST/$DATE/network/" 2>/dev/null

#
# Diagnostics
#

ip a > "$WORKDIR/$HOST/$DATE/ip_a.txt"
ip r > "$WORKDIR/$HOST/$DATE/ip_r.txt"
nft list ruleset > "$WORKDIR/$HOST/$DATE/nft_ruleset.txt" 2>/dev/null

#
# Archive
#

tar -czf "/tmp/$ARCHIVE" -C "$WORKDIR" .

#
# SMB
#

mkdir -p "$MOUNT_POINT"

mount -t cifs "$SHARE" "$MOUNT_POINT" \
-o credentials=/root/.smb/backup.credentials

if [ $? -ne 0 ]; then
    echo "[$(date)] SMB mount failed" >> "$LOGFILE"
    exit 1
fi

mkdir -p "$MOUNT_POINT/$HOST"

cp "/tmp/$ARCHIVE" "$MOUNT_POINT/$HOST/"

if [ $? -eq 0 ]; then
    echo "[$(date)] Backup success: $ARCHIVE" >> "$LOGFILE"
else
    echo "[$(date)] Backup copy failed" >> "$LOGFILE"
fi

umount "$MOUNT_POINT"

rm -rf "$WORKDIR"
rm -f "/tmp/$ARCHIVE"
