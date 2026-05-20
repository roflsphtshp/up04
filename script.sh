#!/bin/bash

set -e

WG_IF="wg0"
WG_PORT="51820"
WG_DIR="/etc/wireguard"

# внешний адрес RTR
SERVER_IP="172.16.23.254"

# WireGuard сеть
WG_NET="10.5.10.0/24"
SERVER_WG_IP="10.5.10.1"
CLIENT_WG_IP="10.5.10.2"

dnf install -y wireguard-tools || yum install -y wireguard-tools

mkdir -p $WG_DIR
chmod 700 $WG_DIR
cd $WG_DIR

umask 077

# =========================
# RTR KEYS
# =========================
wg genkey | tee server_private.key | wg pubkey > server_public.key

SERVER_PRIV=$(cat server_private.key)
SERVER_PUB=$(cat server_public.key)

# =========================
# CLIENT KEYS
# =========================
wg genkey | tee client_private.key | wg pubkey > client_public.key

CLIENT_PRIV=$(cat client_private.key)
CLIENT_PUB=$(cat client_public.key)

# =========================
# RTR CONFIG
# =========================
cat > $WG_IF.conf <<EOF
[Interface]
Address = $SERVER_WG_IP/24
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIV

# OUT-CLI
[Peer]
PublicKey = $CLIENT_PUB
AllowedIPs = $CLIENT_WG_IP/32
EOF

# =========================
# CLIENT CONFIG
# =========================
cat > cli.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = $CLIENT_WG_IP/24

[Peer]
PublicKey = $SERVER_PUB
Endpoint = $SERVER_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

# =========================
# START WG ON RTR
# =========================
systemctl enable wg-quick@$WG_IF
systemctl restart wg-quick@$WG_IF

# =========================
# EXPORT CLIENT CONFIG
# =========================
cp cli.conf /home/user/cli.conf
chmod 644 /home/user/cli.conf

echo "WireGuard setup done"
echo "RTR: $SERVER_WG_IP"
echo "CLIENT: $CLIENT_WG_IP"
echo "Endpoint: $SERVER_IP:$WG_PORT"
