#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Reconnexion inversée (`listen()`) à travers un vrai NAT/pare-feu (issue #27).
#
# Topologie (espaces de noms réseau Linux, netfilter réel) :
#
#   [lan] 192.168.77.2 --- 192.168.77.1 [routeur] 198.51.100.1 --- 198.51.100.2 [hôte]
#   Xvnc + vncconfig        MASQUERADE + pare-feu à états          asyncvnc2.listen()
#
# Le routeur traduit les adresses (SNAT/MASQUERADE) et refuse toute connexion
# entrante vers le LAN (FORWARD DROP, seul ESTABLISHED,RELATED revient) : comme
# une box domestique. Le script vérifie :
#   1. que le serveur VNC est INJOIGNABLE depuis l'hôte (connect() impossible) ;
#   2. que `vncconfig -connect` traverse le NAT jusqu'à `listen()` ;
#   3. que l'hôte voit l'adresse publique du routeur (198.51.100.1), pas
#      192.168.77.2 : la traduction a bien eu lieu ;
#   4. que le `Client` obtenu est utilisable (capture d'écran de la couleur
#      posée par xsetroot, clic souris, frappe clavier).
#
# Usage : sudo -v ; scripts/scenario_listen_nat.sh
# Requiert : ip (iproute2), iptables (ou iptables-legacy), Xvnc et vncconfig
# (TigerVNC), xsetroot, uv. Utilise sudo pour le réseau ; les processus VNC
# tournent sous l'utilisateur courant. Tout est supprimé en sortie.
#
# Sur un vrai réseau (box Internet), un opérateur rejoue la même chose sans les
# espaces de noms : `listen()` sur une machine joignable (port 5500 ouvert), le
# serveur derrière la box lance `vncconfig -connect <ip-publique>:5500`
# (TigerVNC) ou `x11vnc -connect_or_exit <ip-publique>:5500`, puis on vérifie
# l'étape 4 ; voir docs/sessions/session-26-2026-10-24.md.
set -euo pipefail

ICI="$(cd "$(dirname "$0")/.." && pwd)"
UTILISATEUR="$(id -un)"
AFFICHAGE="${AFFICHAGE:-:57}"
LAN=avnc-lan
ROUTEUR=avnc-routeur
IPT="${IPT:-}"

journal() { printf '[scenario_listen_nat] %s\n' "$*" >&2; }

if [ -z "$IPT" ]; then
    if sudo iptables -t nat -L -n >/dev/null 2>&1; then IPT=iptables; else IPT=iptables-legacy; fi
fi

nettoyer() {
    journal "nettoyage"
    [ -n "${PID_LISTEN:-}" ] && kill "$PID_LISTEN" 2>/dev/null || true
    sudo ip netns pids "$LAN" 2>/dev/null | xargs -r sudo kill 2>/dev/null || true
    sudo ip netns del "$LAN" 2>/dev/null || true
    sudo ip netns del "$ROUTEUR" 2>/dev/null || true
    sudo ip link del avnc-wan0 2>/dev/null || true
    sudo ip route del 192.168.77.0/24 2>/dev/null || true
    rm -f "${RESULTAT:-}"
}
trap nettoyer EXIT

journal "réseau : espaces $LAN et $ROUTEUR ($IPT)"
sudo ip netns add "$LAN"
sudo ip netns add "$ROUTEUR"
sudo ip link add avnc-lan0 type veth peer name avnc-rlan
sudo ip link add avnc-wan0 type veth peer name avnc-rwan
sudo ip link set avnc-lan0 netns "$LAN"
sudo ip link set avnc-rlan netns "$ROUTEUR"
sudo ip link set avnc-rwan netns "$ROUTEUR"
sudo ip -n "$LAN" addr add 192.168.77.2/24 dev avnc-lan0
sudo ip -n "$LAN" link set lo up
sudo ip -n "$LAN" link set avnc-lan0 up
sudo ip -n "$LAN" route add default via 192.168.77.1
sudo ip -n "$ROUTEUR" addr add 192.168.77.1/24 dev avnc-rlan
sudo ip -n "$ROUTEUR" addr add 198.51.100.1/24 dev avnc-rwan
sudo ip -n "$ROUTEUR" link set avnc-rlan up
sudo ip -n "$ROUTEUR" link set avnc-rwan up
sudo ip addr add 198.51.100.2/24 dev avnc-wan0
sudo ip link set avnc-wan0 up
# Route explicite vers le LAN : si la connexion directe échoue, c'est le
# pare-feu du routeur qui la refuse, pas une simple absence de route.
sudo ip route add 192.168.77.0/24 via 198.51.100.1
sudo ip netns exec "$ROUTEUR" sysctl -q -w net.ipv4.ip_forward=1
sudo ip netns exec "$ROUTEUR" "$IPT" -t nat -A POSTROUTING -o avnc-rwan -j MASQUERADE
sudo ip netns exec "$ROUTEUR" "$IPT" -P FORWARD DROP
sudo ip netns exec "$ROUTEUR" "$IPT" -A FORWARD -i avnc-rlan -o avnc-rwan -j ACCEPT
sudo ip netns exec "$ROUTEUR" "$IPT" -A FORWARD -i avnc-rwan -o avnc-rlan \
    -m state --state ESTABLISHED,RELATED -j ACCEPT

journal "serveur : Xvnc $AFFICHAGE dans $LAN"
sudo ip netns exec "$LAN" sudo -u "$UTILISATEUR" \
    Xvnc "$AFFICHAGE" -geometry 320x240 -depth 24 -SecurityTypes None -rfbport 5900 \
    -nolisten tcp >/dev/null 2>&1 &
for _ in $(seq 50); do
    sudo ip netns exec "$LAN" sudo -u "$UTILISATEUR" xsetroot -display "$AFFICHAGE" \
        -solid '#2080c0' 2>/dev/null && break
    sleep 0.2
done

journal "étape 1 : le serveur doit être injoignable depuis l'hôte"
if timeout 3 bash -c 'exec 3<>/dev/tcp/192.168.77.2/5900' 2>/dev/null; then
    journal "ÉCHEC : 192.168.77.2:5900 joignable directement, le pare-feu ne filtre pas"
    exit 1
fi
journal "  ok : connexion directe refusée par le pare-feu"

RESULTAT="$(mktemp)"
journal "étape 2 : listen() sur 198.51.100.2:5500"
(cd "$ICI" && uv run --quiet python - "$RESULTAT" <<'PY'
import asyncio
import sys

from loguru import logger

import asyncvnc2

logger.remove()


async def principal():
    async with asyncvnc2.listen('198.51.100.2', 5500) as client:
        pair = client.writer.get_extra_info('peername')
        image = await asyncio.wait_for(client.screenshot(), 20)
        client.mouse.click()
        client.keyboard.write('ok')
        await client.writer.drain()
        return pair[0], image.shape, tuple(int(v) for v in image[120, 160, :3])


pair, forme, pixel = asyncio.run(asyncio.wait_for(principal(), 60))
with open(sys.argv[1], 'w') as f:
    f.write(f'{pair} {forme[0]}x{forme[1]} {pixel[0]},{pixel[1]},{pixel[2]}\n')
PY
) &
PID_LISTEN=$!
for _ in $(seq 50); do
    ss -ltn | grep -q '198.51.100.2:5500' && break
    sleep 0.2
done

journal "étape 2 : vncconfig -connect 198.51.100.2:5500 depuis le LAN"
sudo ip netns exec "$LAN" sudo -u "$UTILISATEUR" \
    vncconfig -display "$AFFICHAGE" -connect 198.51.100.2:5500
wait "$PID_LISTEN"
PID_LISTEN=

read -r PAIR TAILLE PIXEL <"$RESULTAT"
journal "  pair vu par listen() : $PAIR ; écran $TAILLE ; pixel central $PIXEL"
[ "$PAIR" = 198.51.100.1 ] || { journal "ÉCHEC étape 3 : adresse $PAIR non traduite"; exit 1; }
[ "$TAILLE" = 240x320 ] || { journal "ÉCHEC étape 4 : taille $TAILLE"; exit 1; }
[ "$PIXEL" = 32,128,192 ] || { journal "ÉCHEC étape 4 : pixel $PIXEL au lieu de 32,128,192"; exit 1; }
journal "SUCCÈS : listen() à travers NAT + pare-feu, adresse traduite, Client utilisable"
