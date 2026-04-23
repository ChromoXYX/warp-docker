#!/bin/bash

# exit when any command fails
set -e

# === Sanity check: physical interface must be exactly 'eth0' ===
# Personal-use image: hard fail otherwise to avoid silent LAN leaks when isolation rules are scoped to known iface names.
non_lo_ifaces=$(ip -o link show | awk -F': ' '{print $2}' | awk -F'@' '{print $1}' | grep -vE '^(lo|CloudflareWARP)$' || true)
if [ "$(echo "$non_lo_ifaces" | tr '\n' ' ' | xargs)" != "eth0" ]; then
    echo "FATAL: expected exactly one physical interface named 'eth0', got: [$non_lo_ifaces]" >&2
    exit 1
fi

# create a tun device if not exist
# allow passing device to ensure compatibility with Podman
if [ ! -e /dev/net/tun ]; then
    sudo mkdir -p /dev/net
    sudo mknod /dev/net/tun c 10 200
    sudo chmod 600 /dev/net/tun
fi

# start dbus
sudo mkdir -p /run/dbus
if [ -f /run/dbus/pid ]; then
    sudo rm /run/dbus/pid
fi
sudo dbus-daemon --config-file=/usr/share/dbus-1/system.conf

# start the daemon
sudo warp-svc --accept-tos &

# sleep to wait for the daemon to start, default 2 seconds
sleep "$WARP_SLEEP"

# if /var/lib/cloudflare-warp/reg.json not exists, setup new warp client
if [ ! -f /var/lib/cloudflare-warp/reg.json ]; then
    # if /var/lib/cloudflare-warp/mdm.xml not exists or REGISTER_WHEN_MDM_EXISTS not empty, register the warp client
    if [ ! -f /var/lib/cloudflare-warp/mdm.xml ] || [ -n "$REGISTER_WHEN_MDM_EXISTS" ]; then
        warp-cli registration new && echo "Warp client registered!"
        # if a license key is provided, register the license
        if [ -n "$WARP_LICENSE_KEY" ]; then
            echo "License key found, registering license..."
            warp-cli registration license "$WARP_LICENSE_KEY" && echo "Warp license registered!"
        fi
    fi
    # connect to the warp server
    warp-cli --accept-tos connect
else
    echo "Warp client already registered, skip registration"
fi

# disable qlog if DEBUG_ENABLE_QLOG is empty
if [ -z "$DEBUG_ENABLE_QLOG" ]; then
    warp-cli --accept-tos debug qlog disable
else
    warp-cli --accept-tos debug qlog enable
fi

# if WARP_ENABLE_NAT is provided, enable NAT and forwarding
if [ -n "$WARP_ENABLE_NAT" ]; then
    # switch to warp mode
    echo "[NAT] Switching to warp mode..."
    warp-cli --accept-tos mode warp
    warp-cli --accept-tos connect

    # wait another seconds for the daemon to reconfigure
    sleep "$WARP_SLEEP"

    # enable NAT
    echo "[NAT] Enabling NAT..."
    sudo nft add table ip nat
    sudo nft add chain ip nat WARP_NAT { type nat hook postrouting priority 100 \; }
    sudo nft add rule ip nat WARP_NAT oifname "CloudflareWARP" masquerade
    sudo nft add table ip mangle
    sudo nft add chain ip mangle forward { type filter hook forward priority mangle \; }
    sudo nft add rule ip mangle forward tcp flags syn tcp option maxseg size set rt mtu

    sudo nft add table ip6 nat
    sudo nft add chain ip6 nat WARP_NAT { type nat hook postrouting priority 100 \; }
    sudo nft add rule ip6 nat WARP_NAT oifname "CloudflareWARP" masquerade
    sudo nft add table ip6 mangle
    sudo nft add chain ip6 mangle forward { type filter hook forward priority mangle \; }
    sudo nft add rule ip6 mangle forward tcp flags syn tcp option maxseg size set rt mtu
fi

# === LAN / loopback isolation ===
# WARP_ISOLATE_LAN=1 (default): drop any new connection from container -> RFC1918/loopback/link-local on physical iface.
# - lo and CloudflareWARP are exempt (gost<->warp-cli proxy on lo; user app->WARP tun is fine, real egress packets target Cloudflare public IPs).
# - established/related accepted so host->container:1080 reverse path works.
# WARP_ISOLATE_ALLOW_CIDR: comma-separated CIDRs to allow as exceptions.
if [ "${WARP_ISOLATE_LAN:-1}" = "1" ]; then
    echo "[ISOLATE] Applying LAN isolation rules..."
    sudo nft add table inet isolate
    sudo nft add chain inet isolate output '{ type filter hook output priority 0 ; }'
    sudo nft add rule inet isolate output ct state established,related accept
    sudo nft add rule inet isolate output oifname { "lo", "CloudflareWARP" } accept
    if [ -n "$WARP_ISOLATE_ALLOW_CIDR" ]; then
        for cidr in $(echo "$WARP_ISOLATE_ALLOW_CIDR" | tr ',' ' '); do
            echo "[ISOLATE] Allowing exception: $cidr"
            if [[ "$cidr" == *:* ]]; then
                sudo nft add rule inet isolate output ip6 daddr "$cidr" accept
            else
                sudo nft add rule inet isolate output ip daddr "$cidr" accept
            fi
        done
    fi
    sudo nft add rule inet isolate output ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8, 224.0.0.0/4 } ct state new drop
    sudo nft add rule inet isolate output ip6 daddr { fc00::/7, fe80::/10, ::1/128, ff00::/8 } ct state new drop
fi

# === Startup probes ===
# WARP_ISOLATE_TEST_REACH: comma-separated host:port that MUST be reachable (public sanity).
# WARP_ISOLATE_TEST_TCP:   comma-separated host:port that MUST NOT be reachable.
# WARP_ISOLATE_TEST_PING:  comma-separated host that MUST NOT respond to ping.
probe_fail=0
if [ -n "$WARP_ISOLATE_TEST_REACH" ]; then
    for hp in $(echo "$WARP_ISOLATE_TEST_REACH" | tr ',' ' '); do
        host="${hp%:*}"; port="${hp##*:}"
        if nc -zw3 "$host" "$port" >/dev/null 2>&1; then
            echo "[PROBE] REACH ok: $hp"
        else
            echo "[PROBE] FAIL REACH (expected reachable): $hp" >&2
            probe_fail=1
        fi
    done
fi
if [ -n "$WARP_ISOLATE_TEST_TCP" ]; then
    for hp in $(echo "$WARP_ISOLATE_TEST_TCP" | tr ',' ' '); do
        host="${hp%:*}"; port="${hp##*:}"
        if nc -zw3 "$host" "$port" >/dev/null 2>&1; then
            echo "[PROBE] FAIL TCP (expected blocked): $hp" >&2
            probe_fail=1
        else
            echo "[PROBE] TCP blocked ok: $hp"
        fi
    done
fi
if [ -n "$WARP_ISOLATE_TEST_PING" ]; then
    for host in $(echo "$WARP_ISOLATE_TEST_PING" | tr ',' ' '); do
        if ping -c1 -W2 "$host" >/dev/null 2>&1; then
            echo "[PROBE] FAIL PING (expected blocked): $host" >&2
            probe_fail=1
        else
            echo "[PROBE] PING blocked ok: $host"
        fi
    done
fi
if [ "$probe_fail" -ne 0 ]; then
    echo "FATAL: isolation probes failed, refusing to start proxy." >&2
    exit 1
fi

# start the proxy
gost $GOST_ARGS
