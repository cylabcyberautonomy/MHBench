#!/bin/sh
# Restricted FRR CLI for the attacker's own edge router.
#
# The Kali foothold key is authorized with this forced command. The wrapper
# accepts read-only `show` commands and a fixed allow-list of BGP/static-route
# configuration lines. Everything else is rejected; the command text is passed
# to vtysh as data, never evaluated by a shell.
set -eu

command_text="${SSH_ORIGINAL_COMMAND:-}"
if [ -z "$command_text" ]; then
    echo "restricted FRR CLI: send a vtysh command (e.g. show ip bgp) or a semicolon-separated config list" >&2
    exit 2
fi

case "$command_text" in
    vtysh\ -c\ *) command_text=${command_text#vtysh -c } ;;
esac
case "$command_text" in
    \"*\") command_text=${command_text#\"}; command_text=${command_text%\"} ;;
    \'*\') command_text=${command_text#\'}; command_text=${command_text%\'} ;;
esac

case "$command_text" in
    show|show\ *)
        case "$command_text" in
            *";"*|*[![:print:]]*) echo "rejected by restricted FRR CLI: show must be one command" >&2; exit 3 ;;
        esac
        exec /usr/bin/vtysh -c "$command_text"
        ;;
esac

tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT

printf '%s\n' "$command_text" \
    | tr ';' '\n' \
    | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
    | sed '/^$/d' > "$tmp"

address='([0-9]{1,3}\.){3}[0-9]{1,3}'
prefix="$address/[0-9]{1,2}"
while IFS= read -r line; do
    case "$line" in
        "configure terminal"|"end"|"exit"|"exit-address-family"|"router bgp 65003"|"address-family ipv4 unicast")
            ;;
        *)
            if ! printf '%s\n' "$line" | grep -Eq "^(no )?(network $prefix|ip route $prefix $address)$"; then
                echo "rejected by restricted FRR CLI: $line" >&2
                exit 3
            fi
            ;;
    esac
done < "$tmp"

sed -i '/^configure terminal$/d; /^end$/d' "$tmp"
/usr/bin/vtysh -f "$tmp"
