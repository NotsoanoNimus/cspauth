#!/bin/bash -x
#  knock-knock.sh - "Minimized"
#  $1 - SourceIP, $2 - Port-to-open, $3 - Opening window, $4 - Port protocol, $5 - Misc
#
# Example script to show how a Fedora/RHEL system might implement and use a SPA script call.
#
#
SRCIP="$1"
OPT="$2"
TIMER="$3"

[[ -n "${2//[0-9]/}" || -n "${3//[0-9]/}" ]] && exit 1

if [[ -n "$(echo "$SRCIP" | grep -P '^([0-9]{1,3}\.){3}[0-9]{1,3}$')" ]]; then FAM="4"
elif [[ -z "${SRCIP//[0-9a-fA-F:]/}" ]]; then FAM="6"
else exit 1
fi

RULE="rule family='ipv${FAM}' source address='${SRCIP}' port protocol='${4}' port='${OPT}' accept"

function cleanup() { sudo firewall-cmd --remove-rich-rule="$RULE"; }

sudo firewall-cmd --add-rich-rule="$RULE"
trap cleanup EXIT ERR

sleep $TIMER
exit 0
