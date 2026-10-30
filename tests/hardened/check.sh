#!/bin/sh
# The hardened deployment (docs/security.md §6 item 4), checked as root inside
# a container whose PID 1 is systemd. `run.sh` builds the image and runs
# this. Users:
#   alice   - admitted by `daemon install --hardened --user alice`
#   bob     - in the gyges group, but not an admitted uid
#   mallory - neither
set -eu

NET=regtest
SOCK=/run/gyges/$NET/gygesd.sock
UNIT=/etc/systemd/system/gygesd-$NET.service
pass() { echo "ok   $*"; }
fail() { echo "FAIL $*"; exit 1; }
as() { u=$1; shift; runuser -u "$u" -- env GYGES_SOCKET=$SOCK "$@"; }

for u in alice bob mallory; do useradd --create-home "$u"; done

gyges -n $NET daemon install --hardened --user alice
pass "install --hardened"
usermod --append --groups gyges bob

[ "$(stat -c '%a %U %G' $SOCK)" = "660 gyges gyges" ] || fail "socket is $(stat -c '%a %U %G' $SOCK)"
[ "$(stat -c '%a %U %G' /run/gyges/$NET)" = "750 gyges gyges" ] || fail "socket dir is $(stat -c '%a %U %G' /run/gyges/$NET)"
[ "$(stat -c '%a %U' /var/lib/gyges)" = "700 gyges" ] || fail "home is $(stat -c '%a %U' /var/lib/gyges)"
pass "socket 0660 gyges:gyges in a 0750 directory; home 0700 gyges"
id -nG alice | grep -qw gyges || fail "alice is not in the gyges group"
pass "alice added to the gyges group"

as alice gyges -n $NET daemon status | grep -q "on regtest" || fail "alice cannot reach the daemon"
pass "alice (admitted, group member) gets daemon status"

if as mallory gyges -n $NET daemon status >/dev/null 2>&1; then fail "mallory reached the daemon"; fi
as mallory gyges -n $NET daemon status 2>&1 | grep -q "Permission denied" || fail "mallory: unexpected error"
pass "mallory (not in the group) cannot open the socket"

if as bob gyges -n $NET daemon status >/dev/null 2>&1; then fail "bob reached the daemon"; fi
pass "bob (group member, not admitted) is dropped by the peer policy"

for f in /var/lib/gyges /var/lib/gyges/$NET/config.toml /var/lib/gyges/$NET/keys; do
  if as alice ls "$f" >/dev/null 2>&1 || as alice cat "$f" >/dev/null 2>&1; then
    fail "alice can read $f"
  fi
done
pass "alice cannot read the daemon's home"

# Reinstalling restarts the daemon (the upgrade step); nothing new to create.
PID1=$(systemctl show -p MainPID --value gygesd-$NET.service)
gyges -q -n $NET daemon install --hardened --user alice
PID2=$(systemctl show -p MainPID --value gygesd-$NET.service)
[ "$PID1" != "$PID2" ] || fail "reinstall did not restart the daemon"
pass "reinstall restarts the daemon ($PID1 -> $PID2)"

# `daemon stop` from alice exits 0, so the unit stays stopped.
as alice gyges -n $NET daemon stop >/dev/null
sleep 12
[ "$(systemctl is-active gygesd-$NET.service || true)" = "inactive" ] || fail "the daemon came back after daemon stop"
[ ! -e /run/gyges/$NET ] || fail "the runtime directory survived the stop"
pass "daemon stop stays stopped; /run/gyges/$NET removed"

# A crash restarts it.
systemctl start gygesd-$NET.service
sleep 2
kill -9 "$(systemctl show -p MainPID --value gygesd-$NET.service)"
sleep 13
as alice gyges -n $NET daemon status >/dev/null || fail "not restarted after kill -9"
pass "restarted after kill -9"

systemd-analyze security gygesd-$NET.service --no-pager | tail -1

gyges -n $NET daemon uninstall --hardened
[ ! -e $UNIT ] || fail "unit left behind"
id gyges >/dev/null || fail "the gyges user was removed"
[ -d /var/lib/gyges/$NET/keys ] || fail "the home was removed"
if [ -S $SOCK ]; then fail "socket left behind"; fi
gyges -q -n $NET daemon uninstall --hardened
pass "uninstall --hardened removes the unit, keeps the account and home, and is idempotent"

echo "ALL PASS"
