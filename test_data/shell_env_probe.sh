#!/bin/sh
set -eu

tmp_root="${TMPDIR:-/tmp}"
tmpdir="$tmp_root/tos-userland-env-$$"
file="$tmpdir/data.txt"
moved="$tmpdir/moved.txt"
link="$tmpdir/link.txt"

cleanup() {
  rm -f "$link" "$moved" "$file"
  rmdir "$tmpdir" 2>/dev/null || true
}

trap cleanup EXIT HUP INT TERM

[ -d /bin ]
[ -d /usr/bin ]
[ -d /tmp ]
[ -d /dev ]
[ -d /proc ]

printf 'discard\n' >/dev/null
cat /proc/self/exe >/dev/null
ps >/dev/null
sleep 0

mkdir -p "$tmpdir"
touch "$file"
printf 'payload-from-sh\n' > "$file"
mv "$file" "$moved"
ln -s "$moved" "$link"
payload="$(cat "$link")"
cwd="$(pwd)"
kernel="$(uname -s)"

printf 'TOS-USERLAND-LAYOUT bin=ok usrbin=ok tmp=ok dev=ok proc=ok tmp_root=%s\n' \
  "$tmp_root"
printf 'TOS-USERLAND-TOOLS mkdir=ok touch=ok mv=ok ln=ok cat=ok pwd=%s ps=ok sleep=ok uname=%s\n' \
  "$cwd" "$kernel"
printf 'TOS-USERLAND-ENV-OK payload=%s probe=%s shell=%s proc_exe=ok dev_null=ok\n' \
  "$payload" "${TOS_PROBE:-missing}" "$0"
