#!/bin/sh
# activeban installer (run as root, idempotent).
# Run from the root of a clone/copy of this repository.
# Installs the log-only enforcement pair. Swap in a real pair afterwards.
# Secret files (nextcloud.json / llm.json / openai.key) are installed only
# when you place the real files next to this script; it never creates their
# contents, and .gitignore keeps them out of commits.
set -eu
[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 1; }
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# --- group and users ---
getent group activeban >/dev/null || groupadd -r activeban
id qdetect >/dev/null 2>&1 || useradd -r -g activeban -s /usr/sbin/nologin -M qdetect
id qllm >/dev/null 2>&1 || useradd -r -g activeban -s /usr/sbin/nologin -M qllm
id quarantine >/dev/null 2>&1 || useradd -r -g activeban -s /usr/sbin/nologin -M quarantine
for u in quarantine qllm qdetect; do usermod -a -G activeban "$u"; done

# --- daemon and enforcement pair (log-only) ---
install -m 0755 "$SRC/activeban.py" /usr/local/sbin/activeban.py
install -m 0755 "$SRC/fw.d/activeban-ban-log" /usr/local/sbin/activeban-ban
install -m 0755 "$SRC/fw.d/activeban-release-log" /usr/local/sbin/activeban-release

# --- configuration ---
install -d -o root -g activeban -m 0750 /etc/activeban
if [ -f "$SRC/policy.json" ]; then
  install -m 0644 -o root -g root "$SRC/policy.json" /etc/activeban/policy.json
  echo "policy : installed from $SRC/policy.json"
elif [ -f /etc/activeban/policy.json ]; then
  echo "policy : keeping existing /etc/activeban/policy.json"
else
  echo "MISSING: /etc/activeban/policy.json - create it from examples/policy.example.json first"
fi

# --- systemd ---
install -m 0644 "$SRC/systemd/activeban.service" /etc/systemd/system/activeban.service
install -m 0644 "$SRC/systemd/activeban-verify.service" /etc/systemd/system/activeban-verify.service
systemctl daemon-reload

# --- files containing secrets ---
# Place the real files next to deploy.sh (same names, without .example);
# they are listed in .gitignore, so they cannot be committed by accident.
# Installed with owner root:<reader> and mode 640. Existing files in
# /etc/activeban are kept when no source file is present.
install_secret() {
  if [ -f "$SRC/$1" ]; then
    install -m 0640 -o root -g "$3" "$SRC/$1" "/etc/activeban/$1"
    echo "secret : installed /etc/activeban/$1 (root:$3 640)"
  elif [ -e "/etc/activeban/$1" ]; then
    echo "secret : keeping existing /etc/activeban/$1"
  else
    echo "MISSING: $1 - copy $2 to $1 next to deploy.sh, fill it in, re-run"
  fi
}
install_secret nextcloud.json examples/nextcloud.example.json quarantine
install_secret llm.json examples/llm.example.json qllm
install_secret openai.key examples/openai.key.example qllm
# Device profiles are read by the verification loop (qllm). Not a secret,
# but installed through the same path: place device_profiles.json next to
# deploy.sh (build a skeleton with examples/make_device_profiles.py).
install_secret device_profiles.json examples/device_profiles.example.json qllm

echo "== installed =="
echo "daemon : systemctl enable --now activeban"
echo "verify : systemctl enable --now activeban-verify"
echo "note: qdetect is nologin for now; switch it to /bin/sh when adding the SSH forced-command bridge."
