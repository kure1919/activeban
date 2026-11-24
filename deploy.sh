#!/bin/sh
# activeban installer (run as root, idempotent).
# Run from the root of a clone/copy of this repository.
# Installs the log-only enforcement pair. Swap in a real pair afterwards.
# Never creates files containing secrets (nextcloud.json / llm.json / openai.key).
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
  echo "MISSING: /etc/activeban/policy.json - create it from policy.example.json first"
fi

# --- systemd ---
install -m 0644 "$SRC/systemd/activeban.service" /etc/systemd/system/activeban.service
install -m 0644 "$SRC/systemd/activeban-verify.service" /etc/systemd/system/activeban-verify.service
systemctl daemon-reload

echo "== installed =="
echo "daemon : systemctl enable --now activeban"
echo "verify : place llm.json and openai.key, then systemctl enable --now activeban-verify"
for f in nextcloud.json llm.json openai.key; do
  if [ -e "/etc/activeban/$f" ]; then
    echo "found  : /etc/activeban/$f"
  else
    echo "MISSING: /etc/activeban/$f (create it locally; never paste secrets into chat)"
  fi
done
echo "  nextcloud.json: {\"base_url\": \"https://<nextcloud>\", \"user\": \"...\", \"password\": \"...\", \"token\": \"<talk-room-token>\"}  owner root:quarantine 640"
echo "  llm.json      : {\"api_key_file\": \"/etc/activeban/openai.key\", \"model\": \"gpt-4o-mini\"}  owner root:qllm 640"
echo "  openai.key    : the OpenAI API key itself (one line)  owner root:qllm 640"
echo "note: qdetect is nologin for now; switch it to /bin/sh when adding the SSH forced-command bridge."
