#!/usr/bin/env python3
"""Build a device_profiles.json skeleton from a MAC -> name registry.

Usage:
    make_device_profiles.py device_names.json > device_profiles.json

The registry format is the one used by dns_watch: a JSON object mapping
MAC addresses to human-assigned names. The output keeps the MAC as the
key and fills name; type / vendor / expected / notes start empty (or
with a template hint) for the operator to complete. The `expected`
field should follow the three-part shape: normal destinations /
volume and timing / what the device never does.

An existing profiles file can be passed as the second argument; its
entries are kept and only missing devices are added, so re-running
this after the registry grows does not clobber hand-written context.
"""
import json
import sys

# A deliberately small OUI hint table. Vendor identification from a MAC
# prefix is a clue, not a fact (private-label modules are common in
# IoT), so unknown prefixes simply stay blank.
OUI_HINTS = {
    "30:30:F9": "SwitchBot (Espressif module)",
    "84:FC:E6": "SwitchBot (Espressif module)",
    "2C:CF:67": "Raspberry Pi",
    "88:A2:9E": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "BC:24:11": "Proxmox VE (virtual)",
}


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 1
    with open(sys.argv[1], encoding="utf-8") as f:
        registry = json.load(f)
    profiles = {}
    if len(sys.argv) > 2:
        with open(sys.argv[2], encoding="utf-8") as f:
            profiles = json.load(f)
    added = 0
    for mac, name in registry.items():
        mac = mac.strip().upper()
        if ":" not in mac or mac in profiles:
            continue
        profiles[mac] = {
            "name": name,
            "type": "",
            "vendor": OUI_HINTS.get(mac[:8], ""),
            "ip": "",
            "expected": "",
            "notes": "",
        }
        added += 1
    json.dump(profiles, sys.stdout, ensure_ascii=False, indent=1,
              sort_keys=True)
    print(f"\n# {added} new skeleton entries added", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
