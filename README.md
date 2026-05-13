# Transmission Blocklist

Auto-updating Transmission-compatible security blocklist generated from public threat intelligence feeds.

The blocklist is generated automatically with GitHub Actions and published in two formats:

- Plain P2P blocklist
- Gzip-compressed P2P blocklist

## Blocklist URLs

Plain:

```text
https://raw.githubusercontent.com/h1de0x/transmission-blocklist/main/dist/blocklist.p2p
```

Gzip:

```text
https://raw.githubusercontent.com/h1de0x/transmission-blocklist/main/dist/blocklist.p2p.gz
```

## Recommended Transmission URL

Use the gzip version first:

```text
https://raw.githubusercontent.com/h1de0x/transmission-blocklist/main/dist/blocklist.p2p.gz
```

If your Transmission setup does not accept the gzip file, use the plain version instead:

```text
https://raw.githubusercontent.com/h1de0x/transmission-blocklist/main/dist/blocklist.p2p
```

## Transmission configuration

Example `settings.json`:

```json
{
  "blocklist-enabled": true,
  "blocklist-url": "https://raw.githubusercontent.com/h1de0x/transmission-blocklist/main/dist/blocklist.p2p.gz"
}
```

Update the blocklist manually:

```bash
transmission-remote --blocklist-update
```

Check blocklist status:

```bash
transmission-remote --blocklist
```

## Sources

Sources are configured in [`sources.yml`](sources.yml).

Current source categories include:

- known hostile networks
- recent attacker IPs
- scanners
- brute-force sources
- compromised hosts
- public threat intelligence feeds

## Generated files

```text
dist/blocklist.p2p
dist/blocklist.p2p.gz
```

The generated blocklist uses Transmission-compatible P2P plaintext format:

```text
source_name:start_ip-end_ip
```

Example:

```text
blocklist_de:1.2.3.4-1.2.3.4
spamhaus_drop:5.6.7.0-5.6.7.255
```

## Update schedule

The blocklist is regenerated automatically every 12 hours using GitHub Actions.

Workflow file:

```text
.github/workflows/generate.yml
```

## Local generation

Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Generate blocklists:

```bash
python generate_blocklist.py
```

Output:

```text
dist/blocklist.p2p
dist/blocklist.p2p.gz
```

## Notes

This is not a pure torrent-specific blocklist. It is a security-focused blocklist for Transmission, built from public threat intelligence sources.

Some entries may come from scanners, compromised hosts, brute-force sources, hostile networks, or public reputation feeds. False positives are possible.

## Copyright and license

Copyright (c) 2026 [h1de0x](https://github.com/h1de0x).

Project: <https://github.com/h1de0x/transmission-blocklist>

The generator code, workflow files, and project documentation are licensed under the MIT License. See [`LICENSE`](LICENSE).

The generated blocklists are compiled from third-party public threat intelligence feeds. Rights, licenses, and usage restrictions for upstream sources remain with their respective maintainers.

Use this blocklist at your own risk. False positives are possible.
