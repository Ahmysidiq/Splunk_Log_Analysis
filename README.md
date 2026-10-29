# Splunk Log Analysis Lab — SSH Brute Force & Web Recon Detection

An intermediate, self-built log analysis lab run on Kali Linux: simulate an
attack, capture it, ingest it into Splunk, and detect it using SPL —
cross-checked against raw CLI analysis so the SIEM isn't a black box.

## What this lab covers

- Simulated an SSH brute-force attack (Hydra) against a dedicated low-privilege
  account, ending in one successful login after a burst of failures
- Simulated web reconnaissance / directory enumeration against Apache (curl)
- Captured all traffic live with `tcpdump`
- Ingested authentication logs and web access logs into Splunk
- Built SPL searches to detect:
  - the brute-force failure cluster
  - the failure-to-success transaction pattern
  - the web enumeration pattern (burst of 404s from one source)
  - cross-source timing correlation
- Cross-checked every Splunk finding against raw `grep`/`awk` output
- Produced a short incident summary (see `notes/incident-summary.md`)

Full step-by-step walkthrough: [`docs/Log_Analysis_Lab_Splunk_Kali.pdf`](docs/Log_Analysis_Lab_Splunk_Kali.pdf)

## Environment

| Component | Details |
|---|---|
| Attacker/analyst host | Kali Linux |
| Target | Same host (loopback), dedicated `labuser` account + local Apache |
| Tools | Splunk Enterprise (Free license), Hydra, tcpdump, grep/awk |

## Key SPL queries

All queries used are in [`spl-queries/queries.spl`](spl-queries/queries.spl). Highlights:

**Detect the brute-force cluster**
```spl
index=lab_logs sourcetype=linux_secure "Failed password"
| bin _time span=1m
| stats count by _time, user, src_ip
| where count > 3
```

**Catch the failure-to-success transition**
```spl
index=lab_logs sourcetype=linux_secure ("Failed password" OR "Accepted password")
| transaction user startswith="Failed password" endswith="Accepted password" maxspan=5m
| table _time, user, duration, eventcount
```

**Detect web enumeration**
```spl
index=lab_logs sourcetype=access_combined status=404
| stats count, values(uri_path) as paths_tried by clientip
| where count >= 4
```

## Screenshots

| Brute-force cluster | Failure → success transaction | Dashboard |
|---|---|---|
| ![brute force](screenshots/brute-force-cluster.png) | ![transaction](screenshots/transaction-search.png) | ![dashboard](screenshots/dashboard.png) |

## Findings

Full writeup: [`notes/incident-summary.md`](notes/incident-summary.md)

Short version: isolated a tight cluster of failed SSH logins against a single
account, confirmed the attack succeeded on the attempt following the cluster,
and correlated it against a concurrent web enumeration pattern from curl
hitting common admin/config paths — consistent with a single actor doing
broad reconnaissance rather than two unrelated events.

## Troubleshooting notes (the part tutorials usually skip)

Real problems hit and resolved during this lab, worth noting for anyone
running it themselves:

- **OpenSSH `PerSourcePenalties`** (new in OpenSSH 9.8) throttled the
  simulated brute-force mid-attack — a live example of a modern anti-brute-force
  control working as intended. Disabled for the lab via `sshd_config`.
- **Splunk admin login failures** traced back to a stale seeded password;
  resolved by reseeding via a forced first-time-setup.
- **License group silently reverting to Trial** on every restart — root
  cause was a leftover trial license file still present under
  `/opt/splunk/etc/licenses/trial/`; removing it let the Free license group
  stick.
- **Searches returning 0 results** traced back to a Data Input pointed at
  the wrong index — verified and fixed via Settings > Indexes and
  Settings > Data Inputs rather than guessing.

## Disclaimer

Every action in this lab targets `127.0.0.1` (this machine only). This is a
self-contained, isolated lab — none of these techniques were run against any
system the author does not own.

## License

MIT
