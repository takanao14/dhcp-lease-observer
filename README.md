# DHCP Lease Observer

This repository contains the IX2106 DHCP lease collector and its anonymized
Stage 1 fixtures. The Go collector uses a pinned SSH host key, an
IX2106-specific algorithm allowlist, bounded prompt-driven shell I/O, and fixed
commands only. It derives opaque HMAC device IDs, emits deterministic lease
transition events, and atomically persists private last-good state without
plain MAC addresses. It has not yet been enabled against a live device.

The fixtures are anonymized. They contain only TEST-NET-1 IPv4 addresses,
synthetic locally administered MAC addresses, and synthetic device/profile
names. Never add credentials or unredacted router output to this repository.

## Parser contract

- Accept the known IX2106 lease and ARP table layouts and a final config prompt.
- Preserve `BoundTime` and `LeaseTime` as integer seconds.
- Accept only the documented and observed `Bound` lease state. Preserve profile
  names as source strings and reject an unconfirmed state until an anonymized
  real-device fixture establishes its semantics.
- Preserve ARP TTL and uptime as source strings until their semantics are
  confirmed.
- Validate the row count reported by the device.
- Reject paged, truncated, unknown, and config-lock transcripts.
- Treat `Leased to 0 clients` as a valid empty snapshot.
- Accept SSH EOF only after the expected config prompt. EOF before the prompt is
  retryable `unexpected_eof`; the partial result is unusable and cannot emit
  lease-removal events.
- Apply the same prompt boundary to command deadlines. A timeout before the
  prompt is retryable `timeout`; a deadline observed after the prompt does not
  invalidate the already complete command body.
- Classify rejected SSH authentication as non-retryable
  `authentication_failed`. Do not retain a username, password, or device
  transcript in its fixture or error contract.
- Classify rejection of an allowlisted command after successful authentication
  as non-retryable `authorization_failed`. Record the fixed command name, but do
  not retain the device's rejection transcript.
- Classify a mismatch against the pinned SSH identity as non-retryable
  `host_key_mismatch`. Do not retain the observed key, fingerprint, or target
  address in fixtures or normal logs; require independent verification before
  changing the pin.
- Classify an occupied exclusive config process as retryable `config_occupied`.
  Leave the other session untouched, do not invoke a forced unlock command, and
  retry at the next scheduled poll.
- Classify a pager marker after `terminal length 0` as non-retryable
  `pager_detected` for the current poll. Preserve last-good state, perform no
  same-poll retry, and leave the next scheduled poll enabled.
- Require the Monitor config prompt after each fixed command. A different
  prompt-like terminator is non-retryable `prompt_mismatch` for the current poll,
  even when the command body alone would parse successfully.
- Normalize a parser rejection after a complete prompt as non-retryable
  `parse_failed` for the current poll. Preserve last-good state and never copy a
  rejected source row or parser exception detail into the failure contract.
- Remove one exact echo of the fixed command before parsing and also accept a
  transcript with echo disabled. Reject a different command-like first line as
  non-retryable `command_echo_mismatch` for the current poll.

## Run

```console
go test ./...
go run ./cmd/dhcp-lease-observer --config ./config.example.json --check-config
go run ./cmd/package-release --version v0.1.0 --output-dir dist
```

This is a public repository licensed under the MIT License. Production releases
will provide immutable Linux artifacts and checksums for deployment repositories
to pin; deployments must not consume a mutable `latest` reference.

Release tags matching `v*.*.*` run tests, race detection, vet, and the Go fixture
contracts before publishing deterministic `linux/amd64` and `linux/arm64`
archives plus `checksums.txt`. Each archive contains only the statically linked
collector binary and `LICENSE`; the version is embedded in the binary at build
time.

Before reporting parser failures, redact device output as described in
[`SECURITY.md`](SECURITY.md). Do not attach raw router transcripts to an issue.

## State contract

- Require an identity key containing at least 32 bytes. Deployment must create
  it from a cryptographically secure random source and preserve it across
  upgrades.
- Derive versioned, opaque device and key IDs with domain-separated
  HMAC-SHA256. Never persist a plain MAC address in last-good state or events.
- Reject an identity-key change against existing state instead of emitting a
  mass removal and rebinding event set.
- Normalize IX2106 relative lease timers to UTC `bound_at` and `expires_at`
  values at the observation boundary.
- Emit only `lease_bound`, `lease_renewed`, `lease_moved`, and `lease_removed`
  transitions. A missing lease is not called expired without stronger evidence.
- Write last-good JSON through a mode `0600` temporary file, `fsync`, and atomic
  rename in the destination directory. Reject non-regular, over-permissive,
  oversized, unknown-field, trailing, and invalid state files.

## Output contract

- Render collector health and the caller-supplied last-good leases as
  Prometheus text format. A failed collection sets `up` to zero while preserving
  the previous lease samples; an initial failure may pass an empty lease set.
- Accept only an explicit low-cardinality scope. Do not turn the IX2106 profile
  string into a Prometheus label implicitly.
- Keep metric names fixed, validate all label inputs, escape label values, sort
  lease samples by opaque device ID, and cap output at 2,048 leases and 4 MiB.
- Atomically replace the node_exporter textfile through a mode `0644` temporary
  file, `fsync`, rename, and directory `fsync`.
- Validate the complete transition event set before writing one JSON object per
  line. Cap one poll at 4,096 events and propagate destination write failures.

## Collector configuration

- Start from `config.example.json`; configuration rejects unknown fields,
  symlinks, group/world-writable files, unbounded timeouts, and unsafe labels.
- Supply credentials separately with `--credentials-dir`. The directory must
  contain mode `0600` regular files named `ix2106-password` and `identity-key`.
  The identity key must contain at least 32 random bytes.
- `--check-config` validates configuration without reading credentials or
  contacting the router. Normal collection writes JSON Lines events to stdout.
- DHCP lease data is authoritative. Failure to collect or parse the optional
  ARP table produces an `up=true`, degraded status event and records only a
  sanitized ARP failure class.
