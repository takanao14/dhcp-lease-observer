# DHCP Lease Observer

This Go collector retrieves IX2106 DHCP leases using a pinned SSH host key,
an IX2106-specific algorithm allowlist, bounded prompt-driven shell I/O, and
fixed commands only. It derives opaque HMAC device IDs, emits deterministic lease
transition events, and atomically persists private last-good state without
plain MAC addresses. It has not yet been enabled against a live device.

The fixtures are anonymized. They contain only TEST-NET-1 IPv4 addresses,
synthetic locally administered MAC addresses, and synthetic device/profile
names. Follow [`SECURITY.md`](SECURITY.md) when preparing fixtures or reporting
failures; never include credentials or unredacted router output.

## Parser contract

- Accept the known IX2106 lease and ARP table layouts and an optional final
  config prompt. Session framing requires the prompt before parsing.
- Preserve `BoundTime` and `LeaseTime` as integer seconds, and profile names as
  source strings.
- Retain only `Bound` rows. Accept observed `Offered` and `Abandoned` rows only
  with `N/A` timers and exclude them from the snapshot. Reject other states.
- Require the reported lease count to match retained `Bound` rows and the ARP
  dynamic count to match parsed neighbors. `Leased to 0 clients` is valid.
- Preserve ARP TTL and uptime as source strings until their semantics are
  confirmed.
- Reject paged, truncated, unknown, and config-lock transcripts.

## Session and failure contract

Require the Monitor config prompt after each fixed command, even when the body
alone would parse successfully. EOF or a deadline after a complete prompt does
not invalidate the command body. Remove one exact command echo before parsing;
echo-disabled responses are also accepted.

Acquisition, framing, and lease parsing failures preserve last-good state and
emit no lease transitions. Errors retain only sanitized failure classes and,
for authorization failures, the fixed command name. Never include source output,
credentials, usernames, target addresses, observed keys, fingerprints, rejected
rows, or parser exception details in failure logs or fixtures.

| Condition | Failure class | Retryable |
| --- | --- | --- |
| EOF before the expected prompt | `unexpected_eof` | Yes |
| Command deadline before the expected prompt | `timeout` | Yes |
| Rejected SSH authentication | `authentication_failed` | No |
| Rejected fixed command after authentication | `authorization_failed` | No |
| Pinned SSH identity mismatch | `host_key_mismatch` | No |
| Occupied exclusive config process | `config_occupied` | Yes |
| Pager marker after `terminal length 0` | `pager_detected` | No |
| Different prompt-like terminator | `prompt_mismatch` | No |
| Parser rejection after a complete prompt | `parse_failed` | No |
| Different command-like first line | `command_echo_mismatch` | No |

Each poll makes one attempt; retryability never triggers an internal retry or
disables the next scheduled poll. Leave occupied config sessions untouched and
never force an unlock. Independently verify the SSH identity before changing
its pin.

DHCP leases are authoritative. Optional ARP acquisition or parsing failures
leave Prometheus `up` at one, emit `status="degraded"`, and record a sanitized
ARP failure class.

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

## State contract

- Require an identity key containing at least 32 bytes. Deployment must create
  it from a cryptographically secure random source and preserve it across
  upgrades.
- Derive versioned, opaque device and key IDs with domain-separated
  HMAC-SHA256. Never persist a plain MAC address in last-good state or events.
- Reject an identity-key change against existing state instead of emitting a
  mass removal and rebinding event set.
- Normalize IX2106 relative lease timers to UTC `bound_at` and `expires_at`
  values at the complete lease-response boundary, before optional ARP collection.
  ARP delays and failures do not shift lease timers or create renewal events.
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
- Write runtime events to stdout as JSON Lines with common `schema_version`,
  `observed_at`, `event`, and `severity` fields. Events emitted after loading
  configuration also include `source` and `source_instance`.
- Use `event` consistently for lease transitions and collector status. Status
  records use `status=degraded|failed` and never combine `up` and `degraded`
  booleans. A successful poll with no lease transitions emits no log heartbeat;
  use the Prometheus health and timestamp metrics for that purpose.
- Emit sanitized startup failures as `collector_start_failed`. Runtime failures
  are not duplicated as plain-text stderr messages. Stderr is reserved for CLI
  usage errors and the fallback case where a JSON log cannot be written.

## Collector configuration

- Use GNU-style long options with two hyphens. Multi-character single-hyphen
  forms such as `-config` are rejected; `-h` is the only supported short form.
- Start from `config.example.json`; configuration rejects unknown fields,
  symlinks, group/world-writable files, unbounded timeouts, and unsafe labels.
- Supply credentials separately with `--credentials-dir`. The directory must
  contain regular files named `ix2106-password` and `identity-key` that are
  neither group-writable nor accessible to other users, so both a private
  `0600` file and a systemd `LoadCredential` file exposed as `0440` are
  accepted.
- `--check-config` validates configuration without reading credentials or
  contacting the router.
- The process handles SIGINT and SIGTERM by canceling the bounded collection
  context so a systemd stop does not wait for the SSH phase timeout.
