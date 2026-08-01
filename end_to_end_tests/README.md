# RustPBX SIP end-to-end tests

This suite runs two authenticated SIPp endpoints and RustPBX inside one Docker
Desktop Linux network namespace.  A tcpdump sidecar starts before either client
registers and stops only after both clients explicitly unregister.  It leaves a
pcap, SIPp logs, TLS key logs, Compose logs, and packet-validation report in a
deterministic per-case directory.

The private keys under `certs/` and `sipp/` are fixed test fixtures. They are
intentionally reusable for packet decryption and must never be used outside
this isolated suite.

The matrix is transport (`udp`, `tcp`, `tls`) × media path (`direct`, `proxy`).
`direct` maps to RustPBX `media_proxy = "none"`; `proxy` maps to
`media_proxy = "all"`.  The test calls extension `1002` from `1001` using the
canned configuration.  SIPp sends RTP to the `c=` address and `m=audio` port it
learns through SDP; it does not use hard-coded peer media destinations.

## Run

Docker Desktop on macOS is supported: all capture and tshark work occurs inside
Linux containers, so the host does not need `tcpdump`, GNU `timeout`, or
Wireshark.  The analyzer image is digest-pinned (`cincan/tshark` Wireshark
3.6.5); set `E2E_TSHARK_IMAGE` only when intentionally testing another decoder.

```sh
cd end_to_end_tests
make udp-direct
make tls-proxy
make matrix
```

Equivalent direct invocation is `./run.sh tls proxy`.  The runner accepts
`E2E_PHASE_TIMEOUT_SECONDS` (default 45), `E2E_SHUTDOWN_BUDGET_SECONDS`
(default 4), `E2E_RTP_GRACE_SECONDS` (default 2), and
`E2E_CAPTURE_DRAIN_SECONDS` (default 1) when diagnostics need more or less
tolerance. The RustPBX image builds the current checkout with core features
and cached, low-memory Cargo settings suitable for Docker Desktop's 4 GiB VM.

## Artifacts and acceptance checks

For `udp direct`, artifacts are at `artifacts/udp-direct/`; every other case
uses the same `<transport>-<media>` convention.  The important files are:

- `capture.pcap` — the complete trace from pre-registration through
  unregistration.
- `caller.keylog` and `callee.keylog` (TLS) — NSS `SSLKEYLOGFILE` format;
  validation merges them into `tls.keys`.
- `validation.txt` — the independent tshark result, with counts and failures.
- `sdp-media-targets.txt`, `rtp-sources.txt`, `rtp-destinations.txt`, and
  `rtp-flows.txt` — the SDP-derived endpoints and actual RTP evidence.

Validation requires digest-auth registration/challenge/success, explicit
unregistration, INVITE/200/ACK/BYE/200, decoded bidirectional RTP, and RTP sent
to and originated by every SDP-advertised `c=`/`m=audio` endpoint. Requiring
reciprocal RTP makes a bogus address or closed media port fail even though
tcpdump can still observe an attempted UDP send. It verifies both replayed
PCMA and RFC 2833 RTP payloads. It also fails if RTP
continues more than two seconds after BYE or either endpoint waits longer than
four seconds after BYE to unregister. For TCP and TLS, both B2BUA dialog
streams must also close within that budget. TLS validation supplies the merged
key log to tshark, so encrypted SIP traffic must actually be decryptable rather
than being mistaken for an empty trace.

## Container interface

`run.sh` deliberately owns orchestration, while the SIPp image owns protocol
scenarios.  It expects the Compose services `netns`, `rustpbx`, `capture`,
`caller`, and `callee`; the persistent endpoint containers provide:

```text
/opt/e2e/run-phase.sh register|lifecycle|answer|call|unregister
```

`callee answer` must remain running until the call completes.  `caller call`
must issue BYE after successful media/DTMF exchange.  Each `unregister` phase
must return only after its `REGISTER` with `Expires: 0` has a `200 OK`.  The
capture service must log `E2E_CAPTURE_READY` only after tcpdump has started,
and must flush `capture.pcap` when Compose stops it.  The Compose configuration
receives `E2E_TRANSPORT`, `E2E_MEDIA_PROXY`, `E2E_SIP_PORT`, `E2E_CASE`, and an
absolute `E2E_ARTIFACT_DIR`, mounted as `/artifacts`.

For TCP/TLS, the runner uses the additional `callee lifecycle` phase. It keeps
the callee's registered connection open, answers the out-of-call INVITE on that
same flow, then unregisters and closes it. This matches how a real connection-
oriented SIP phone receives calls; UDP continues to use separate phases.
