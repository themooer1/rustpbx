# SIP PBX end-to-end tests

This suite runs two authenticated SIPp endpoints and either RustPBX or an
independently packaged Asterisk/PJSIP fixture inside one Docker Desktop Linux
network namespace. A tcpdump sidecar starts before either client registers and
stops only after both clients explicitly unregister. It leaves a pcap, SIPp
logs, TLS key logs, Compose logs, and packet-validation report in a per-run,
per-case directory. Independent invocations use separate Compose projects and
Linux network namespaces, even when they run the same case.

The private keys under `certs/` and `sipp/` are fixed test fixtures. They are
intentionally reusable for packet decryption and must never be used outside
this isolated suite.

The comparison fixture pins Alpine 3.22's Asterisk 20.11.1-r6 package and uses
only the explicit files under `asterisk/`; it does not depend on a host
Asterisk installation or generated RustPBX-to-PJSIP configuration translation.

The matrix is PBX (`rustpbx`, `asterisk`) × transport (`udp`, `tcp`, `tls`) ×
media path (`direct`, `proxy`). `direct` maps to RustPBX
`media_proxy = "none"` or PJSIP `direct_media = yes`; `proxy` maps to RustPBX
`media_proxy = "all"` or PJSIP `direct_media = no`. The test calls extension
`1002` from `1001` using explicit canned configurations. SIPp sends RTP to the
`c=` address and `m=audio` port it learns through SDP; it does not use
hard-coded peer media destinations.

## Run

Docker Desktop on macOS is supported: all capture and tshark work occurs inside
Linux containers, so the host does not need `tcpdump`, GNU `timeout`, or
Wireshark.  The analyzer image is digest-pinned (`cincan/tshark` Wireshark
3.6.5); set `E2E_TSHARK_IMAGE` only when intentionally testing another decoder.

```sh
cd end_to_end_tests
make udp-direct
make PBX=asterisk tls-proxy
make rustpbx-matrix
make asterisk-matrix
make all-matrix
```

Equivalent direct invocations are `./run.sh rustpbx tls proxy` and
`./run.sh asterisk tls proxy`; the old two-argument form defaults to RustPBX.
The runner accepts
`E2E_RUN_ID` (a lowercase Compose-safe identifier, generated automatically),
`E2E_PHASE_TIMEOUT_SECONDS` (default 45), `E2E_SHUTDOWN_BUDGET_SECONDS`
(default 4), `E2E_RTP_GRACE_SECONDS` (default 2), and
`E2E_CAPTURE_DRAIN_SECONDS` (default 1) when diagnostics need more or less
tolerance. The RustPBX image builds the current checkout with core features
and cached, low-memory Cargo settings suitable for Docker Desktop's 4 GiB VM.

## Artifacts and acceptance checks

For run `ci-1`, RustPBX `udp direct` artifacts are at
`artifacts/ci-1/rustpbx-udp-direct/`; every other case uses the same
`<run-id>/<pbx>-<transport>-<media>` convention. Supplying the same
`E2E_RUN_ID` to separate processes intentionally selects the same Compose
project and is not safe for concurrent use. The important files are:

- `capture.pcap` — the complete trace from pre-registration through
  unregistration.
- `caller.keylog` and `callee.keylog` (TLS) — NSS `SSLKEYLOGFILE` format;
  validation merges them into `tls.keys`.
- `validation.txt` — the independent tshark result, with counts and failures.
- `sdp-media-targets.txt`, `caller-advertised-targets.txt`,
  `callee-advertised-targets.txt`, `rtp-sources.txt`,
  `rtp-destinations.txt`, and `rtp-flows.txt` — the SDP-derived endpoints and
  actual RTP evidence.

Validation requires digest-auth registration/challenge/success, explicit
unregistration, INVITE/200/ACK/BYE/200, correctly paired 401 or 407 digest
headers, and decoded bidirectional RTP. Every actual RTP destination must have
appeared in SDP, and PCMA must reach the exact address and port each SIPp client
itself bound and advertised. This makes a bogus or closed PBX media rewrite
fail even though tcpdump can still observe an attempted UDP send. The validator
checks both replayed PCMA and the dynamically negotiated RFC 4733
`telephone-event` payload type, plus direct versus four-direction anchored RTP
topology.

It also fails if RTP continues more than two seconds after BYE or either
endpoint waits longer than four seconds after BYE to unregister. It does not
require TCP or TLS to close after BYE: RFC 3261 recommends persistent SIP
connections, so dialog/media termination is the portable black-box contract.
TLS validation supplies the merged key log to tshark, so encrypted SIP traffic
must actually be decryptable rather than being mistaken for an empty trace.

See `BEHAVIOR_DIFFERENCES.md` for the pcap comparison, the standards reasoning
behind the shared contract, and possible RustPBX follow-up findings.

## Container interface

`run.sh` deliberately owns orchestration, while the SIPp image owns protocol
scenarios. It expects the Compose services `netns`, `rustpbx`, `asterisk`,
`capture`, `caller`, and `callee`; the runner starts only the selected PBX.
The persistent endpoint containers provide:

```text
/opt/e2e/run-phase.sh register|lifecycle|answer|call|unregister
```

`callee answer` must remain running until the call completes.  `caller call`
must issue BYE after successful media/DTMF exchange.  Each `unregister` phase
must return only after its `REGISTER` with `Expires: 0` has a `200 OK`.  The
capture service must log `E2E_CAPTURE_READY` only after tcpdump has started,
and must flush `capture.pcap` when Compose stops it.  The Compose configuration
receives `E2E_TRANSPORT`, `E2E_MEDIA_PROXY`, `E2E_SIP_PORT`, `E2E_CASE`, and an
absolute `E2E_ARTIFACT_DIR`, mounted as `/artifacts`. Asterisk additionally
mounts one explicit `pjsip-direct.conf` or `pjsip-proxy.conf`; no generated
cross-PBX configuration adapter is involved.

For TCP/TLS, the runner uses the additional `callee lifecycle` phase. It keeps
the callee's registered connection open, answers the out-of-call INVITE on that
same flow, then unregisters and closes it. This matches how a real connection-
oriented SIP phone receives calls; UDP continues to use separate phases.
