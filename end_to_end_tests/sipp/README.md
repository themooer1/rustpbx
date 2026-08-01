# SIPp end-to-end client

The image builds SIPp v3.7.7 (tag commit
`369b3c187f0ff96f3ec9795650820e80cf17c776`) and verifies the official
release source tarball SHA-256 before compiling it. It enables PCAP replay and SIPp's
OpenSSL key-log callback (`-DUSE_SSL=KL` in this upstream version).

Compose should build `end_to_end_tests` as its context with this file as its
Dockerfile, keep each client service running, and execute phases with:

```sh
/opt/e2e/run-phase.sh register
/opt/e2e/run-phase.sh lifecycle    # persistent TCP/TLS callee plus OOC answer
/opt/e2e/run-phase.sh answer       # callee, run in the background
/opt/e2e/run-phase.sh call         # caller; INVITE, media, RFC2833, BYE
/opt/e2e/run-phase.sh unregister
```

Required environment: `SIPP_ROLE` (`caller` or `callee`), `SIPP_USER`,
`SIPP_PASSWORD`, and `SIPP_TARGET`. `SIPP_TRANSPORT` is `udp`, `tcp`, or
`tls`; `SIPP_REMOTE_HOST` and `SIPP_REMOTE_PORT` select the PBX listener.
Set the same shared `SIPP_ARTIFACT_DIR` and `SIPP_LOG_PREFIX=caller|callee`.
TLS appends NSS/Wireshark-compatible secrets to
`$SIPP_ARTIFACT_DIR/$SIPP_LOG_PREFIX.keylog`; phase and lifecycle timestamps
are in `$SIPP_ARTIFACT_DIR/$SIPP_LOG_PREFIX-events.log`.

The default caller RTP range is 40000-40098 and callee range is 40100-40198;
override with `SIPP_RTP_MIN_PORT`/`SIPP_RTP_MAX_PORT`. PCAP replay uses raw
UDP sockets, so each SIPp service needs `NET_RAW` (and runs as root). SIPp
reads the peer's SDP `c=` address and `m=audio` port when replay begins;
there is no hard-coded RTP destination in the scenarios. A bogus/closed SDP
media endpoint therefore produces no valid end-to-end media and must fail the
PCAP validator rather than being masked by a canned target.
