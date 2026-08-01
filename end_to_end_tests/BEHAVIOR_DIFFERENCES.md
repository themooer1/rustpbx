# RustPBX and Asterisk pcap comparison

This comparison is based on the twelve passing captures from the shared
transport × media-path matrix. It records portable behavior, not an attempt to
make RustPBX byte-for-byte identical to Asterisk. Random tags, branches,
Call-IDs, CSeq starting values, RTP SSRCs, ports within the PBX allocation
range, packet timing, and header ordering are deliberately not pinned.

## Shared black-box contract

Both implementations passed all of these checks with the same clients and
validator:

- two challenged and authenticated registrations, followed by two explicit
  unregister transactions;
- INVITE, final 200, ACK, BYE, and final 200 on UDP, TCP, and decryptable TLS;
- PCMA and negotiated RFC 4733 `telephone-event` delivered to the exact RTP
  receive addresses advertised by both clients;
- client-to-client RTP in direct mode and four anchored RTP directions in
  proxy mode;
- no RTP more than two seconds after BYE, and final unregister less than four
  seconds after BYE.

The observed final RTP packet was 0.184–0.207 seconds after BYE and final
unregister was 2.388–2.628 seconds after BYE. Direct captures decoded roughly
158–162 PCMA packets and 10 DTMF packets. Anchored captures decoded roughly
308–310 PCMA packets and 20 DTMF packets because tcpdump sees both sides of
each relayed packet.

## Expected and permitted differences

| Area | Asterisk/PJSIP | RustPBX | Ruling |
| --- | --- | --- | --- |
| INVITE authentication | `401` + `WWW-Authenticate`; retry uses `Authorization` | `407` + `Proxy-Authenticate`; retry uses `Proxy-Authorization` | Both header/code pairs are defined. RFC 3261 assigns 401 to a UAS and 407 to a proxy. The contract permits either observable role but rejects mixed families. |
| Dialog legs | Generates a new Call-ID and local CSeq space toward the callee | Also generates a new Call-ID and local CSeq space toward the callee | Both behave as a B2BUA for the call legs. Exact identifiers and CSeq starting values are intentionally unconstrained. |
| Direct media setup | Initially anchors RTP, then re-INVITEs both endpoints to exchange their client RTP targets | Places the opposite client's RTP target in the initial offer/answer path, without re-INVITEs | Both are valid offer/answer strategies. The contract evaluates the final negotiated data path, not how many offers were needed. |
| Direct media teardown | Re-INVITEs the surviving callee leg back to an Asterisk RTP port immediately before forwarding BYE | Forwards BYE without a teardown re-INVITE | Both end the dialog and media promptly. The shared callee scenario accepts any number of valid in-dialog re-INVITEs while still requiring BYE. |
| Provisional responses | One caller-leg `100 Trying`, then `180 Ringing` | Two caller-leg `100 Trying` responses, then `180 Ringing` | Multiple provisional responses are legal for a UAS. The second 100 is redundant and worth reviewing; a stateful proxy must not forward a downstream 100, while a B2BUA can generate responses on its independent upstream leg. |
| TCP/TLS lifetime | Reuses the callee registration flow for the incoming dialog and leaves SIP connections reusable until client cleanup | Same externally visible behavior | RFC 3261 recommends keeping reliable connections open. The test requires prompt dialog/media cleanup, not a TCP FIN immediately after BYE. |
| RTP source port | May differ from the SDP receive port, especially while transitioning direct media | May differ from the SDP receive port in proxy mode | RFC 3264 defines `c=`/`m=` as the receive destination and explicitly does not constrain the RTP source. The validator checks exact destinations and topology instead of false source symmetry. |

Relevant standards text:

- [RFC 3261 §22.2, UAS authentication](https://www.rfc-editor.org/rfc/rfc3261.html#section-22.2)
- [RFC 3261 §22.3, proxy authentication](https://www.rfc-editor.org/rfc/rfc3261.html#section-22.3)
- [RFC 3261 §14, modifying a session with re-INVITE](https://www.rfc-editor.org/rfc/rfc3261.html#section-14)
- [RFC 3261 §15, terminating a session](https://www.rfc-editor.org/rfc/rfc3261.html#section-15)
- [RFC 3261 §18, persistent transports](https://www.rfc-editor.org/rfc/rfc3261.html#section-18)
- [RFC 3264 §5, SDP receive addresses and RTP source independence](https://www.rfc-editor.org/rfc/rfc3264.html#section-5)
- [RFC 4733, negotiated telephony events](https://www.rfc-editor.org/rfc/rfc4733.html)

The authentication codes are not arbitrary synonyms. Asterisk's 401 directly
matches its UAS/B2BUA role. RustPBX creates a separate downstream dialog and
Call-ID after its 407, so the 407 is standards-aligned only if authentication
is considered a proxy-role front end before B2BUA call creation. That is a
plausible co-located architecture and interoperates correctly here; if the
inbound RustPBX component is intended to be solely the UAS half of a B2BUA,
401 would describe its RFC 3261 role more precisely.

## Differential findings from test development

These did not justify weakening the portable positive-call contract:

1. The original SIPp fixtures reused the same Via branch in two processes
   sharing one network namespace. Asterisk's transaction matcher treated one
   authenticated REGISTER as a retransmission of the other transaction;
   RustPBX happened to tolerate it. RFC 3261 §8.1.1.7 requires branch values to
   be unique across space and time, so the clients were wrong. Every fixture
   now appends its distinct local signaling port to `[branch]`.

2. The original caller emitted `To: To: <sip:...>` in ACK and BYE because the
   SIPp `[last_To:]` keyword already contains the header name. Asterisk rejected
   the malformed dialog requests; RustPBX accepted them. The client is fixed,
   but RustPBX's permissive parsing is a possible robustness/conformance issue:
   the value does not match the `To` grammar in RFC 3261 §25. This should be
   considered for a separate negative parser test rather than accepted in the
   successful-call suite.

3. RustPBX emits two upstream `100 Trying` responses within about 15–20 ms.
   This is harmless to conforming clients—RFC 3261 allows a UAS to send as many
   provisional responses as it likes—but it may mean a downstream 100 is being
   translated unnecessarily. If the relevant component is intended to act as
   a stateful proxy rather than the UAS half of a B2BUA, RFC 3261 §16.7 says a
   downstream 100 must not be forwarded. This is a review item, not a current
   interoperability failure.

No observed difference caused RustPBX to violate the positive behavior needed
to register phones, negotiate and exchange media/DTMF, hang up, stop RTP, and
clean up promptly.
