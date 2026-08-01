#!/bin/sh
# Runs inside the wireshark/tshark image.  Do not move this analysis to the
# macOS host: Docker Desktop's host tools are not a reliable packet decoder.
set -eu

CASE_DIR=${1:?case artifact directory is required}
PBX=${2:?PBX is required}
TRANSPORT=${3:?transport is required}
MEDIA=${4:?media mode is required}
PCAP="$CASE_DIR/capture.pcap"
REPORT="$CASE_DIR/validation.txt"
KEYLOG="$CASE_DIR/tls.keys"
SHUTDOWN_BUDGET_SECONDS=${E2E_SHUTDOWN_BUDGET_SECONDS:-4}
RTP_GRACE_SECONDS=${E2E_RTP_GRACE_SECONDS:-2}

fail() {
    echo "FAIL: $*" | tee -a "$REPORT" >&2
    exit 1
}

require_file() {
    [ -s "$1" ] || fail "missing or empty $1"
}

run_tshark() {
    # TLS SIP must be decoded after decryption.  -d is harmless for UDP/TCP,
    # and makes the nonstandard/shared-netns listener explicit to tshark.
    if [ "$TRANSPORT" = tls ]; then
        tshark -n -r "$PCAP" -o "tls.keylog_file:$KEYLOG" \
            -o sip.tls.port:5061 -d tcp.port==5061,tls "$@"
    else
        tshark -n -r "$PCAP" "$@"
    fi
}

count_sip() {
    filter=$1
    run_tshark -Y "$filter" -T fields -e frame.number 2>>"$REPORT" | awk 'NF { n++ } END { print n + 0 }'
}

require_sip() {
    label=$1
    filter=$2
    minimum=$3
    actual=$(count_sip "$filter")
    echo "$label: $actual" | tee -a "$REPORT"
    [ "$actual" -ge "$minimum" ] || fail "$label expected >= $minimum, got $actual"
}

count_rtp() {
    filter=$1
    run_tshark -Y "$filter" -T fields -e frame.number 2>>"$REPORT" |
        awk 'NF { n++ } END { print n + 0 }'
}

write_sdp_targets() {
    filter=$1
    output=$2
    run_tshark -Y "$filter" -T fields \
        -e sdp.connection_info.address -e sdp.media.port 2>>"$REPORT" |
        awk -F '\t' '
          $1 != "" && $2 != "" {
            split($1, ips, ","); split($2, ports, ",");
            for (i in ips) for (j in ports)
              if (ips[i] != "0.0.0.0" && ports[j] != "0") print ips[i] ":" ports[j]
          }' | sort -u >"$output"
}

require_file "$PCAP"
: >"$REPORT"
echo "case: $PBX/$TRANSPORT/$MEDIA" | tee -a "$REPORT"

if [ "$TRANSPORT" = tls ]; then
    # Each TLS client logs different connection secrets.  Merge all logs so
    # either registration connection and both dialog connections decrypt.
    set -- "$CASE_DIR"/*.keylog "$CASE_DIR"/*.keys
    found=0
    : >"$KEYLOG"
    for candidate in "$@"; do
        [ -f "$candidate" ] || continue
        [ "$candidate" = "$KEYLOG" ] && continue
        awk 'NF && !seen[$0]++ { print }' "$candidate" >>"$KEYLOG"
        found=1
    done
    [ "$found" -eq 1 ] && [ -s "$KEYLOG" ] || fail "TLS requires nonempty SIPp SSLKEYLOGFILE output"
fi

# Authentication has two successful registrations (one for each endpoint), a
# challenge for digest authentication, and two explicit Expires: 0 requests.
require_sip "REGISTER requests" 'sip.Method == "REGISTER"' 4
require_sip "digest authentication challenges" 'sip.Status-Code == 401 || sip.Status-Code == 407' 2
require_sip "REGISTER success responses" 'sip.CSeq.method == "REGISTER" && sip.Status-Code == 200' 4
require_sip "explicit unregister requests" 'sip.Method == "REGISTER" && sip.Expires == 0' 2
require_sip "caller unregister requests" 'sip.Method == "REGISTER" && sip.Expires == 0 && sip.from.user == "1001"' 1
require_sip "callee unregister requests" 'sip.Method == "REGISTER" && sip.Expires == 0 && sip.from.user == "1002"' 1

# RFC 3261 assigns 401/WWW-Authenticate to a UAS or registrar and
# 407/Proxy-Authenticate to a proxy. Either architectural role is valid, but
# mixing the response code and header family is not.
bad_401=$(count_sip 'sip.Status-Code == 401 && !sip.WWW-Authenticate')
bad_407=$(count_sip 'sip.Status-Code == 407 && !sip.Proxy-Authenticate')
[ "$bad_401" -eq 0 ] || fail "401 response without WWW-Authenticate"
[ "$bad_407" -eq 0 ] || fail "407 response without Proxy-Authenticate"
invite_401=$(count_sip 'sip.CSeq.method == "INVITE" && sip.Status-Code == 401')
invite_407=$(count_sip 'sip.CSeq.method == "INVITE" && sip.Status-Code == 407')
if [ "$invite_401" -gt 0 ]; then
    require_sip "INVITE Authorization retries" 'sip.Method == "INVITE" && sip.Authorization' 1
fi
if [ "$invite_407" -gt 0 ]; then
    require_sip "INVITE Proxy-Authorization retries" 'sip.Method == "INVITE" && sip.Proxy-Authorization' 1
fi
echo "INVITE authentication challenges: 401=$invite_401 407=$invite_407" | tee -a "$REPORT"

require_sip "INVITE" 'sip.Method == "INVITE"' 1
require_sip "INVITE 200 OK" 'sip.CSeq.method == "INVITE" && sip.Status-Code == 200' 1
require_sip "ACK" 'sip.Method == "ACK"' 1
require_sip "BYE" 'sip.Method == "BYE"' 1
require_sip "BYE 200 OK" 'sip.CSeq.method == "BYE" && sip.Status-Code == 200' 1

# Record all SDP receive destinations. RFC 3264 explicitly does not require
# RTP to originate from its advertised receive address, so source symmetry is
# not part of this portable contract.
write_sdp_targets \
    'sdp.media.port && sdp.connection_info.address' \
    "$CASE_DIR/sdp-media-targets.txt"
[ -s "$CASE_DIR/sdp-media-targets.txt" ] || fail "no SDP c=/m= media destinations decoded"

# These are the receive addresses the clients themselves placed in SDP. They
# are stronger evidence than a broad configured port range: if a PBX rewrites
# a client leg to a bogus or closed destination, no media will reach the exact
# address/port that SIPp bound and advertised.
write_sdp_targets \
    'sdp.media.port && sdp.connection_info.address && (udp.srcport == 5062 || tcp.srcport == 5062)' \
    "$CASE_DIR/caller-advertised-targets.txt"
write_sdp_targets \
    'sdp.media.port && sdp.connection_info.address && (udp.srcport == 5064 || tcp.srcport == 5064)' \
    "$CASE_DIR/callee-advertised-targets.txt"
[ -s "$CASE_DIR/caller-advertised-targets.txt" ] || fail "no caller-originated SDP media target"
[ -s "$CASE_DIR/callee-advertised-targets.txt" ] || fail "no callee-originated SDP media target"

run_tshark -Y rtp -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport 2>>"$REPORT" |
    awk -F '\t' -v sources="$CASE_DIR/rtp-sources.unsorted" \
        -v destinations="$CASE_DIR/rtp-destinations.unsorted" \
        'NF == 4 && $1 != "" && $3 != "" {
          print $1 ":" $2 " -> " $3 ":" $4
          print $1 ":" $2 > sources
          print $3 ":" $4 > destinations
        }' \
    >"$CASE_DIR/rtp-flows.txt"
[ -s "$CASE_DIR/rtp-flows.txt" ] || fail "no RTP packets decoded"
sort -u "$CASE_DIR/rtp-sources.unsorted" >"$CASE_DIR/rtp-sources.txt"
sort -u "$CASE_DIR/rtp-destinations.unsorted" >"$CASE_DIR/rtp-destinations.txt"
rm -f "$CASE_DIR/rtp-sources.unsorted" "$CASE_DIR/rtp-destinations.unsorted"

# Every actual destination must have appeared in negotiated SDP. This allows
# superseded targets from a re-INVITE to remain unused while rejecting media
# sent to an address that neither endpoint advertised.
while IFS= read -r target; do
    grep -F -x "$target" "$CASE_DIR/sdp-media-targets.txt" >/dev/null 2>&1 ||
        fail "RTP destination $target was never advertised in SDP"
done <"$CASE_DIR/rtp-destinations.txt"

flow_count=$(sort -u "$CASE_DIR/rtp-flows.txt" | wc -l | tr -d ' ')
echo "distinct RTP flows: $flow_count" | tee -a "$REPORT"
[ "$flow_count" -ge 2 ] || fail "expected bidirectional RTP, got $flow_count flow(s)"

# Require PCMA at every exact client-originated SDP receive target without
# assuming that a sender's source port equals its advertised receive port.
caller_audio=0
for target in $(cat "$CASE_DIR/caller-advertised-targets.txt"); do
    target_ip=${target%:*}
    target_port=${target##*:}
    packets=$(count_rtp "rtp.p_type == 8 && ip.dst == $target_ip && udp.dstport == $target_port")
    echo "PCMA delivered to caller target $target: $packets" | tee -a "$REPORT"
    [ "$packets" -gt 0 ] || fail "caller SDP target $target did not receive PCMA RTP"
    caller_audio=$((caller_audio + packets))
done
callee_audio=0
for target in $(cat "$CASE_DIR/callee-advertised-targets.txt"); do
    target_ip=${target%:*}
    target_port=${target##*:}
    packets=$(count_rtp "rtp.p_type == 8 && ip.dst == $target_ip && udp.dstport == $target_port")
    echo "PCMA delivered to callee target $target: $packets" | tee -a "$REPORT"
    [ "$packets" -gt 0 ] || fail "callee SDP target $target did not receive PCMA RTP"
    callee_audio=$((callee_audio + packets))
done
echo "PCMA delivered to caller: $caller_audio" | tee -a "$REPORT"
echo "PCMA delivered to callee: $callee_audio" | tee -a "$REPORT"

direct_caller_to_callee=$(count_rtp 'rtp && udp.srcport >= 40000 && udp.srcport <= 40098 && udp.dstport >= 40100 && udp.dstport <= 40198')
direct_callee_to_caller=$(count_rtp 'rtp && udp.srcport >= 40100 && udp.srcport <= 40198 && udp.dstport >= 40000 && udp.dstport <= 40098')
if [ "$MEDIA" = direct ]; then
    [ "$direct_caller_to_callee" -gt 0 ] || fail "direct mode has no caller-to-callee RTP"
    [ "$direct_callee_to_caller" -gt 0 ] || fail "direct mode has no callee-to-caller RTP"
else
    [ "$direct_caller_to_callee" -eq 0 ] || fail "proxy mode unexpectedly carried direct caller-to-callee RTP"
    [ "$direct_callee_to_caller" -eq 0 ] || fail "proxy mode unexpectedly carried direct callee-to-caller RTP"
    for label_and_filter in \
        'caller uplink|rtp && udp.srcport >= 40000 && udp.srcport <= 40098 && udp.dstport >= 30000 && udp.dstport <= 30019' \
        'caller downlink|rtp && udp.srcport >= 30000 && udp.srcport <= 30019 && udp.dstport >= 40000 && udp.dstport <= 40098' \
        'callee uplink|rtp && udp.srcport >= 40100 && udp.srcport <= 40198 && udp.dstport >= 30000 && udp.dstport <= 30019' \
        'callee downlink|rtp && udp.srcport >= 30000 && udp.srcport <= 30019 && udp.dstport >= 40100 && udp.dstport <= 40198'
    do
        label=${label_and_filter%%|*}
        filter=${label_and_filter#*|}
        packets=$(count_rtp "$filter")
        [ "$packets" -gt 0 ] || fail "proxy mode has no $label RTP"
    done
fi

# The scenarios replay PCMA and a RFC 2833 telephone-event after SDP
# negotiation.  Checking the RTP payload types proves this is real media, not
# just a successful dialog with an empty UDP socket.
audio_packets=$(count_rtp 'rtp.p_type == 8')
# telephone-event uses a dynamically negotiated RTP payload type. Extract all
# mappings seen in SDP instead of assuming the conventional value 101. The
# pinned Wireshark 3.6 image leaves sdp.media_attribute.value empty for rtpmap,
# but its detailed decoder exposes the parsed Media Format and MIME Type on
# adjacent lines.
run_tshark -Y sdp -V 2>>"$REPORT" |
    awk '
      /Media Format: [0-9]+$/ { format = $NF }
      /MIME Type: telephone-event$/ && format != "" { print format; format = "" }
    ' | sort -nu >"$CASE_DIR/telephone-event-payloads.txt"
[ -s "$CASE_DIR/telephone-event-payloads.txt" ] || fail "SDP did not negotiate telephone-event"
dtmf_filter=$(awk 'BEGIN { sep = "" } { printf "%srtp.p_type == %s", sep, $1; sep = " || " } END { print "" }' "$CASE_DIR/telephone-event-payloads.txt")
dtmf_packets=$(count_rtp "$dtmf_filter")
callee_dtmf_packets=0
for target in $(cat "$CASE_DIR/callee-advertised-targets.txt"); do
    target_ip=${target%:*}
    target_port=${target##*:}
    packets=$(count_rtp "($dtmf_filter) && ip.dst == $target_ip && udp.dstport == $target_port")
    callee_dtmf_packets=$((callee_dtmf_packets + packets))
done
echo "PCMA RTP packets: $audio_packets" | tee -a "$REPORT"
echo "RFC4733 telephone-event RTP packets: $dtmf_packets" | tee -a "$REPORT"
[ "$audio_packets" -gt 0 ] || fail "no canned PCMA RTP was decoded"
[ "$dtmf_packets" -gt 0 ] || fail "no RFC2833 telephone-event RTP was decoded"
[ "$callee_dtmf_packets" -gt 0 ] || fail "callee did not receive negotiated telephone-event RTP"

# A valid BYE must cause media to stop quickly and both unregister transactions
# to complete quickly.  This rejects a suite that merely waits for a media/RTP
# timeout and then happens to send cleanup signalling.
run_tshark -Y 'sip.Method == "BYE"' -T fields -e frame.time_epoch 2>>"$REPORT" |
    awk 'NF { print; exit }' >"$CASE_DIR/bye-time.txt"
BYE_TIME=$(sed -n '1p' "$CASE_DIR/bye-time.txt")
[ -n "$BYE_TIME" ] || fail "could not determine BYE timestamp"

run_tshark -Y rtp -T fields -e frame.time_epoch 2>>"$REPORT" |
    awk 'NF { print }' >"$CASE_DIR/rtp-times.txt"
last_rtp=$(awk 'END { print }' "$CASE_DIR/rtp-times.txt")
[ -n "$last_rtp" ] || fail "could not determine final RTP timestamp"
awk -v bye="$BYE_TIME" -v last="$last_rtp" 'BEGIN {
    printf "last RTP relative to BYE: %+.3fs\n", last - bye
  }' | tee -a "$REPORT"
awk -v bye="$BYE_TIME" -v grace="$RTP_GRACE_SECONDS" '
    $1 > bye + grace { printf "RTP continues %.3fs after BYE\n", $1 - bye; exit 1 }
  ' "$CASE_DIR/rtp-times.txt" || fail "RTP did not stop within ${RTP_GRACE_SECONDS}s after BYE"

run_tshark -Y 'sip.Method == "REGISTER" && sip.Expires == 0' \
    -T fields -e frame.time_epoch 2>>"$REPORT" |
    awk 'NF { print }' >"$CASE_DIR/unregister-times.txt"
last_unreg=$(awk 'END { print }' "$CASE_DIR/unregister-times.txt")
[ -n "$last_unreg" ] || fail "could not determine final unregister timestamp"
awk -v bye="$BYE_TIME" -v last="$last_unreg" 'BEGIN {
    printf "final unregister after BYE: %.3fs\n", last - bye
  }' | tee -a "$REPORT"
awk -v bye="$BYE_TIME" -v last="$last_unreg" -v budget="$SHUTDOWN_BUDGET_SECONDS" 'BEGIN {
    if (last > bye + budget) {
      printf "last unregister %.3fs after BYE (budget %.3fs)\n", last - bye, budget
      exit 1
    }
  }' || fail "endpoints did not close promptly after BYE"

if [ "$MEDIA" = direct ]; then
    echo "direct mode: validated bidirectional client-to-client RTP" | tee -a "$REPORT"
else
    echo "proxy mode: validated four anchored RTP directions" | tee -a "$REPORT"
fi
echo "PASS" | tee -a "$REPORT"
