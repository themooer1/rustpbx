#!/bin/sh
# Runs inside the wireshark/tshark image.  Do not move this analysis to the
# macOS host: Docker Desktop's host tools are not a reliable packet decoder.
set -eu

CASE_DIR=${1:?case artifact directory is required}
TRANSPORT=${2:?transport is required}
MEDIA=${3:?media mode is required}
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

require_file "$PCAP"
: >"$REPORT"
echo "case: $TRANSPORT/$MEDIA" | tee -a "$REPORT"

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

require_sip "INVITE" 'sip.Method == "INVITE"' 1
require_sip "INVITE 200 OK" 'sip.CSeq.method == "INVITE" && sip.Status-Code == 200' 1
require_sip "ACK" 'sip.Method == "ACK"' 1
require_sip "BYE" 'sip.Method == "BYE"' 1
require_sip "BYE 200 OK" 'sip.CSeq.method == "BYE" && sip.Status-Code == 200' 1

# SDP must advertise the endpoints that actually receive media.  RTP dissector
# ports are learned from SDP; explicitly compare every advertised IP:port to a
# destination in the trace so an incorrect c= address or m= port cannot pass.
run_tshark -Y 'sdp.media.port && sdp.connection_info.address' -T fields \
    -e sdp.connection_info.address -e sdp.media.port 2>>"$REPORT" |
    awk -F '\t' '
      $1 != "" && $2 != "" {
        split($1, ips, ","); split($2, ports, ",");
        for (i in ips) for (j in ports)
          if (ips[i] != "0.0.0.0" && ports[j] != "0") print ips[i] ":" ports[j]
      }' | sort -u >"$CASE_DIR/sdp-media-targets.txt"
[ -s "$CASE_DIR/sdp-media-targets.txt" ] || fail "no SDP c=/m= media destinations decoded"

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

while IFS= read -r target; do
    grep -F -x "$target" "$CASE_DIR/rtp-destinations.txt" >/dev/null 2>&1 ||
        fail "SDP advertised RTP destination $target did not receive RTP"
    # A send toward an unreachable UDP port is still visible in tcpdump.  A
    # reciprocal RTP source proves that the advertised endpoint was live and
    # participating, so a bogus c= address or closed m= port cannot pass.
    grep -F -x "$target" "$CASE_DIR/rtp-sources.txt" >/dev/null 2>&1 ||
        fail "SDP advertised RTP endpoint $target did not originate reciprocal RTP"
done <"$CASE_DIR/sdp-media-targets.txt"

flow_count=$(sort -u "$CASE_DIR/rtp-flows.txt" | wc -l | tr -d ' ')
echo "distinct RTP flows: $flow_count" | tee -a "$REPORT"
[ "$flow_count" -ge 2 ] || fail "expected bidirectional RTP, got $flow_count flow(s)"

# The scenarios replay PCMA and a RFC 2833 telephone-event after SDP
# negotiation.  Checking the RTP payload types proves this is real media, not
# just a successful dialog with an empty UDP socket.
audio_packets=$(run_tshark -Y 'rtp.p_type == 8' -T fields -e frame.number 2>>"$REPORT" | awk 'NF { n++ } END { print n + 0 }')
dtmf_packets=$(run_tshark -Y 'rtp.p_type == 101' -T fields -e frame.number 2>>"$REPORT" | awk 'NF { n++ } END { print n + 0 }')
echo "PCMA RTP packets: $audio_packets" | tee -a "$REPORT"
echo "RFC2833 RTP packets: $dtmf_packets" | tee -a "$REPORT"
[ "$audio_packets" -gt 0 ] || fail "no canned PCMA RTP was decoded"
[ "$dtmf_packets" -gt 0 ] || fail "no RFC2833 telephone-event RTP was decoded"

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

# For connection-oriented SIP, each B2BUA dialog leg has its own TCP stream.
# Require the caller and callee BYE streams to close, rather than merely
# accepting a SIP transaction followed by an RTP inactivity timeout.
if [ "$TRANSPORT" != udp ]; then
    run_tshark -Y 'sip.Method == "BYE"' -T fields \
        -e tcp.stream -e frame.time_epoch 2>>"$REPORT" |
        awk 'NF == 2 && !seen[$1]++ { print }' >"$CASE_DIR/bye-streams.txt"
    bye_stream_count=$(wc -l <"$CASE_DIR/bye-streams.txt" | tr -d ' ')
    [ "$bye_stream_count" -ge 2 ] || fail "expected both TCP/TLS BYE streams, got $bye_stream_count"
    while read -r stream stream_bye; do
        close_time=$(run_tshark \
            -Y "tcp.stream == $stream && (tcp.flags.fin == 1 || tcp.flags.reset == 1)" \
            -T fields -e frame.time_epoch 2>>"$REPORT" |
            awk -v bye="$stream_bye" '$1 >= bye { print; exit }')
        [ -n "$close_time" ] || fail "SIP stream $stream did not close after BYE"
        close_delta=$(awk -v bye="$stream_bye" -v closed_at="$close_time" \
            -v budget="$SHUTDOWN_BUDGET_SECONDS" 'BEGIN {
              delta = closed_at - bye
              printf "%.3f", delta
              if (delta > budget) exit 1
            }') || fail "SIP stream $stream did not close promptly after BYE"
        echo "SIP stream $stream closed after BYE: ${close_delta}s" | tee -a "$REPORT"
    done <"$CASE_DIR/bye-streams.txt"
fi

if [ "$MEDIA" = direct ]; then
    echo "direct mode: validated reciprocal RTP for every SDP endpoint" | tee -a "$REPORT"
else
    echo "proxy mode: validated reciprocal RTP on both PBX SDP legs" | tee -a "$REPORT"
fi
echo "PASS" | tee -a "$REPORT"
