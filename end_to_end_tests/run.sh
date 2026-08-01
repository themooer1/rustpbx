#!/bin/sh
# Run one SIP listener/media-path combination, preserving the packet trace and
# diagnostics even when a phase fails.  This intentionally needs only Docker
# on the host; packet capture and tshark execute in Linux containers.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
COMPOSE_FILE="$SCRIPT_DIR/compose.yaml"
ARTIFACT_ROOT="$SCRIPT_DIR/artifacts"
COMPOSE_BIN=${DOCKER_COMPOSE_BIN:-docker}
COMPOSE_PLUGIN=${DOCKER_COMPOSE_PLUGIN:-compose}
DOCKER_BIN=${DOCKER_BIN:-docker}
PHASE_TIMEOUT_SECONDS=${E2E_PHASE_TIMEOUT_SECONDS:-45}

usage() {
    echo "usage: $0 {udp|tcp|tls} {direct|proxy}" >&2
    echo "       $0 --matrix" >&2
    exit 64
}

compose() {
    "$COMPOSE_BIN" "$COMPOSE_PLUGIN" -f "$COMPOSE_FILE" "$@"
}

now_epoch() {
    date +%s
}

wait_for_log() {
    service=$1
    marker=$2
    deadline=$(( $(now_epoch) + PHASE_TIMEOUT_SECONDS ))
    while [ "$(now_epoch)" -lt "$deadline" ]; do
        if compose logs --no-color "$service" 2>&1 | grep -F "$marker" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "timed out waiting for $service to log $marker" >&2
    return 1
}

wait_for_file() {
    marker=$1
    deadline=$(( $(now_epoch) + PHASE_TIMEOUT_SECONDS ))
    while [ "$(now_epoch)" -lt "$deadline" ]; do
        [ -f "$CASE_DIR/$marker" ] && return 0
        sleep 1
    done
    echo "timed out waiting for artifact marker $marker" >&2
    return 1
}

run_phase() {
    service=$1
    phase=$2
    deadline=$(( $(now_epoch) + PHASE_TIMEOUT_SECONDS ))
    # The phase helper writes its own SIPp log to /artifacts.  A background
    # exec lets this wrapper apply a portable timeout without GNU timeout.
    compose exec -T "$service" /opt/e2e/run-phase.sh "$phase" &
    phase_pid=$!
    while kill -0 "$phase_pid" 2>/dev/null; do
        if [ "$(now_epoch)" -ge "$deadline" ]; then
            echo "timed out running $service phase $phase" >&2
            kill "$phase_pid" 2>/dev/null || true
            wait "$phase_pid" 2>/dev/null || true
            return 124
        fi
        sleep 1
    done
    wait "$phase_pid"
}

collect_logs() {
    for service in netns rustpbx capture caller callee; do
        compose logs --no-color "$service" >"$CASE_DIR/$service.compose.log" 2>&1 || true
    done
}

stop_capture() {
    # The capture entrypoint converts this to SIGINT for tcpdump, which closes
    # a readable pcap after unregistration rather than truncating it.
    compose stop -t 5 capture >/dev/null 2>&1 || true
}

cleanup() {
    result=$?
    stop_capture
    collect_logs
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    trap - EXIT INT TERM HUP
    exit "$result"
}

run_case() {
    transport=$1
    media=$2
    case "$transport" in udp|tcp|tls) ;; *) usage ;; esac
    case "$media" in direct|proxy) ;; *) usage ;; esac

    case "$media" in
        direct) proxy_mode=none ;;
        proxy) proxy_mode=all ;;
    esac
    case "$transport" in
        tls) sip_port=5061 ;;
        *) sip_port=5060 ;;
    esac

    CASE_NAME="$transport-$media"
    CASE_DIR="$ARTIFACT_ROOT/$CASE_NAME"
    # CASE_NAME is validated above, so this is a narrowly scoped reset of a
    # deterministic test artifact directory.
    rm -rf "$CASE_DIR"
    mkdir -p "$CASE_DIR"

    export E2E_CASE="$CASE_NAME"
    export E2E_TRANSPORT="$transport"
    export E2E_MEDIA_MODE="$media"
    # These are Compose's stable image-facing names.  The E2E_* aliases are
    # retained as useful provenance in logs and for future services.
    export MEDIA_PROXY_MODE="$proxy_mode"
    export SIP_TRANSPORT="$transport"
    export SIP_TARGET_PORT="$sip_port"
    export E2E_MEDIA_PROXY="$proxy_mode"
    export E2E_SIP_PORT="$sip_port"
    export E2E_ARTIFACT_DIR="$CASE_DIR"
    export CAPTURE_FILE=capture.pcap
    export COMPOSE_PROJECT_NAME="rustpbx-e2e-$CASE_NAME"

    trap cleanup EXIT INT TERM HUP

    compose up -d --build netns rustpbx capture caller callee
    wait_for_log capture E2E_CAPTURE_READY

    # TCP/TLS phones keep the registered flow open.  SIPp's lifecycle scenario
    # receives the call as an out-of-call dialog on that same connection and
    # unregisters before exiting. UDP needs no persistent signalling flow.
    if [ "$transport" = udp ]; then
        run_phase callee register
        run_phase caller register
        run_phase callee answer &
        callee_answer_pid=$!
        sleep 1
        run_phase caller call
        wait "$callee_answer_pid"
        run_phase caller unregister
        run_phase callee unregister
    else
        run_phase callee lifecycle &
        callee_lifecycle_pid=$!
        wait_for_file callee-registered.ready
        run_phase caller register
        run_phase caller call
        wait "$callee_lifecycle_pid"
        run_phase caller unregister
    fi
    # Give tcpdump time to drain its packet ring after the final 200 OK.  An
    # immediate container stop can otherwise leave the last TCP/TLS
    # unregister transaction outside the pcap even though SIPp received it.
    sleep "${E2E_CAPTURE_DRAIN_SECONDS:-1}"
    stop_capture
    collect_logs

    # Keep Wireshark off the macOS host.  The analyzer sees the case directory
    # at one stable path, irrespective of where this checkout lives.
    "$DOCKER_BIN" run --rm --network none \
        -e "E2E_SHUTDOWN_BUDGET_SECONDS=${E2E_SHUTDOWN_BUDGET_SECONDS:-4}" \
        -e "E2E_RTP_GRACE_SECONDS=${E2E_RTP_GRACE_SECONDS:-2}" \
        -v "$CASE_DIR:/artifacts" \
        -v "$SCRIPT_DIR:/suite:ro" \
        --entrypoint /bin/sh \
        "${E2E_TSHARK_IMAGE:-cincan/tshark@sha256:9cf3985977320cde1b19e9cbb3130c03c5668ff7b561ec97bfff28c850383104}" \
        /suite/scripts/validate_pcap.sh /artifacts "$transport" "$media"
    trap - EXIT INT TERM HUP
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    echo "PASS: $CASE_NAME ($CASE_DIR)"
}

if [ "${1:-}" = "--matrix" ] && [ "$#" -eq 1 ]; then
    for transport in udp tcp tls; do
        for media in direct proxy; do
            # Each invocation owns its own compose project and cleanup trap.
            "$0" "$transport" "$media"
        done
    done
    exit 0
fi

[ "$#" -eq 2 ] || usage
run_case "$1" "$2"
