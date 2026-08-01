#!/usr/bin/env bash
# Execute one deterministic SIPp lifecycle phase.  This is deliberately a
# separate process for REGISTER, dialog, and unregister: the SIP contact is
# stable while the test remains able to prove the terminal unregister.
set -euo pipefail

phase=${1:?usage: run-phase.sh register\|lifecycle\|answer\|call\|unregister}

: "${SIPP_ROLE:=caller}"
: "${SIPP_TRANSPORT:=udp}"
: "${SIPP_REMOTE_HOST:=rustpbx}"
: "${SIPP_REMOTE_PORT:=5060}"
: "${SIPP_USER:?SIPP_USER is required}"
: "${SIPP_PASSWORD:?SIPP_PASSWORD is required}"
: "${SIPP_TARGET:?SIPP_TARGET is required}"
: "${SIPP_ARTIFACT_DIR:=/artifacts}"
: "${SIPP_LOG_PREFIX:=${SIPP_ROLE}}"
: "${SIPP_TIMEOUT:=30s}"

case "${SIPP_ROLE}" in
  caller)
    : "${SIPP_LOCAL_PORT:=5062}"
    : "${SIPP_RTP_MIN_PORT:=40000}"
    : "${SIPP_RTP_MAX_PORT:=40098}"
    ;;
  callee)
    : "${SIPP_LOCAL_PORT:=5064}"
    : "${SIPP_RTP_MIN_PORT:=40100}"
    : "${SIPP_RTP_MAX_PORT:=40198}"
    ;;
  *)
    echo "SIPP_ROLE must be caller or callee, got '${SIPP_ROLE}'" >&2
    exit 64
    ;;
esac

: "${SIPP_LOCAL_IP:=$(hostname -i | awk '{print $1}')}"
: "${SIPP_MEDIA_IP:=${SIPP_LOCAL_IP}}"

case "${SIPP_TRANSPORT}" in
  udp) transport_mode=u1 ;;
  tcp) transport_mode=t1 ;;
  tls) transport_mode=l1 ;;
  *)
    echo "SIPP_TRANSPORT must be udp, tcp, or tls, got '${SIPP_TRANSPORT}'" >&2
    exit 64
    ;;
esac

case "${phase}" in
  register) scenario=/opt/e2e/scenarios/register.xml ;;
  lifecycle) scenario=/opt/e2e/scenarios/register-lifecycle.xml ;;
  unregister) scenario=/opt/e2e/scenarios/unregister.xml ;;
  answer) scenario=/opt/e2e/scenarios/callee-answer.xml ;;
  call) scenario=/opt/e2e/scenarios/caller-call.xml ;;
  *)
    echo "unknown phase '${phase}'; expected register, answer, call, or unregister" >&2
    exit 64
    ;;
esac

max_calls=1
phase_args=()
if [[ "${phase}" == lifecycle ]]; then
  [[ "${SIPP_ROLE}" == callee ]] || {
    echo "lifecycle phase is only valid for the callee" >&2
    exit 64
  }
  phase_args+=( -oocsf /opt/e2e/scenarios/callee-answer.xml )
fi

mkdir -p "${SIPP_ARTIFACT_DIR}"
cd "${SIPP_ARTIFACT_DIR}"

# SIPp's callback appends all TLS handshakes from this endpoint to one file,
# including the registration and terminal unregister connections.
export SSLKEYLOGFILE="${SIPP_ARTIFACT_DIR}/${SIPP_LOG_PREFIX}.keylog"
touch "${SSLKEYLOGFILE}"

event_file="${SIPP_ARTIFACT_DIR}/${SIPP_LOG_PREFIX}-events.log"
printf '%s phase=%s event=start transport=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${SIPP_TRANSPORT}" | tee -a "${event_file}"

common=(
  "${SIPP_REMOTE_HOST}:${SIPP_REMOTE_PORT}"
  -sf "${scenario}"
  -t "${transport_mode}"
  -i "${SIPP_LOCAL_IP}" -p "${SIPP_LOCAL_PORT}"
  -mi "${SIPP_MEDIA_IP}"
  -min_rtp_port "${SIPP_RTP_MIN_PORT}" -max_rtp_port "${SIPP_RTP_MAX_PORT}"
  -s "${SIPP_TARGET}"
  -au "${SIPP_USER}" -ap "${SIPP_PASSWORD}"
  -auth_uri "${SIPP_REMOTE_HOST}:${SIPP_REMOTE_PORT}"
  -key e2e_user "${SIPP_USER}" -key e2e_target "${SIPP_TARGET}"
  -m "${max_calls}" -nostdin -timeout "${SIPP_TIMEOUT}"
  -default_behaviors all,-bye
  -trace_err -trace_logs -trace_msg
)
common+=( "${phase_args[@]}" )

if [[ "${SIPP_TRANSPORT}" == tls ]]; then
  common+=( -tls_cert /opt/sipp/tls/sipp-client.crt -tls_key /opt/sipp/tls/sipp-client.key )
fi

if /usr/local/bin/sipp "${common[@]}"; then
  printf '%s phase=%s event=complete transport=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${SIPP_TRANSPORT}" | tee -a "${event_file}"
else
  status=$?
  printf '%s phase=%s event=failed exit=%s transport=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${status}" "${SIPP_TRANSPORT}" | tee -a "${event_file}" >&2
  exit "${status}"
fi
