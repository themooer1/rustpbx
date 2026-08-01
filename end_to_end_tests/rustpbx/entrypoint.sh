#!/bin/sh
set -eu

# Keep the test matrix in Compose rather than carrying four nearly identical
# PBX configurations.  Restrict this to the enum's known values so the shell
# substitution cannot produce arbitrary TOML.
media_proxy_mode="${MEDIA_PROXY_MODE:-all}"
case "${media_proxy_mode}" in
  all|auto|nat|none|bypass) ;;
  *)
    echo "MEDIA_PROXY_MODE must be all, auto, nat, none, or bypass (got ${media_proxy_mode})" >&2
    exit 64
    ;;
esac

mkdir -p /state
sed "s/__MEDIA_PROXY_MODE__/${media_proxy_mode}/g" \
  /etc/rustpbx/rustpbx.toml.in > /state/rustpbx.toml

exec /app/rustpbx --conf /state/rustpbx.toml
