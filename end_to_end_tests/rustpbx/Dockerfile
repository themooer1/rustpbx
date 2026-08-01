#
# This image deliberately builds the checkout supplied as the Compose build
# context.  It must not use the release image: the purpose of this suite is to
# test the binary which is being changed.
FROM rust:1.97.1-bookworm AS builder

WORKDIR /workspace

RUN apt-get update \
    && apt-get install --yes --no-install-recommends pkg-config libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .
# This repository intentionally ignores Cargo.lock, so a clean checkout has no
# lock file to enforce.  The E2E image exercises the SIP/auth/TLS/RTP core and
# does not need the console or optional addons.  A low-memory dev build keeps
# this usable in Docker Desktop's default 4 GiB VM; cache mounts make repeated
# matrix builds reuse the compiled dependency graph.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/target \
    CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 \
    cargo build --no-default-features --bin rustpbx \
    && mkdir -p /out \
    && cp target/debug/rustpbx /out/rustpbx


FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/rustpbx /app/rustpbx
COPY --from=builder /workspace/static /app/static
COPY --from=builder /workspace/templates /app/templates
COPY --from=builder /workspace/locales /app/locales
COPY --from=builder /workspace/config/sounds /app/sounds
COPY end_to_end_tests/rustpbx/rustpbx.toml.in /etc/rustpbx/rustpbx.toml.in
COPY end_to_end_tests/rustpbx/entrypoint.sh /usr/local/bin/rustpbx-e2e

RUN chmod 0755 /usr/local/bin/rustpbx-e2e \
    && mkdir -p /state /app/config \
    && ln -s /app/sounds /app/config/sounds

ENTRYPOINT ["/usr/local/bin/rustpbx-e2e"]
