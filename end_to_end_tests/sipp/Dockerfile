# SIPp v3.7.7 is the stable tag for immutable commit
# 369b3c187f0ff96f3ec9795650820e80cf17c776. The release archive is used
# because it carries the non-stub version.h required by SIPp's CMake build.
FROM debian:12-slim AS source

ARG SIPP_COMMIT=369b3c187f0ff96f3ec9795650820e80cf17c776
ARG SIPP_VERSION=3.7.7
ARG SIPP_TARBALL_SHA256=e55b15f567760e9febeef366a1ab51a5239d197a132ce931b78c826d22d31e69

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl tar \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN curl --fail --location --silent --show-error \
      --output sipp.tar.gz "https://github.com/SIPp/sipp/releases/download/v${SIPP_VERSION}/sipp-${SIPP_VERSION}.tar.gz" \
 && echo "${SIPP_TARBALL_SHA256}  sipp.tar.gz" | sha256sum --check --strict \
 && mkdir sipp \
 && tar --extract --gzip --file sipp.tar.gz --strip-components=1 --directory sipp

FROM debian:12-slim AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      cmake g++ gcc libncurses-dev libpcap-dev libssl-dev make ninja-build pkg-config \
 && rm -rf /var/lib/apt/lists/*

COPY --from=source /src/sipp /src/sipp
WORKDIR /build
# In SIPp v3.7.7 TLS key logging is enabled by USE_SSL=KL.  This compiles
# SSL_CTX_set_keylog_callback support when linked against OpenSSL >= 1.1.1.
RUN cmake -G Ninja /src/sipp \
      -DCMAKE_BUILD_TYPE=Release \
      -DUSE_PCAP=1 \
      -DUSE_SSL=KL \
 && ninja

FROM debian:12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates libncursesw6 libpcap0.8 libssl3 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /build/sipp /usr/local/bin/sipp
COPY --from=source /src/sipp/pcap /opt/sipp/pcap
COPY sipp/sipp-client.crt sipp/sipp-client.key /opt/sipp/tls/
COPY sipp/run-phase.sh /opt/e2e/run-phase.sh
COPY scenarios /opt/e2e/scenarios
RUN chmod 0755 /opt/e2e/run-phase.sh \
 && chmod 0600 /opt/sipp/tls/sipp-client.key \
 && mkdir -p /artifacts

# The compose services remain available for each phase; the runner invokes
# /opt/e2e/run-phase.sh with docker compose exec.
CMD ["sleep", "infinity"]
