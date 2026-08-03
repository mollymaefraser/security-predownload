# Builds mollymaefraser/vulnscan (another security passion project of mine) 
# from source and packages just the compiled binary into a minimal, non-root
# runtime image used by internal/sandbox.

FROM rust:1-slim-bookworm AS builder

# CVEs (2 critical, 2 high) reported against this stage are build-time only: 
# the OS packages and toolchain here never ship in the final image below 
# (multi-stage build copies out just the compiled binary).
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Builds whatever the latest tagged GitHub Release is at the time the image
# is built (resolved fresh each build; rerun with --no-cache to pick up a
# release that shipped after the last build).
RUN VULNSCAN_TAG=$(curl -fsSL https://api.github.com/repos/mollymaefraser/vulnscan/releases/latest \
        | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/') \
    && git clone --branch "${VULNSCAN_TAG}" --depth 1 \
        https://github.com/mollymaefraser/vulnscan.git /src

WORKDIR /src
RUN cargo build --release

FROM debian:bookworm-slim

# This stage also had CVEs (2 critical, 2 high) before the upgrade below.
# Unlike the builder stage, this one does ship: vulnscan is dynamically
# linked against libssl3/libcrypto3 (confirmed via ldd — native-tls links
# system OpenSSL for the OSV.dev HTTPS calls), so these packages are live
# code paths, not dead weight. Patched via apt-get upgrade; blast radius if
# an unpatched CVE surfaces is bounded by the sandbox hardening in
# internal/sandbox (non-root, read-only rootfs, dropped caps, network only
# enabled for the SCA pass that actually needs it).
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 65532 --no-create-home --shell /usr/sbin/nologin scanner

COPY --from=builder /src/target/release/vulnscan /usr/local/bin/vulnscan

# Matches sandboxUser in internal/sandbox, which always runs containers as
# this uid:gid regardless of what image is passed in.
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/vulnscan"]
