#!/bin/sh
# Build Linux gyges/gygesd in Docker, then run check.sh in a container whose
# PID 1 is systemd. Needs Docker with privileged containers and cgroup v2
# (Docker Desktop, or a Linux host). The cargo registry and target directory
# live in named volumes, so only the first build is slow.
#
#   tests/hardened/run.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"; docker rm -f gyges-hardened >/dev/null 2>&1 || true' EXIT

arch=$(uname -m)
case "$arch" in arm64|aarch64) protoc_arch=aarch_64 ;; *) protoc_arch=x86_64 ;; esac
toolchain=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$root/rust-toolchain.toml")

docker build -q -t gyges-hardened-build --build-arg PROTOC_ARCH=$protoc_arch - <<EOF >/dev/null
FROM rust:$toolchain-trixie
ARG PROTOC_ARCH
RUN apt-get update -qq && apt-get install -y -qq clang libclang-dev unzip >/dev/null \
 && curl -sSL -o /tmp/p.zip https://github.com/protocolbuffers/protobuf/releases/download/v29.3/protoc-29.3-linux-\$PROTOC_ARCH.zip \
 && unzip -q /tmp/p.zip -d /usr/local && rm /tmp/p.zip
EOF

docker run --rm \
  -v "$root":/src:ro \
  -v gyges-hardened-registry:/usr/local/cargo/registry \
  -v gyges-hardened-target:/target \
  -v "$out":/out \
  -e CARGO_TARGET_DIR=/target \
  -w /src gyges-hardened-build \
  sh -c 'cargo build --locked -p gygesd -p gyges-cli && cp /target/debug/gyges /target/debug/gygesd /out/'

cp "$here/Dockerfile" "$here/check.sh" "$out/"
docker build -q -t gyges-hardened "$out" >/dev/null
docker run -d --name gyges-hardened --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  gyges-hardened >/dev/null
# Wait for systemd to finish booting.
for _ in $(seq 1 60); do
  state=$(docker exec gyges-hardened systemctl is-system-running 2>/dev/null || true)
  case "$state" in running|degraded) break ;; esac
  sleep 1
done
docker exec gyges-hardened sh /usr/local/bin/check-hardened
