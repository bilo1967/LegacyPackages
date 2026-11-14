#!/usr/bin/env bash
set -euo pipefail
# Run on gojira. Compiles the *unchanged* Focal source in a throwaway container.
# Does not install packages or restart services on the host.
SRC_DIR="${1:-/usr/local/src/apache2-backport}"
OUT_DIR="${2:-/usr/local/src/apache2-build-output}"
test -f "$SRC_DIR/apache2_2.4.41-4ubuntu3.23.dsc"
test -d "$SRC_DIR/apache2-2.4.41/debian"
mkdir -p "$OUT_DIR"
docker run --rm --name apache2-focal-baseline-build \
  --cpus=2 --memory=4g --pids-limit=256 \
  -e DEBIAN_FRONTEND=noninteractive \
  -v "$SRC_DIR:/input:ro" \
  -v "$OUT_DIR:/output:rw" \
  ubuntu:20.04 bash -euc '
    sed -n "s/^deb /deb-src /p" /etc/apt/sources.list >> /etc/apt/sources.list
    apt-get update
    apt-get install -y --no-install-recommends build-essential fakeroot dpkg-dev ca-certificates
    apt-get build-dep -y apache2
    mkdir -p /work
    cp -a /input/apache2-2.4.41 /work/
    cd /work/apache2-2.4.41
    dpkg-buildpackage -b -us -uc -j2
    cp -v /work/*.deb /output/
  '
echo "Compiled .deb files: $OUT_DIR"
