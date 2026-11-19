#!/usr/bin/env bash
# Run patchval inside a dedicated container that is the isolation boundary:
#   --network none, --memory/--cpus/--pids-limit, read-only root fs,
#   writable tmpfs only for /tmp, writable host volumes for reports and the
#   regression registry, no new privileges.
# The container runs with YOUR uid:gid so it can write the mounted volumes.
# Usage: scripts/run_in_docker.sh -c targets/csvsum/config.correct.yaml [patchval args...]
# Reports land in ./docker_out, the persistent regression registry in ./docker_registry.
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
docker build -q -t patchval "$HERE" >/dev/null
mkdir -p "$HERE/docker_out" "$HERE/docker_registry"
exec docker run --rm \
  --user "$(id -u):$(id -g)" \
  --network none --memory 2g --memory-swap 2g --cpus 2 --pids-limit 512 \
  --read-only --tmpfs /tmp:rw,exec,size=1g --security-opt no-new-privileges \
  -e HOME=/tmp -e PATCHVAL_REGISTRY_DIR=/registry \
  -v "$HERE/docker_out:/out" -v "$HERE/docker_registry:/registry" \
  patchval --work /tmp/pv --artifacts /out/artifacts --json /out/report.json "$@"
