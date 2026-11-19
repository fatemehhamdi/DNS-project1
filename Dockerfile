# Dedicated, resource-limited container for patchval.
# Use scripts/run_in_docker.sh, which starts it with no network, memory/CPU/pid
# limits, a read-only root filesystem and a non-root user.
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gcc clang make patch python3 python3-yaml python3-pytest binutils bubblewrap \
      ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/patchval
COPY . /opt/patchval
RUN useradd -m runner && chown -R runner:runner /opt/patchval
USER runner
ENV PATCHVAL_CONTAINER=1 PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python3", "-m", "patchval"]
CMD ["--help"]
