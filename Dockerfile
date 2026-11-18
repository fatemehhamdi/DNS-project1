FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gcc make procps python3 python3-yaml python3-pytest \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/patchval
COPY patchval/ ./patchval/
COPY tests/ ./tests/
COPY Makefile ./
RUN useradd -m runner && chown -R runner:runner /opt/patchval
USER runner
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["make", "unit"]
