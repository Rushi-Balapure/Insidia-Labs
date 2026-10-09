# CLI plus every engine pinned in core/insidia/catalog.py.
# A v* tag builds and signs this image. See .github/workflows/release.yml.
FROM python:3.12-slim-bookworm

ARG UV_VERSION=0.9.24
ARG NODE_VERSION=22.20.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/* \
    && arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
        amd64) node_arch=x64 ;; \
        arm64) node_arch=arm64 ;; \
        *) echo "unsupported architecture $arch" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.gz" \
        | tar -xz -C /usr/local --strip-components=1 \
    && pip install --no-cache-dir "uv==${UV_VERSION}"

COPY core /opt/insidia/core
COPY NOTICE THIRD_PARTY_NOTICES.md /usr/share/doc/insidia/

RUN pip install --no-cache-dir /opt/insidia/core \
    && mkdir -p /opt/insidia/engines \
    && names="$(python -c 'from insidia.catalog import SPECS; print(" ".join(spec.name for spec in SPECS))')" \
    && ok=0 \
    && for attempt in 1 2 3; do \
        if INSIDIA_TOOLCHAIN=/opt/insidia/engines insidia engines install $names; then \
            ok=1; \
            break; \
        fi; \
        echo "engine install attempt ${attempt} failed" >&2; \
        sleep 15; \
    done \
    && test "$ok" = 1

ENV INSIDIA_TOOLCHAIN=/opt/insidia/engines
WORKDIR /work
LABEL org.opencontainers.image.source="https://github.com/Rushi-Balapure/Insidia-Labs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="Insidia"
ENTRYPOINT ["insidia"]
CMD ["doctor"]
