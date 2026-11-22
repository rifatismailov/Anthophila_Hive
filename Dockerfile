# Anthophila_Hive — образ для сервера організації: Hive + DocScan yara / yarac (Linux) + git + bubblewrap.
#
#   docker build -t anthophila-hive .
#   docker build --build-arg YARA_DOCSCAN_REF=v1.0.7 -t anthophila-hive .
#
# Розгортання — docs/DEPLOY.md.

# ---------------------------------------------------------------- 1. DocScan yara / yarac (форк YARA 4.6 з модулем docscan)
FROM debian:bookworm-slim AS yara
ARG YARA_DOCSCAN_REPO=https://github.com/rifatismailov/yara-docscan.git
ARG YARA_DOCSCAN_REF=v1.0.7
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git build-essential automake autoconf libtool pkg-config flex bison libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch "${YARA_DOCSCAN_REF}" "${YARA_DOCSCAN_REPO}" yara-docscan
WORKDIR /src/yara-docscan
# статичні yara / yarac: без libyara.so поруч
RUN ./bootstrap.sh && ./configure --disable-shared --enable-static && make -j"$(nproc)" \
    && strip yara yarac \
    && ./yara --help | grep -q -- --critical-rules \
    && install -m 0755 yara yarac /usr/local/bin/

# ---------------------------------------------------------------- 2. Hive (Go, без cgo)
FROM golang:1.26-bookworm AS hive
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/hive ./cmd/hive

# ---------------------------------------------------------------- 3. Образ
FROM debian:bookworm-slim
# git — простори й джерела; bubblewrap — пісочниця для наборів лабораторії (якщо Docker дозволяє простори імен);
# python3 — лише щоб імпортувати налаштування наявного build_vendor_rules.py; tini — коректні сигнали.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git bubblewrap python3 tini openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 hive && useradd --uid 10001 --gid hive --home-dir /data --shell /usr/sbin/nologin hive \
    && mkdir -p /data && chown hive:hive /data && chmod 0700 /data
COPY --from=yara /usr/local/bin/yara /usr/local/bin/yarac /usr/local/bin/
COPY --from=hive /out/hive /usr/local/bin/hive
COPY --chmod=0755 deploy/entrypoint.sh /usr/local/bin/hive-entrypoint
USER hive
ENV HIVE_DATA=/data \
    HIVE_YARA=/usr/local/bin/yara \
    HIVE_YARAC=/usr/local/bin/yarac \
    HIVE_LISTEN=0.0.0.0:8740 \
    GIT_CONFIG_NOSYSTEM=1
VOLUME ["/data"]
EXPOSE 8740
HEALTHCHECK --interval=60s --timeout=10s CMD ["/usr/local/bin/hive", "health"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/hive-entrypoint"]
CMD ["serve"]
