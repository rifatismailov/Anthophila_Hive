#!/bin/sh
# Точка входу контейнера Anthophila_Hive.
#   serve (за замовчуванням) — веб-інтерфейс; HTTPS: HIVE_TLS_CERT / HIVE_TLS_KEY (змонтовані файли) або
#   HIVE_BEHIND_PROXY=1, якщо HTTPS завершує reverse proxy організації.
#   Будь-яка інша команда — hive <команда> (user add, keystore init, backup, verify …).
set -eu

if [ "${1:-serve}" = "serve" ]; then
    if [ -z "${HIVE_TLS_CERT:-}" ] && [ "${HIVE_BEHIND_PROXY:-}" != "1" ] && [ "${HIVE_SELF_SIGNED:-}" = "1" ]; then
        # тимчасовий самопідписаний сертифікат (лише для першого запуску / перевірки)
        mkdir -p /data/tls
        if [ ! -f /data/tls/cert.pem ]; then
            openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj "/CN=${HIVE_HOSTNAME:-anthophila-hive}" \
                -keyout /data/tls/key.pem -out /data/tls/cert.pem >/dev/null 2>&1
            chmod 0600 /data/tls/key.pem
        fi
        export HIVE_TLS_CERT=/data/tls/cert.pem HIVE_TLS_KEY=/data/tls/key.pem
    fi
    exec /usr/local/bin/hive serve
fi
exec /usr/local/bin/hive "$@"
