#!/bin/sh
# Throwaway, passwordless Pi-hole v6 containers for integration tests.
#   scripts/test-piholes.sh up    -> web on 127.0.0.1:18081/18082, DNS on 127.0.0.1:15301/15302
#   scripts/test-piholes.sh down  -> removes both containers and their network
set -eu
DOCKER="docker --context ${DOCKER_CONTEXT:-lighter}"
NET=twinhole-test

case "${1:-}" in
  up)
    $DOCKER network inspect $NET >/dev/null 2>&1 || $DOCKER network create $NET >/dev/null
    for i in 1 2; do
      $DOCKER rm -f twinhole-test-ph$i >/dev/null 2>&1 || true
      $DOCKER run -d --name twinhole-test-ph$i --network $NET \
        -p 127.0.0.1:1808$i:80 -p 127.0.0.1:1530$i:53/udp -p 127.0.0.1:1530$i:53/tcp \
        -e TZ=Europe/London \
        -e FTLCONF_webserver_api_password= \
        -e FTLCONF_dns_listeningMode=all \
        pihole/pihole:latest >/dev/null
    done
    for i in 1 2; do
      n=0
      until curl -fs "http://127.0.0.1:1808$i/api/info/login" >/dev/null 2>&1; do
        n=$((n+1)); [ $n -gt 90 ] && { echo "ph$i did not come up" >&2; exit 1; }
        sleep 2
      done
      echo "ph$i up on http://127.0.0.1:1808$i (DNS 127.0.0.1:1530$i)"
    done
    ;;
  down)
    $DOCKER rm -f twinhole-test-ph1 twinhole-test-ph2 >/dev/null 2>&1 || true
    $DOCKER network rm $NET >/dev/null 2>&1 || true
    echo "test Pi-holes removed"
    ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
