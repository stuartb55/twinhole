"""Settings, read from environment variables (see .env.example)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class PiholeConfig:
    id: str  # stable key used in the database; the host part of the URL
    role: str  # "main" or "secondary"
    name: str
    url: str  # e.g. http://192.168.1.118
    dns_host: str  # IPv4 address (or name) the DNS check queries
    dns_port: int
    ipv6: str  # "auto", "off" or a literal IPv6 address


@dataclass(frozen=True)
class Settings:
    main: PiholeConfig
    secondary: PiholeConfig
    ntfy_url: str = ""
    ntfy_topic: str = ""
    ntfy_token: str = ""
    allow_writes: bool = False
    check_interval: int = 30
    history_interval: int = 600
    drift_interval: int = 900
    dns_probe_domain: str = "example.com"
    dns_timeout: float = 1.0
    recursion_interval: int = 300
    recursion_timeout: float = 3.0
    dnssec_interval: int = 3600
    dnssec_probe_domain: str = "dnssec-failed.org"
    fail_threshold: int = 2
    blocking_grace: int = 10 * 60
    gravity_max_age: int = 8 * 86400
    drift_grace: int = 60 * 60
    auto_sync: bool = False
    auto_sync_max_deletes: int = 5
    check_releases: bool = True
    retention_days: int = 730
    backfill_days: int = 92
    query_log_size: int = 500
    tz: str = "Europe/London"
    db_path: str = "/data/twinhole.db"

    @property
    def piholes(self) -> tuple[PiholeConfig, PiholeConfig]:
        return (self.main, self.secondary)


class ConfigError(ValueError):
    pass


def _pihole(env: Mapping[str, str], role: str) -> PiholeConfig:
    prefix = f"PIHOLE_{role.upper()}_"
    url = env.get(prefix + "URL", "").strip().rstrip("/")
    if not url:
        raise ConfigError(f"{prefix}URL is required")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError(f"{prefix}URL must look like http://192.168.1.118, got {url!r}")
    host = parsed.hostname

    dns = env.get(prefix + "DNS", "").strip() or host
    dns_host, _, dns_port = dns.partition(":")
    return PiholeConfig(
        id=env.get(prefix + "ID", "").strip() or host,
        role=role,
        name=env.get(prefix + "NAME", "").strip() or host,
        url=url,
        dns_host=dns_host,
        dns_port=int(dns_port or 53),
        ipv6=env.get(prefix + "IPV6", "auto").strip() or "auto",
    )


def _int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = env.get(key, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError as e:
        raise ConfigError(f"{key} must be a whole number, got {raw!r}") from e


def _bool(env: Mapping[str, str], key: str) -> bool:
    return env.get(key, "").strip().lower() in ("1", "true", "yes")


def load(env: Mapping[str, str] = os.environ) -> Settings:
    main = _pihole(env, "main")
    secondary = _pihole(env, "secondary")
    if main.id == secondary.id:
        raise ConfigError("main and secondary Pi-hole must be different hosts")
    return Settings(
        main=main,
        secondary=secondary,
        ntfy_url=env.get("NTFY_URL", "").strip().rstrip("/"),
        ntfy_topic=env.get("NTFY_TOPIC", "").strip(),
        ntfy_token=env.get("NTFY_TOKEN", "").strip(),
        allow_writes=_bool(env, "ALLOW_WRITES"),
        check_interval=_int(env, "CHECK_INTERVAL", 30),
        history_interval=_int(env, "HISTORY_INTERVAL", 600),
        drift_interval=_int(env, "DRIFT_INTERVAL", 900),
        dns_probe_domain=env.get("DNS_PROBE_DOMAIN", "").strip() or "example.com",
        dns_timeout=_int(env, "DNS_TIMEOUT_MS", 1000) / 1000,
        recursion_interval=_int(env, "RECURSION_INTERVAL", 300),
        recursion_timeout=_int(env, "RECURSION_TIMEOUT_MS", 3000) / 1000,
        dnssec_interval=_int(env, "DNSSEC_INTERVAL", 3600),
        dnssec_probe_domain=env.get("DNSSEC_PROBE_DOMAIN", "").strip() or "dnssec-failed.org",
        fail_threshold=_int(env, "FAIL_THRESHOLD", 2),
        blocking_grace=_int(env, "BLOCKING_GRACE_MIN", 10) * 60,
        gravity_max_age=_int(env, "GRAVITY_MAX_DAYS", 8) * 86400,
        drift_grace=_int(env, "DRIFT_GRACE_MIN", 60) * 60,
        auto_sync=_bool(env, "AUTO_SYNC"),
        auto_sync_max_deletes=_int(env, "AUTO_SYNC_MAX_DELETES", 5),
        check_releases=env.get("CHECK_RELEASES", "").strip().lower() not in ("0", "false", "no"),
        retention_days=_int(env, "RETENTION_DAYS", 730),
        backfill_days=_int(env, "BACKFILL_DAYS", 92),
        query_log_size=_int(env, "QUERY_LOG_SIZE", 500),
        tz=env.get("TZ", "").strip() or "Europe/London",
        db_path=env.get("DB_PATH", "").strip() or "/data/twinhole.db",
    )
