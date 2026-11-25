"""Environment-driven configuration (12-factor; every knob defaults safe)."""

from pathlib import Path
from typing import Literal, Optional

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Path fragments that identify cloud-synced folders. The data dir holds
# mail-at-rest (alias DB, audit chain, cache mirror) — it must never ride
# a sync client onto other machines or a vendor cloud.
_SYNCED_MARKERS = ("onedrive", "dropbox", "google drive", "googledrive", "icloud")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    # --- Who the server acts for ---------------------------------------------
    # static: one mailbox, the configured EWS_EMAIL / EWS_USERNAME /
    #   EWS_PASSWORD (single user; stdio or HTTP).
    # bearer: many mailboxes. Every HTTP request carries the caller's own EWS
    #   OAuth2 access token (Authorization: Bearer); the mailbox comes from
    #   its claims (EWS_TOKEN_MAILBOX_CLAIMS) and Exchange checks the token.
    #   No token -> HTTP 401. The server holds no Exchange credentials.
    ews_auth_mode: Literal["static", "bearer"] = "static"
    ews_token_mailbox_claims: str = "email,upn,preferred_username,unique_name"

    # --- Exchange upstream -------------------------------------------------
    ews_server_url: str
    ews_email: Optional[str] = None  # required in static mode
    ews_username: Optional[str] = None
    ews_password: Optional[str] = None
    # Auto-negotiation is the default because it adapts to what the server
    # offers; forcing a scheme skips the unauthenticated probe request and is
    # appropriate when the scheme is known.
    ews_auth_type_force: Optional[Literal["basic", "ntlm", "digest"]] = None
    ews_insecure_skip_verify: bool = False
    ews_tz: str = "UTC"
    request_timeout: int = 30

    # --- Reliability --------------------------------------------------------
    ews_warmup_max_backoff_seconds: int = 300
    ews_heartbeat_seconds: int = 600
    ews_retry_max_wait_seconds: int = 300
    ews_auth_failure_cooldown_seconds: int = Field(default=900, ge=60)
    ews_auth_max_rejections: int = Field(default=3, ge=1, le=10)
    # Worker threads for Exchange calls: the process-wide cap on requests in
    # flight across every mailbox (default 4 in static mode, 32 in bearer).
    ews_max_concurrency: Optional[int] = Field(default=None, ge=1, le=512)
    # Requests ONE mailbox may have in flight (its share of the pool and its
    # exchangelib connection count). Exchange's own per-user EWS limit is far
    # higher; staying at 2-3 keeps a single busy assistant a polite guest.
    ews_mailbox_max_concurrency: int = Field(default=2, ge=1, le=8)
    # A mailbox's session (connections, mirror) is closed after this long
    # without calls; past EWS_MAX_MAILBOXES the least recently used idle
    # sessions go first.
    ews_mailbox_idle_seconds: int = Field(default=1800, ge=60)
    ews_max_mailboxes: int = Field(default=2000, ge=1)
    circuit_failure_threshold: int = 5
    circuit_open_seconds: int = 60

    # --- Safety -------------------------------------------------------------
    ews_capability_tier: Literal["read", "draft", "full"] = "draft"
    send_enabled: bool = False  # kill-switch: v5 defaults SAFE (off)
    send_confirm_secret: Optional[str] = None
    confirm_ttl_seconds: int = 600  # ONE default everywhere (== confirm.DEFAULT_TTL_SECONDS)
    ews_recipient_allowlist: str = ""
    ews_recipient_denylist: str = ""
    ews_max_sends_per_hour: int = 10
    ews_attachment_dir: str = ""
    ews_max_attachment_mb: int = Field(default=25, ge=1, le=50)
    ews_keep_dumpable: bool = False

    # --- Serving ------------------------------------------------------------
    mcp_transport: Literal["stdio", "http"] = "stdio"
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8000
    mcp_api_key: Optional[str] = None
    log_level: str = "INFO"

    # --- Storage (NEVER a synced folder) -------------------------------------
    data_dir: str = ""  # empty → ~/.ewsmcp; always resolved to an absolute path
    data_dir_allow_synced: bool = False  # explicit opt-out of the synced-path guard

    # --- Cache mirror (cache-first reads; false = pure EWS, fully functional)
    # Default: on in static mode, off in bearer mode (live reads; Exchange's
    # own search index already covers every mailbox).
    ews_cache_enabled: Optional[bool] = None
    ews_cache_folders: str = "inbox,sent"
    ews_cache_sync_seconds: int = 45
    ews_cache_hierarchy_seconds: int = 600
    ews_cache_window_days: int = 365
    ews_cache_purge_on_boot: bool = False  # admin path: wipe + resync from scratch

    # --- Optional semantic tier (adapter; core stays dependency-free) --------
    ews_semantic_index: Literal["none", "pgvector"] = "none"
    ews_semantic_pg_dsn: Optional[str] = None  # from env only, never committed
    ews_semantic_ollama_url: str = "http://localhost:11434"
    ews_semantic_model: str = "bge-m3"  # 1024-d, Arabic-capable

    # --- Response economy ----------------------------------------------------
    default_page_size: int = Field(default=20, le=50)
    body_max_chars: int = 4000

    @field_validator("ews_auth_type_force", mode="before")
    @classmethod
    def _blank_auth_type_is_unset(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip().lower()
            return stripped or None
        return value

    @property
    def bearer_mode(self) -> bool:
        return self.ews_auth_mode == "bearer"

    @model_validator(mode="after")
    def _resolve_mode(self) -> "Settings":
        """Fill mode-dependent defaults and refuse combinations that would
        mix mailboxes or cannot work."""
        bearer = self.ews_auth_mode == "bearer"
        if self.ews_max_concurrency is None:
            self.ews_max_concurrency = 32 if bearer else 4
        if self.ews_cache_enabled is None:
            self.ews_cache_enabled = not bearer
        if not bearer:
            if not (self.ews_email or "").strip():
                raise ValueError("EWS_EMAIL is required when EWS_AUTH_MODE=static.")
            return self
        if self.mcp_transport != "http":
            raise ValueError(
                "EWS_AUTH_MODE=bearer serves many users over HTTP; set MCP_TRANSPORT=http."
            )
        if self.ews_semantic_index != "none":
            raise ValueError(
                "EWS_SEMANTIC_INDEX is single-mailbox (its index has no mailbox "
                "column) and would mix users' mail in bearer mode; set it to none."
            )
        if self.ews_cache_enabled:
            raise ValueError(
                "The background mirror polls one mailbox; it is not available in "
                "bearer mode. Set EWS_CACHE_ENABLED=false."
            )
        return self

    @model_validator(mode="after")
    def _resolve_data_dir(self) -> "Settings":
        raw = self.data_dir or str(Path.home() / ".ewsmcp")
        resolved = Path(raw).expanduser().resolve()
        if not self.data_dir_allow_synced:
            lowered = str(resolved).lower()
            marker = next((m for m in _SYNCED_MARKERS if m in lowered), None)
            if marker is not None:
                raise ValueError(
                    f"DATA_DIR {resolved} appears to be inside a cloud-synced "
                    f"folder ({marker!r}). It stores mail-at-rest (aliases, "
                    "audit chain, cache) and must stay local — point DATA_DIR "
                    "at a local path, or set DATA_DIR_ALLOW_SYNCED=true to "
                    "accept the risk deliberately."
                )
        self.data_dir = str(resolved)
        return self


def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
