"""Configuration management using Pydantic Settings."""

from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogLevel(str, Enum):
    """Log level options."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class HttpClientType(str, Enum):
    """HTTP client types."""
    CURL_IMPERSONATE = "curl-impersonate"
    HTTPX = "httpx"


class LLMProvider(str, Enum):
    """LLM provider options."""
    OLLAMA = "ollama"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    GROQ = "groq"
    CLAUDE_CODE = "claude_code"  # Claude Code CLI headless mode


class ScopeConfig(BaseModel):
    """Scope validation configuration."""
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_patterns: list[str] = Field(default_factory=list)
    blocked_patterns: list[str] = Field(default_factory=list)
    allowed_asns: list[int] = Field(default_factory=list)
    allowed_ip_ranges: list[str] = Field(default_factory=list)


class ProxyConfig(BaseModel):
    """Proxy pool configuration."""
    enabled: bool = False
    sources: list[str] = Field(default_factory=list)
    max_failures: int = 3
    prefer_residential: bool = True


class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""
    initial_rate: float = 30.0
    min_rate: float = 1.0
    backoff_factor: float = 0.5
    recovery_factor: float = 1.1


class PurednsConfig(BaseModel):
    """Puredns configuration."""
    resolver_file: str = "wordlists/resolvers.txt"
    wildcard_tests: int = 50
    rate_limit: int = 500
    trusted_resolvers: list[str] = Field(
        default_factory=lambda: ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    )


class NucleiConfig(BaseModel):
    """Nuclei scanning configuration."""
    exclude_tags: list[str] = Field(
        default_factory=lambda: [
            "fuzz", "dos", "fuzzing", "intrusive", "sqli",
            "xss", "rce", "bruteforce", "oob", "oast", "interactsh"
        ]
    )
    severity: list[str] = Field(
        default_factory=lambda: ["critical", "high", "medium"]
    )
    disable_interactsh: bool = True
    # Optimized performance settings based on ProjectDiscovery recommendations
    # See: https://docs.projectdiscovery.io/tools/nuclei/mass-scanning-cli
    # Tuned for 8-16GB RAM systems
    rate_limit: int = 500       # Fast but safe (default 150, max recommended ~500)
    bulk_size: int = 50         # Hosts per template (default 25)
    concurrency: int = 50       # Templates in parallel (default 25)
    payload_concurrency: int = 25  # Payloads per template (default 25)
    timeout: int = 5            # Request timeout in seconds (default 10)
    retries: int = 1            # Number of retries (default 1)
    max_host_error: int = 10    # Skip host after N errors (default 30)
    response_size_read: int = 2097152  # 2MB max response (default 4MB)
    scan_strategy: str = "host-spray"  # More memory efficient


class HttpConfig(BaseModel):
    """HTTP client configuration."""
    primary_client: HttpClientType = HttpClientType.CURL_IMPERSONATE
    fallback_client: HttpClientType = HttpClientType.HTTPX
    timeout: int = 10
    retries: int = 2
    browser_profiles: list[str] = Field(
        default_factory=lambda: ["chrome120", "firefox121", "safari17_0"]
    )
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )


class LLMConfig(BaseModel):
    """LLM configuration."""
    primary_provider: LLMProvider = LLMProvider.OLLAMA
    primary_model: str = "llama3.2"
    fallback_provider: LLMProvider = LLMProvider.OPENAI
    fallback_model: str = "gpt-4o-mini"
    api_base: Optional[str] = None
    # Use SecretStr to prevent accidental logging of API keys
    api_key: Optional[SecretStr] = Field(default=None, repr=False)

    def get_api_key(self) -> Optional[str]:
        """Get the API key value securely."""
        return self.api_key.get_secret_value() if self.api_key else None


class APIKeysConfig(BaseModel):
    """API keys configuration for external services.

    Keys are loaded from (in order of priority):
    1. Environment variables (SHODAN_API_KEY, etc.)
    2. Config file (~/.reconductor/config.yaml)
    """
    # Use SecretStr to prevent accidental logging
    shodan: Optional[SecretStr] = Field(default=None, repr=False)
    securitytrails: Optional[SecretStr] = Field(default=None, repr=False)
    censys_id: Optional[SecretStr] = Field(default=None, repr=False)
    censys_secret: Optional[SecretStr] = Field(default=None, repr=False)

    def get_shodan(self) -> Optional[str]:
        """Get Shodan API key."""
        return self.shodan.get_secret_value() if self.shodan else None

    def get_securitytrails(self) -> Optional[str]:
        """Get SecurityTrails API key."""
        return self.securitytrails.get_secret_value() if self.securitytrails else None

    def get_censys(self) -> tuple[Optional[str], Optional[str]]:
        """Get Censys API credentials (id, secret)."""
        api_id = self.censys_id.get_secret_value() if self.censys_id else None
        api_secret = self.censys_secret.get_secret_value() if self.censys_secret else None
        return api_id, api_secret


class Settings(BaseSettings):
    """Main application settings."""

    model_config = SettingsConfigDict(
        env_prefix="RECONDUCTOR_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General settings
    app_name: str = "ReconDuctor"
    debug: bool = False
    log_level: LogLevel = LogLevel.INFO
    log_json: bool = False

    # Paths
    base_dir: Path = Field(default_factory=lambda: Path.cwd())
    data_dir: Path = Field(default_factory=lambda: Path.cwd() / "data")
    wordlists_dir: Path = Field(default_factory=lambda: Path.cwd() / "wordlists")
    output_dir: Path = Field(default_factory=lambda: Path.cwd() / "output")
    database_path: Path = Field(default_factory=lambda: Path.cwd() / "data" / "reconductor.db")

    # Scope settings
    scope: ScopeConfig = Field(default_factory=ScopeConfig)

    # Proxy settings
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)

    # Rate limiting
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)

    # Puredns settings
    puredns: PurednsConfig = Field(default_factory=PurednsConfig)

    # Nuclei settings
    nuclei: NucleiConfig = Field(default_factory=NucleiConfig)

    # HTTP client settings
    http: HttpConfig = Field(default_factory=HttpConfig)

    # LLM settings
    llm: LLMConfig = Field(default_factory=LLMConfig)

    # Worker settings
    max_workers: int = 20
    min_workers: int = 3
    workers_per_cpu: int = 2

    # IPv6 settings
    ipv6_prefix: int = 64

    @field_validator("ipv6_prefix")
    @classmethod
    def validate_ipv6_prefix(cls, v: int) -> int:
        """Validate IPv6 prefix length."""
        if v not in [48, 56, 64]:
            raise ValueError(f"IPv6 prefix must be 48, 56, or 64, got {v}")
        return v

    def ensure_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        for dir_path in [self.data_dir, self.wordlists_dir, self.output_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_yaml(cls, path: Path) -> "Settings":
        """Load settings from YAML file."""
        import yaml

        if not path.exists():
            return cls()

        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}

        return cls(**data)

    def to_yaml(self, path: Path) -> None:
        """Save settings to YAML file."""
        import yaml

        data = self.model_dump(mode="json")

        # Convert Path objects to strings
        for key, value in data.items():
            if isinstance(value, Path):
                data[key] = str(value)

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


def load_settings(config_path: Optional[Path] = None) -> Settings:
    """Load settings from config file or environment."""
    if config_path and config_path.exists():
        return Settings.from_yaml(config_path)
    return Settings()


# API Key Management
# Default config directory and file
CONFIG_DIR = Path.home() / ".reconductor"
CONFIG_FILE = CONFIG_DIR / "config.yaml"


def get_api_keys() -> APIKeysConfig:
    """
    Load API keys from environment variables, config file, and native tool configs.

    Priority (highest to lowest):
    1. Environment variables (SHODAN_API_KEY, SECURITYTRAILS_API_KEY, etc.)
    2. Config file (~/.reconductor/config.yaml)
    3. Native tool configs (e.g., ~/.config/shodan/api_key from `shodan init`)
    """
    import yaml

    keys_data: dict[str, Any] = {}

    # Check native tool config locations first (lowest priority)
    # Shodan CLI stores key in ~/.config/shodan/api_key or ~/.shodan/api_key
    native_shodan_paths = [
        Path.home() / ".config" / "shodan" / "api_key",
        Path.home() / ".shodan" / "api_key",
    ]
    for path in native_shodan_paths:
        if path.exists():
            try:
                keys_data["shodan"] = path.read_text().strip()
                break
            except Exception:
                pass

    # Load from reconductor config file (medium priority)
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                config = yaml.safe_load(f) or {}
                api_keys = config.get("api_keys", {})
                if api_keys:
                    keys_data.update(api_keys)
        except Exception:
            pass  # Ignore config file errors

    # Override with environment variables (highest priority)
    env_mappings = {
        "SHODAN_API_KEY": "shodan",
        "SECURITYTRAILS_API_KEY": "securitytrails",
        "CENSYS_API_ID": "censys_id",
        "CENSYS_API_SECRET": "censys_secret",
    }

    for env_var, key_name in env_mappings.items():
        value = os.environ.get(env_var)
        if value:
            keys_data[key_name] = value

    return APIKeysConfig(**keys_data)


def save_api_key(key_name: str, key_value: str) -> None:
    """
    Save an API key to the config file.

    Args:
        key_name: Key name (shodan, securitytrails, censys_id, censys_secret)
        key_value: The API key value
    """
    import yaml

    # Validate key name
    valid_keys = {"shodan", "securitytrails", "censys_id", "censys_secret"}
    if key_name not in valid_keys:
        raise ValueError(f"Invalid key name. Must be one of: {', '.join(valid_keys)}")

    # Ensure config directory exists
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    # Load existing config
    config: dict[str, Any] = {}
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                config = yaml.safe_load(f) or {}
        except Exception:
            config = {}

    # Update API keys
    if "api_keys" not in config:
        config["api_keys"] = {}
    config["api_keys"][key_name] = key_value

    # Save config with restricted permissions
    CONFIG_FILE.touch(mode=0o600, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    # Ensure file permissions are restricted (read/write for owner only)
    CONFIG_FILE.chmod(0o600)


def delete_api_key(key_name: str) -> bool:
    """
    Delete an API key from the config file.

    Args:
        key_name: Key name to delete

    Returns:
        True if key was deleted, False if not found
    """
    import yaml

    if not CONFIG_FILE.exists():
        return False

    try:
        with open(CONFIG_FILE, "r") as f:
            config = yaml.safe_load(f) or {}
    except Exception:
        return False

    api_keys = config.get("api_keys", {})
    if key_name not in api_keys:
        return False

    del api_keys[key_name]
    config["api_keys"] = api_keys

    with open(CONFIG_FILE, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    return True


def list_api_keys() -> dict[str, bool]:
    """
    List configured API keys (shows which are set, not the values).

    Returns:
        Dict mapping key names to whether they are configured
    """
    keys = get_api_keys()
    return {
        "shodan": keys.get_shodan() is not None,
        "securitytrails": keys.get_securitytrails() is not None,
        "censys": keys.get_censys()[0] is not None,
    }
