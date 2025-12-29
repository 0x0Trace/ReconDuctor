"""Multi-provider LLM client for AI-powered reconnaissance."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from reconductor.core.config import LLMConfig, LLMProvider
from reconductor.core.logger import get_logger

logger = get_logger(__name__)


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> str:
        """Generate text from prompt."""
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if provider is available."""
        pass


class OllamaProvider(BaseLLMProvider):
    """
    Ollama local LLM provider with TLS support.

    Free, private, and offline-capable.
    Supports both HTTP and HTTPS connections.
    """

    def __init__(
        self,
        model: str = "llama3.2",
        api_base: str = "http://localhost:11434",
        verify_ssl: bool = True,
        ssl_cert: Optional[str] = None,
    ):
        """
        Initialize Ollama provider.

        Args:
            model: Model name
            api_base: Ollama API base URL (supports http:// and https://)
            verify_ssl: Verify SSL certificates (set False for self-signed certs)
            ssl_cert: Path to custom CA certificate for verification
        """
        self.model = model
        self.api_base = api_base
        self.verify_ssl = verify_ssl
        self.ssl_cert = ssl_cert

    def _get_client_kwargs(self, timeout: int = 120) -> dict[str, Any]:
        """Get httpx client configuration for SSL."""
        kwargs: dict[str, Any] = {"timeout": timeout}

        if self.api_base.startswith("https://"):
            if not self.verify_ssl:
                kwargs["verify"] = False
                logger.warning("SSL verification disabled for Ollama - use only in trusted networks")
            elif self.ssl_cert:
                kwargs["verify"] = self.ssl_cert
        return kwargs

    async def generate(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> str:
        """Generate text using Ollama."""
        import httpx

        try:
            client_kwargs = self._get_client_kwargs(timeout=120)
            async with httpx.AsyncClient(**client_kwargs) as client:
                response = await client.post(
                    f"{self.api_base}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "options": {
                            "num_predict": max_tokens,
                            "temperature": temperature,
                        },
                        "stream": False,
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    return data.get("response", "")
                else:
                    logger.error(f"Ollama error: {response.status_code}")
                    return ""

        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            return ""

    async def is_available(self) -> bool:
        """Check if Ollama is running."""
        import httpx

        try:
            client_kwargs = self._get_client_kwargs(timeout=5)
            async with httpx.AsyncClient(**client_kwargs) as client:
                response = await client.get(f"{self.api_base}/api/tags")
                return response.status_code == 200
        except Exception:
            return False


class OpenAIProvider(BaseLLMProvider):
    """OpenAI API provider."""

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
    ):
        """
        Initialize OpenAI provider.

        Args:
            model: Model name
            api_key: OpenAI API key
        """
        self.model = model
        self.api_key = api_key

    async def generate(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> str:
        """Generate text using OpenAI."""
        import os

        api_key = self.api_key or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            logger.error("OpenAI API key not configured")
            return ""

        import httpx

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": max_tokens,
                        "temperature": temperature,
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    return data["choices"][0]["message"]["content"]
                else:
                    logger.error(f"OpenAI error: {response.status_code}")
                    return ""

        except Exception as e:
            logger.error(f"OpenAI generation failed: {e}")
            return ""

    async def is_available(self) -> bool:
        """Check if OpenAI API key is configured."""
        import os
        return bool(self.api_key or os.environ.get("OPENAI_API_KEY"))


class AnthropicProvider(BaseLLMProvider):
    """Anthropic Claude API provider."""

    def __init__(
        self,
        model: str = "claude-3-haiku-20240307",
        api_key: Optional[str] = None,
    ):
        """
        Initialize Anthropic provider.

        Args:
            model: Model name
            api_key: Anthropic API key
        """
        self.model = model
        self.api_key = api_key

    async def generate(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> str:
        """Generate text using Anthropic."""
        import os

        api_key = self.api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            logger.error("Anthropic API key not configured")
            return ""

        import httpx

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "max_tokens": max_tokens,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    return data["content"][0]["text"]
                else:
                    logger.error(f"Anthropic error: {response.status_code}")
                    return ""

        except Exception as e:
            logger.error(f"Anthropic generation failed: {e}")
            return ""

    async def is_available(self) -> bool:
        """Check if Anthropic API key is configured."""
        import os
        return bool(self.api_key or os.environ.get("ANTHROPIC_API_KEY"))


class GeminiProvider(BaseLLMProvider):
    """Google Gemini API provider."""

    def __init__(
        self,
        model: str = "gemini-1.5-flash",
        api_key: Optional[str] = None,
    ):
        """
        Initialize Gemini provider.

        Args:
            model: Model name (gemini-1.5-flash, gemini-1.5-pro, gemini-2.0-flash-exp)
            api_key: Google AI API key
        """
        self.model = model
        self.api_key = api_key

    async def generate(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> str:
        """Generate text using Gemini."""
        import os

        api_key = self.api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            logger.error("Gemini API key not configured (set GEMINI_API_KEY or GOOGLE_API_KEY)")
            return ""

        import httpx

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
                    params={"key": api_key},
                    headers={"Content-Type": "application/json"},
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {
                            "maxOutputTokens": max_tokens,
                            "temperature": temperature,
                        },
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        content = candidates[0].get("content", {})
                        parts = content.get("parts", [])
                        if parts:
                            return parts[0].get("text", "")
                    return ""
                else:
                    logger.error(f"Gemini error: {response.status_code} - {response.text[:200]}")
                    return ""

        except Exception as e:
            logger.error(f"Gemini generation failed: {e}")
            return ""

    async def is_available(self) -> bool:
        """Check if Gemini API key is configured."""
        import os
        return bool(
            self.api_key
            or os.environ.get("GEMINI_API_KEY")
            or os.environ.get("GOOGLE_API_KEY")
        )


class GroqProvider(BaseLLMProvider):
    """Groq API provider for fast inference."""

    def __init__(
        self,
        model: str = "llama-3.3-70b-versatile",
        api_key: Optional[str] = None,
    ):
        """
        Initialize Groq provider.

        Args:
            model: Model name (llama-3.3-70b-versatile, mixtral-8x7b-32768, etc.)
            api_key: Groq API key
        """
        self.model = model
        self.api_key = api_key

    async def generate(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> str:
        """Generate text using Groq."""
        import os

        api_key = self.api_key or os.environ.get("GROQ_API_KEY")
        if not api_key:
            logger.error("Groq API key not configured (set GROQ_API_KEY)")
            return ""

        import httpx

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": max_tokens,
                        "temperature": temperature,
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    return data["choices"][0]["message"]["content"]
                else:
                    logger.error(f"Groq error: {response.status_code}")
                    return ""

        except Exception as e:
            logger.error(f"Groq generation failed: {e}")
            return ""

    async def is_available(self) -> bool:
        """Check if Groq API key is configured."""
        import os
        return bool(self.api_key or os.environ.get("GROQ_API_KEY"))


class ClaudeCodeProvider(BaseLLMProvider):
    """
    Claude Code CLI provider for headless LLM operations.

    Uses the `claude` CLI command with --print flag for non-interactive
    generation. Leverages existing Claude Code authentication and configuration.

    Security Notes:
        - Requires `claude` CLI to be installed and authenticated
        - Input prompts are validated for length and null bytes
        - Processes are killed on timeout to prevent resource leaks
        - Note: max_tokens and temperature params are not supported by CLI

    Example:
        provider = ClaudeCodeProvider(model="claude-sonnet-4-5-20250514")
        result = await provider.generate("Generate a list of subdomains")
    """

    # Valid model names/aliases for Claude Code CLI
    VALID_MODELS = {
        "sonnet",   # Alias for latest Claude Sonnet
        "opus",     # Alias for latest Claude Opus
        "haiku",    # Alias for latest Claude Haiku
    }

    # Maximum prompt length (characters) - prevent resource exhaustion
    MAX_PROMPT_LENGTH = 100000

    def __init__(
        self,
        model: str = "sonnet",  # Use alias for Claude Sonnet 4
        max_turns: int = 1,
        timeout: int = 120,
    ):
        """
        Initialize Claude Code provider.

        Args:
            model: Claude model to use (default: claude-sonnet-4-5-20250514)
            max_turns: Maximum conversation turns (default: 1 for single-shot)
            timeout: Command timeout in seconds

        Raises:
            ValueError: If model name is invalid or max_turns < 1
        """
        import shutil

        if model not in self.VALID_MODELS:
            logger.warning(f"Unrecognized model '{model}', using anyway")

        if max_turns < 1:
            raise ValueError("max_turns must be at least 1")

        if timeout < 1 or timeout > 600:
            raise ValueError("timeout must be between 1 and 600 seconds")

        self.model = model
        self.max_turns = max_turns
        self.timeout = timeout

        # Cache claude path at init time
        self._claude_path: Optional[str] = shutil.which("claude")

    def _validate_prompt(self, prompt: str) -> None:
        """
        Validate prompt for security and sanity.

        Args:
            prompt: The prompt to validate

        Raises:
            ValueError: If prompt is invalid
        """
        if not prompt:
            raise ValueError("Prompt cannot be empty")

        if len(prompt) > self.MAX_PROMPT_LENGTH:
            raise ValueError(
                f"Prompt too long: {len(prompt)} chars "
                f"(max: {self.MAX_PROMPT_LENGTH})"
            )

        # Check for null bytes (could cause issues with subprocess)
        if "\x00" in prompt:
            raise ValueError("Prompt contains null bytes")

    async def generate(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> str:
        """
        Generate text using Claude Code CLI in headless mode.

        Note: max_tokens and temperature parameters are accepted for API
        compatibility but are not used - Claude Code CLI doesn't support them.

        Args:
            prompt: The prompt to send to Claude
            max_tokens: (Unused) Maximum tokens in response
            temperature: (Unused) Generation temperature
            **kwargs: (Unused) Additional arguments

        Returns:
            Generated text, or empty string on failure
        """
        import asyncio

        # Check CLI availability (using cached path)
        if not self._claude_path:
            logger.error("Claude Code CLI not found in PATH")
            return ""

        # Validate input
        try:
            self._validate_prompt(prompt)
        except ValueError as e:
            logger.error(f"Invalid prompt: {e}")
            return ""

        process: Optional[asyncio.subprocess.Process] = None

        try:
            # Build command for headless execution
            # Note: Arguments are passed as list elements, not shell-interpreted
            cmd = [
                self._claude_path,
                "--print",
                "-p", prompt,
                "--model", self.model,
                "--max-turns", str(self.max_turns),
            ]

            # Execute claude CLI
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout,
            )

            # Decode with error handling
            result = stdout.decode("utf-8", errors="replace").strip()
            stderr_text = stderr.decode("utf-8", errors="replace").strip()

            # Log stderr if present (even on success - may contain warnings)
            if stderr_text:
                logger.debug(f"Claude Code stderr: {stderr_text[:500]}")

            if process.returncode == 0:
                logger.debug(f"Claude Code generated {len(result)} chars")
                return result
            else:
                logger.error(f"Claude Code CLI error (code {process.returncode}): {stderr_text[:500]}")
                return ""

        except asyncio.TimeoutError:
            logger.error(f"Claude Code CLI timed out after {self.timeout}s")
            # CRITICAL: Kill the process to prevent resource leak
            if process is not None:
                try:
                    process.kill()
                    await process.wait()
                    logger.debug("Killed timed-out Claude Code process")
                except ProcessLookupError:
                    pass  # Process already terminated
                except Exception as kill_err:
                    logger.warning(f"Failed to kill process: {kill_err}")
            return ""

        except Exception as e:
            logger.exception(f"Claude Code generation failed: {e}")
            # Clean up process if it exists
            if process is not None:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
            return ""

    async def is_available(self) -> bool:
        """Check if Claude Code CLI is available."""
        return self._claude_path is not None


class LLMClient:
    """
    Unified LLM client with multi-provider support and fallback.

    Defaults to Ollama (local, free, private), falls back to cloud providers.
    """

    PROVIDERS = {
        LLMProvider.OLLAMA: OllamaProvider,
        LLMProvider.OPENAI: OpenAIProvider,
        LLMProvider.ANTHROPIC: AnthropicProvider,
        LLMProvider.GEMINI: GeminiProvider,
        LLMProvider.GROQ: GroqProvider,
        LLMProvider.CLAUDE_CODE: ClaudeCodeProvider,
    }

    def __init__(self, config: Optional[LLMConfig] = None):
        """
        Initialize LLM client.

        Args:
            config: LLM configuration
        """
        self.config = config or LLMConfig()
        self.primary: Optional[BaseLLMProvider] = None
        self.fallback: Optional[BaseLLMProvider] = None

        self._init_providers()

    def _init_providers(self) -> None:
        """Initialize primary and fallback providers."""
        # Get API key securely (use get_api_key() to unwrap SecretStr)
        api_key = self.config.get_api_key()

        # Primary provider
        primary_cls = self.PROVIDERS.get(self.config.primary_provider)
        if primary_cls:
            if self.config.primary_provider == LLMProvider.OLLAMA:
                self.primary = primary_cls(
                    model=self.config.primary_model,
                    api_base=self.config.api_base or "http://localhost:11434",
                )
            elif self.config.primary_provider == LLMProvider.CLAUDE_CODE:
                self.primary = primary_cls(
                    model=self.config.primary_model,
                )
            else:
                self.primary = primary_cls(
                    model=self.config.primary_model,
                    api_key=api_key,
                )

        # Fallback provider
        fallback_cls = self.PROVIDERS.get(self.config.fallback_provider)
        if fallback_cls:
            if self.config.fallback_provider == LLMProvider.CLAUDE_CODE:
                self.fallback = fallback_cls(
                    model=self.config.fallback_model,
                )
            elif self.config.fallback_provider == LLMProvider.OLLAMA:
                self.fallback = fallback_cls(
                    model=self.config.fallback_model,
                    api_base=self.config.api_base or "http://localhost:11434",
                )
            else:
                self.fallback = fallback_cls(
                    model=self.config.fallback_model,
                    api_key=api_key,
                )

    async def generate(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> str:
        """
        Generate text with fallback on failure.

        Args:
            prompt: Input prompt
            max_tokens: Maximum output tokens
            temperature: Generation temperature
            **kwargs: Additional provider-specific arguments

        Returns:
            Generated text
        """
        # Try primary provider
        if self.primary and await self.primary.is_available():
            result = await self.primary.generate(
                prompt, max_tokens, temperature, **kwargs
            )
            if result:
                return result
            logger.warning("Primary LLM failed, trying fallback")

        # Try fallback provider
        if self.fallback and await self.fallback.is_available():
            return await self.fallback.generate(
                prompt, max_tokens, temperature, **kwargs
            )

        logger.error("All LLM providers failed")
        return ""

    async def check_availability(self) -> dict[str, bool]:
        """
        Check availability of all configured providers.

        Returns:
            Dictionary mapping provider name to availability
        """
        availability = {}

        if self.primary:
            availability["primary"] = await self.primary.is_available()

        if self.fallback:
            availability["fallback"] = await self.fallback.is_available()

        return availability


# Default client instance
_default_client: Optional[LLMClient] = None


def get_llm_client(config: Optional[LLMConfig] = None) -> LLMClient:
    """Get or create the default LLM client."""
    global _default_client
    if _default_client is None or config is not None:
        _default_client = LLMClient(config)
    return _default_client
