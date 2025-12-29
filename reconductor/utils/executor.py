"""Async subprocess executor for external tools."""

from __future__ import annotations

import asyncio
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from reconductor.core.logger import get_logger, log_tool_complete, log_tool_start

logger = get_logger(__name__)


# Shell metacharacters that could enable command injection
SHELL_METACHARACTERS = re.compile(r'[;&|`$(){}[\]<>\\"\'\n\r\x00]')

# Additional dangerous patterns
DANGEROUS_PATTERNS = [
    r'\.\.',       # Path traversal
    r'^-',         # Argument injection (leading dash)
]


class CommandInjectionError(Exception):
    """Raised when command injection is detected."""
    pass


def validate_argument(arg: str, allow_paths: bool = True, is_header_value: bool = False) -> str:
    """
    Validate a command argument for shell metacharacters.

    Args:
        arg: Argument to validate
        allow_paths: Whether to allow path-like arguments
        is_header_value: Whether this is an HTTP header value (allows more chars)

    Returns:
        The validated argument

    Raises:
        CommandInjectionError: If dangerous characters detected
    """
    if not arg:
        return arg

    # Characters that are ALWAYS dangerous in any context
    always_dangerous = ['`', '\n', '\r', '\x00']
    for char in always_dangerous:
        if char in arg:
            raise CommandInjectionError(
                f"Dangerous character '{repr(char)}' detected"
            )

    if is_header_value:
        # For HTTP headers, only block command substitution and null bytes
        # Allow semicolons (used in Accept, Accept-Language headers)
        # Allow parentheses (used in User-Agent)
        # Allow quotes (may appear in some headers)
        shell_dangerous = ['&', '|', '$']
        for char in shell_dangerous:
            if char in arg:
                raise CommandInjectionError(
                    f"Shell metacharacter '{char}' in header value"
                )
    else:
        # For regular arguments, be stricter
        critical_dangerous = [';', '&', '|', '$']
        for char in critical_dangerous:
            if char in arg:
                raise CommandInjectionError(
                    f"Critical shell metacharacter '{char}' detected"
                )

        # Check for other dangerous characters
        additional_dangerous = ['<', '>', '\\']
        for char in additional_dangerous:
            if char in arg:
                raise CommandInjectionError(
                    f"Dangerous character '{char}' detected in argument"
                )

    # Check for path traversal (but allow absolute paths)
    if not allow_paths and '..' in arg:
        raise CommandInjectionError("Path traversal detected in argument")

    return arg


def validate_target(target: str) -> str:
    """
    Validate a target (domain, URL, IP) for command injection.

    Args:
        target: Target to validate

    Returns:
        The validated target

    Raises:
        CommandInjectionError: If dangerous characters detected
    """
    if not target:
        return target

    # Targets should never contain shell metacharacters
    dangerous = [';', '&', '|', '`', '$', '(', ')', '{', '}',
                 '[', ']', '<', '>', '\\', '"', "'", '\n', '\r', '\x00']

    for char in dangerous:
        if char in target:
            raise CommandInjectionError(
                f"Dangerous character '{repr(char)}' in target: {target}"
            )

    # Additional validation for targets
    # Must look like a domain, IP, or URL
    valid_target_pattern = re.compile(
        r'^[a-zA-Z0-9]'  # Must start with alphanumeric
        r'[a-zA-Z0-9._:/@\-]*'  # Valid URL/domain chars
        r'$'
    )

    if not valid_target_pattern.match(target):
        raise CommandInjectionError(
            f"Target contains invalid characters: {target}"
        )

    return target


def sanitize_command(command: list[str]) -> list[str]:
    """
    Sanitize a command list for safe execution.

    Args:
        command: Command and arguments

    Returns:
        Sanitized command list

    Raises:
        CommandInjectionError: If dangerous input detected
    """
    if not command:
        raise CommandInjectionError("Empty command")

    sanitized = []
    prev_was_header_flag = False

    for i, arg in enumerate(command):
        if i == 0:
            # First element is the tool path - validate it's a real path
            sanitized.append(validate_argument(arg, allow_paths=True))
        elif arg == '-H' or arg == '--header':
            # This is an HTTP header flag
            sanitized.append(arg)
            prev_was_header_flag = True
        elif prev_was_header_flag:
            # This is an HTTP header value - allow parentheses, quotes, etc.
            sanitized.append(validate_argument(arg, allow_paths=True, is_header_value=True))
            prev_was_header_flag = False
        elif arg.startswith('-'):
            # Flag arguments - allow them but validate
            sanitized.append(validate_argument(arg, allow_paths=False))
            prev_was_header_flag = False
        else:
            # Regular arguments - strict validation
            sanitized.append(validate_argument(arg, allow_paths=True))
            prev_was_header_flag = False

    return sanitized


@dataclass
class ToolResult:
    """Result from executing an external tool."""
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration: float
    success: bool
    error: Optional[str] = None
    output_file: Optional[Path] = None
    parsed_data: Any = None


@dataclass
class ToolConfig:
    """Configuration for a tool execution."""
    name: str
    command: list[str]
    timeout: int = 300
    output_file: Optional[Path] = None
    input_file: Optional[Path] = None
    input_data: Optional[str] = None
    env: dict[str, str] = field(default_factory=dict)
    cwd: Optional[Path] = None


class ToolExecutor:
    """
    Async executor for external reconnaissance tools.

    Provides unified interface for running tools like subfinder,
    puredns, nuclei, httpx, etc. with proper error handling,
    timeout management, and logging.
    """

    def __init__(self, timeout: int = 300):
        """
        Initialize tool executor.

        Args:
            timeout: Default timeout in seconds
        """
        self.default_timeout = timeout
        self._running_processes: dict[str, asyncio.subprocess.Process] = {}

    # ProjectDiscovery and Go-based tools that should be found in ~/go/bin/
    GO_TOOLS = {
        "subfinder", "httpx", "dnsx", "nuclei", "naabu",
        "alterx", "puredns", "katana", "chaos", "notify",
        "interactsh-client", "shuffledns", "tlsx", "uncover",
    }

    @classmethod
    def check_tool_available(cls, tool_name: str) -> bool:
        """
        Check if a tool is available.

        Args:
            tool_name: Name of the tool

        Returns:
            True if tool is available
        """
        return cls.get_tool_path(tool_name) is not None

    @classmethod
    def get_tool_path(cls, tool_name: str) -> Optional[str]:
        """
        Get full path to a tool.

        Prioritizes Go tools from ~/go/bin/ to avoid conflicts
        with Python packages that have the same name (e.g., httpx).

        Args:
            tool_name: Name of the tool

        Returns:
            Full path or None if not found
        """
        # For Go-based tools, check ~/go/bin/ first
        if tool_name in cls.GO_TOOLS:
            go_bin = Path.home() / "go" / "bin" / tool_name
            if go_bin.exists() and go_bin.is_file():
                return str(go_bin)

        # Fall back to regular PATH search
        return shutil.which(tool_name)

    async def run(
        self,
        command: list[str],
        *,
        timeout: Optional[int] = None,
        input_data: Optional[str] = None,
        output_file: Optional[Path] = None,
        cwd: Optional[Path] = None,
        env: Optional[dict[str, str]] = None,
    ) -> ToolResult:
        """
        Execute a command asynchronously.

        Args:
            command: Command and arguments as list
            timeout: Execution timeout in seconds
            input_data: Data to send to stdin
            output_file: Optional file to read output from
            cwd: Working directory
            env: Additional environment variables

        Returns:
            ToolResult with execution results
        """
        tool_name = command[0] if command else "unknown"
        timeout = timeout or self.default_timeout

        # Sanitize command to prevent injection attacks
        try:
            command = sanitize_command(command)
        except CommandInjectionError as e:
            logger.error(f"Command injection attempt blocked: {e}")
            return ToolResult(
                command=" ".join(command) if command else "",
                returncode=-1,
                stdout="",
                stderr="",
                duration=0,
                success=False,
                error=f"Command rejected: {e}",
            )

        cmd_str = " ".join(command)
        log_tool_start(tool_name, command=cmd_str)
        start_time = time.time()

        try:
            # Merge environment
            process_env = None
            if env:
                import os
                process_env = {**os.environ, **env}

            # Create process
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=process_env,
            )

            # Track running process
            process_id = f"{tool_name}_{id(process)}"
            self._running_processes[process_id] = process

            try:
                # Communicate with timeout
                stdin_bytes = input_data.encode() if input_data else None
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input=stdin_bytes),
                    timeout=timeout,
                )

                duration = time.time() - start_time
                success = process.returncode == 0

                result = ToolResult(
                    command=cmd_str,
                    returncode=process.returncode,
                    stdout=stdout.decode(errors="replace"),
                    stderr=stderr.decode(errors="replace"),
                    duration=duration,
                    success=success,
                    output_file=output_file,
                )

                # Read output file if specified
                if output_file and output_file.exists():
                    result.parsed_data = output_file.read_text()

                log_tool_complete(
                    tool_name,
                    success=success,
                    duration=duration,
                    returncode=process.returncode,
                )

                return result

            finally:
                # Remove from tracking
                self._running_processes.pop(process_id, None)

        except asyncio.TimeoutError:
            duration = time.time() - start_time
            logger.error(
                f"{tool_name} timed out",
                timeout=timeout,
                duration=duration,
            )

            # Try to kill the process
            try:
                process.kill()
                await process.wait()
            except Exception:
                pass

            return ToolResult(
                command=cmd_str,
                returncode=-1,
                stdout="",
                stderr="",
                duration=duration,
                success=False,
                error=f"Timeout after {timeout}s",
            )

        except FileNotFoundError:
            duration = time.time() - start_time
            error = f"Tool not found: {tool_name}"
            logger.error(error)

            return ToolResult(
                command=cmd_str,
                returncode=-1,
                stdout="",
                stderr="",
                duration=duration,
                success=False,
                error=error,
            )

        except Exception as e:
            duration = time.time() - start_time
            error = f"Execution error: {str(e)}"
            logger.exception(error)

            return ToolResult(
                command=cmd_str,
                returncode=-1,
                stdout="",
                stderr="",
                duration=duration,
                success=False,
                error=error,
            )

    async def run_with_config(self, config: ToolConfig) -> ToolResult:
        """
        Execute a tool with full configuration.

        Args:
            config: Tool configuration

        Returns:
            ToolResult with execution results
        """
        # Write input file if needed
        if config.input_file and config.input_data:
            config.input_file.parent.mkdir(parents=True, exist_ok=True)
            config.input_file.write_text(config.input_data)

        return await self.run(
            config.command,
            timeout=config.timeout,
            input_data=config.input_data if not config.input_file else None,
            output_file=config.output_file,
            cwd=config.cwd,
            env=config.env,
        )

    async def run_parallel(
        self,
        commands: list[list[str]],
        max_concurrent: int = 5,
        timeout: Optional[int] = None,
    ) -> list[ToolResult]:
        """
        Run multiple commands in parallel with concurrency limit.

        Args:
            commands: List of commands
            max_concurrent: Maximum concurrent executions
            timeout: Timeout per command

        Returns:
            List of ToolResults
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def run_with_semaphore(cmd: list[str]) -> ToolResult:
            async with semaphore:
                return await self.run(cmd, timeout=timeout)

        tasks = [run_with_semaphore(cmd) for cmd in commands]
        return await asyncio.gather(*tasks)

    async def kill_all(self) -> None:
        """Kill all running processes."""
        for process_id, process in list(self._running_processes.items()):
            try:
                process.kill()
                await process.wait()
                logger.info(f"Killed process {process_id}")
            except Exception as e:
                logger.warning(f"Failed to kill {process_id}: {e}")

        self._running_processes.clear()

    def ensure_tools_available(self, tools: list[str]) -> dict[str, bool]:
        """
        Check availability of multiple tools.

        Args:
            tools: List of tool names

        Returns:
            Dictionary mapping tool name to availability
        """
        availability = {}
        for tool in tools:
            available = self.check_tool_available(tool)
            availability[tool] = available
            if not available:
                logger.warning(f"Tool not available: {tool}")
        return availability


# Singleton executor instance
_executor: Optional[ToolExecutor] = None


def get_executor(timeout: int = 300) -> ToolExecutor:
    """Get or create the singleton executor instance."""
    global _executor
    if _executor is None:
        _executor = ToolExecutor(timeout=timeout)
    return _executor
