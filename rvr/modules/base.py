"""
RVR — Base module v2
Supports silent mode so raw commands don't spam the terminal
"""

import subprocess
import shutil
from pathlib import Path
from typing import List, Optional, Dict, Any

from rvr.utils.console import log_warn, log_error
from rvr.utils.state import RVRState
from rvr.utils.config import get_config


class BaseModule:
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        self.state = state
        self.profile = profile
        self.output_dir = state.output_dir
        self.config = get_config()

    def tool(self, key: str) -> str:
        """Resolve a logical tool key (e.g. 'enum4linux') to the actual
        binary name from config.yaml — falls back to the key itself if
        unconfigured. Use this instead of hardcoding binary names in
        run_command()/tool_exists() calls."""
        return self.config.tool(key)

    def tool_exists(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    def run_command(
        self,
        cmd: List[str],
        output_file: Optional[Path] = None,
        timeout: int = 600,
        env: Optional[Dict] = None,
        silent: bool = False,
    ) -> Optional[str]:
        """
        Run a command and return stdout.
        silent=True suppresses the '[*] Running: ...' log line.
        """
        if not silent and self.state.verbose:
            from rvr.utils.console import log_info
            log_info(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
            output = result.stdout + result.stderr

            if output_file:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, "w") as f:
                    f.write(output)

            return result.stdout

        except subprocess.TimeoutExpired:
            log_warn(f"Timed out after {timeout}s: {cmd[0]}")
            return None
        except FileNotFoundError:
            log_error(f"Tool not found: {cmd[0]}")
            return None
        except Exception as e:
            log_error(f"Command failed: {e}")
            return None

    def ensure_dir(self, subdir: str) -> Path:
        d = self.output_dir / subdir
        d.mkdir(parents=True, exist_ok=True)
        return d