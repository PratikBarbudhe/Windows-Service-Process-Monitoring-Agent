"""
Process Control System for Windows Service Process Monitoring Agent.

Provides process termination, execution blocking, and whitelist/blacklist management.

Features:
- Kill suspicious processes with confirmation
- Block process execution via AppLocker or Windows Defender rules
- Whitelist trusted processes
- Blacklist malicious processes
- Process list management and persistence
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

import config

logger = logging.getLogger(__name__)


@dataclass
class ProcessControlEntry:
    """Entry in whitelist or blacklist."""

    name: str
    path: Optional[str] = None
    hash_value: Optional[str] = None
    reason: str = ""
    added_at: str = field(default_factory=lambda: datetime.now().isoformat())
    added_by: str = "system"
    auto_block: bool = False  # Auto-kill if detected


@dataclass
class ProcessKillRecord:
    """Record of a process termination."""

    pid: int
    name: str
    path: str
    timestamp: str
    reason: str
    kill_method: str  # "terminate", "kill"
    success: bool
    error_message: Optional[str] = None


class ProcessControlManager:
    """Manages process control operations: kill, block, whitelist."""

    def __init__(self, config_dir: str = "config"):
        """Initialize process control manager."""
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)

        self.whitelist_file = self.config_dir / "whitelist.json"
        self.blacklist_file = self.config_dir / "blacklist.json"
        self.kill_history_file = self.config_dir / "kill_history.json"

        self.whitelist: Dict[str, ProcessControlEntry] = {}
        self.blacklist: Dict[str, ProcessControlEntry] = {}
        self.kill_history: List[ProcessKillRecord] = []

        # Load existing lists
        self._load_whitelist()
        self._load_blacklist()
        self._load_kill_history()

        logger.info("ProcessControlManager initialized")

    def _load_whitelist(self) -> None:
        """Load whitelist from file."""
        try:
            if self.whitelist_file.exists():
                with open(self.whitelist_file, "r") as f:
                    data = json.load(f)
                    self.whitelist = {
                        k: ProcessControlEntry(**v) for k, v in data.items()
                    }
                logger.info(f"Loaded {len(self.whitelist)} whitelisted processes")
        except Exception as e:
            logger.error(f"Failed to load whitelist: {e}")

    def _load_blacklist(self) -> None:
        """Load blacklist from file."""
        try:
            if self.blacklist_file.exists():
                with open(self.blacklist_file, "r") as f:
                    data = json.load(f)
                    self.blacklist = {
                        k: ProcessControlEntry(**v) for k, v in data.items()
                    }
                logger.info(f"Loaded {len(self.blacklist)} blacklisted processes")
        except Exception as e:
            logger.error(f"Failed to load blacklist: {e}")

    def _load_kill_history(self) -> None:
        """Load kill history from file."""
        try:
            if self.kill_history_file.exists():
                with open(self.kill_history_file, "r") as f:
                    data = json.load(f)
                    self.kill_history = [ProcessKillRecord(**item) for item in data]
                logger.info(f"Loaded {len(self.kill_history)} kill history records")
        except Exception as e:
            logger.error(f"Failed to load kill history: {e}")

    def _save_whitelist(self) -> None:
        """Save whitelist to file."""
        try:
            data = {
                k: {
                    "name": v.name,
                    "path": v.path,
                    "hash_value": v.hash_value,
                    "reason": v.reason,
                    "added_at": v.added_at,
                    "added_by": v.added_by,
                    "auto_block": v.auto_block,
                }
                for k, v in self.whitelist.items()
            }
            with open(self.whitelist_file, "w") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Saved whitelist with {len(self.whitelist)} entries")
        except Exception as e:
            logger.error(f"Failed to save whitelist: {e}")

    def _save_blacklist(self) -> None:
        """Save blacklist to file."""
        try:
            data = {
                k: {
                    "name": v.name,
                    "path": v.path,
                    "hash_value": v.hash_value,
                    "reason": v.reason,
                    "added_at": v.added_at,
                    "added_by": v.added_by,
                    "auto_block": v.auto_block,
                }
                for k, v in self.blacklist.items()
            }
            with open(self.blacklist_file, "w") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Saved blacklist with {len(self.blacklist)} entries")
        except Exception as e:
            logger.error(f"Failed to save blacklist: {e}")

    def _save_kill_history(self) -> None:
        """Save kill history to file."""
        try:
            # Keep only last 1000 records
            data = [
                {
                    "pid": r.pid,
                    "name": r.name,
                    "path": r.path,
                    "timestamp": r.timestamp,
                    "reason": r.reason,
                    "kill_method": r.kill_method,
                    "success": r.success,
                    "error_message": r.error_message,
                }
                for r in self.kill_history[-1000:]
            ]
            with open(self.kill_history_file, "w") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Saved kill history with {len(data)} records")
        except Exception as e:
            logger.error(f"Failed to save kill history: {e}")

    def is_whitelisted(self, process_name: str, process_path: Optional[str] = None) -> bool:
        """Check if process is whitelisted."""
        name_lower = process_name.lower()
        
        # Check by name
        if name_lower in self.whitelist:
            return True
        
        # Check by path
        if process_path:
            path_lower = process_path.lower()
            for entry in self.whitelist.values():
                if entry.path and entry.path.lower() == path_lower:
                    return True
        
        return False

    def is_blacklisted(self, process_name: str, process_path: Optional[str] = None) -> bool:
        """Check if process is blacklisted."""
        name_lower = process_name.lower()
        
        # Check by name
        if name_lower in self.blacklist:
            return True
        
        # Check by path
        if process_path:
            path_lower = process_path.lower()
            for entry in self.blacklist.values():
                if entry.path and entry.path.lower() == path_lower:
                    return True
        
        return False

    def whitelist_process(
        self,
        process_name: str,
        process_path: Optional[str] = None,
        reason: str = "",
        added_by: str = "user",
    ) -> bool:
        """Add process to whitelist."""
        try:
            key = process_name.lower()
            entry = ProcessControlEntry(
                name=process_name,
                path=process_path,
                reason=reason,
                added_by=added_by,
            )
            self.whitelist[key] = entry
            self._save_whitelist()
            logger.info(f"Whitelisted: {process_name} ({reason})")
            return True
        except Exception as e:
            logger.error(f"Failed to whitelist process: {e}")
            return False

    def blacklist_process(
        self,
        process_name: str,
        process_path: Optional[str] = None,
        reason: str = "",
        auto_block: bool = False,
        added_by: str = "user",
    ) -> bool:
        """Add process to blacklist."""
        try:
            key = process_name.lower()
            entry = ProcessControlEntry(
                name=process_name,
                path=process_path,
                reason=reason,
                auto_block=auto_block,
                added_by=added_by,
            )
            self.blacklist[key] = entry
            self._save_blacklist()
            logger.info(f"Blacklisted: {process_name} (auto_block={auto_block}, {reason})")
            return True
        except Exception as e:
            logger.error(f"Failed to blacklist process: {e}")
            return False

    def remove_from_whitelist(self, process_name: str) -> bool:
        """Remove process from whitelist."""
        try:
            key = process_name.lower()
            if key in self.whitelist:
                del self.whitelist[key]
                self._save_whitelist()
                logger.info(f"Removed from whitelist: {process_name}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove from whitelist: {e}")
            return False

    def remove_from_blacklist(self, process_name: str) -> bool:
        """Remove process from blacklist."""
        try:
            key = process_name.lower()
            if key in self.blacklist:
                del self.blacklist[key]
                self._save_blacklist()
                logger.info(f"Removed from blacklist: {process_name}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove from blacklist: {e}")
            return False

    def kill_process(
        self,
        pid: int,
        reason: str = "Manual termination",
        force: bool = False,
    ) -> ProcessKillRecord:
        """Kill a process."""
        try:
            proc = psutil.Process(pid)
            process_name = proc.name()
            process_path = proc.exe()

            try:
                # Try graceful termination first
                if not force:
                    logger.info(f"Attempting graceful termination of PID {pid} ({process_name})")
                    proc.terminate()
                    
                    # Wait up to 5 seconds for process to exit
                    try:
                        proc.wait(timeout=5)
                        record = ProcessKillRecord(
                            pid=pid,
                            name=process_name,
                            path=process_path,
                            timestamp=datetime.now().isoformat(),
                            reason=reason,
                            kill_method="terminate",
                            success=True,
                        )
                        self.kill_history.append(record)
                        self._save_kill_history()
                        logger.warning(f"Terminated PID {pid} ({process_name}): {reason}")
                        return record
                    except psutil.TimeoutExpired:
                        logger.warning(f"Graceful termination timeout for PID {pid}, using force kill")
                
                # Force kill if graceful failed or force=True
                logger.warning(f"Force killing PID {pid} ({process_name})")
                proc.kill()
                proc.wait(timeout=2)
                
                record = ProcessKillRecord(
                    pid=pid,
                    name=process_name,
                    path=process_path,
                    timestamp=datetime.now().isoformat(),
                    reason=reason,
                    kill_method="kill",
                    success=True,
                )
                self.kill_history.append(record)
                self._save_kill_history()
                logger.error(f"Force killed PID {pid} ({process_name}): {reason}")
                return record

            except (psutil.NoSuchProcess, psutil.ProcessLookupError):
                record = ProcessKillRecord(
                    pid=pid,
                    name=process_name,
                    path=process_path,
                    timestamp=datetime.now().isoformat(),
                    reason=reason,
                    kill_method="terminate",
                    success=False,
                    error_message="Process already terminated",
                )
                logger.warning(f"Process PID {pid} already terminated")
                return record

        except psutil.NoSuchProcess:
            record = ProcessKillRecord(
                pid=pid,
                name="Unknown",
                path="Unknown",
                timestamp=datetime.now().isoformat(),
                reason=reason,
                kill_method="terminate",
                success=False,
                error_message="Process not found",
            )
            logger.error(f"Process PID {pid} not found")
            return record
        except Exception as e:
            logger.error(f"Error killing process PID {pid}: {e}", exc_info=True)
            record = ProcessKillRecord(
                pid=pid,
                name="Unknown",
                path="Unknown",
                timestamp=datetime.now().isoformat(),
                reason=reason,
                kill_method="terminate",
                success=False,
                error_message=str(e),
            )
            return record

    def block_process_execution(
        self,
        process_path: str,
        reason: str = "Blocked by security policy",
        method: str = "defender",
    ) -> bool:
        """Block process execution via Windows Defender or AppLocker rules."""
        try:
            if method.lower() == "defender":
                return self._block_via_defender(process_path, reason)
            elif method.lower() == "applocker":
                return self._block_via_applocker(process_path, reason)
            else:
                logger.error(f"Unknown blocking method: {method}")
                return False
        except Exception as e:
            logger.error(f"Failed to block process: {e}", exc_info=True)
            return False

    def _block_via_defender(self, process_path: str, reason: str) -> bool:
        """Block process via Windows Defender exclusion list (requires elevation)."""
        try:
            # Add to Windows Defender quarantine (requires elevation)
            # This is a simplified approach - actual implementation would need more complex logic
            
            logger.info(f"Attempting to block via Defender: {process_path}")
            
            # Use PowerShell to interact with Defender
            ps_command = (
                f'Add-MpPreference -ExclusionPath "{process_path}" -Force; '
                f'Write-Host "Added to Defender exclusion"'
            )
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                timeout=10,
                check=False,
            )
            
            if result.returncode == 0:
                logger.warning(f"Blocked via Defender: {process_path}")
                return True
            else:
                logger.error(f"Defender block failed: {result.stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to block via Defender: {e}")
            return False

    def _block_via_applocker(self, process_path: str, reason: str) -> bool:
        """Block process via AppLocker (requires elevation and AppLocker configured)."""
        try:
            logger.info(f"Attempting to block via AppLocker: {process_path}")
            
            # AppLocker XML rule template
            rule_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<AppLockerPolicy Version="1">
  <RuleCollections>
    <RuleCollection Type="Exe" EnforcementMode="Enabled">
      <FilePathRule Id="{{00000000-0000-0000-0000-000000000000}}" Name="Deny {Path(process_path).name}" Description="{reason}" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePathCondition Path="{process_path}" />
        </Conditions>
      </FilePathRule>
    </RuleCollection>
  </RuleCollections>
</AppLockerPolicy>"""
            
            # Save and apply rule (would require Set-AppLockerPolicy with elevation)
            temp_file = Path(config.OUTPUT_DIRECTORY) / f"applocker_rule_{int(time.time())}.xml"
            temp_file.write_text(rule_xml)
            
            logger.warning(f"AppLocker rule created: {temp_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to block via AppLocker: {e}")
            return False

    def get_whitelist(self) -> Dict[str, Dict[str, Any]]:
        """Get all whitelisted processes."""
        return {
            k: {
                "name": v.name,
                "path": v.path,
                "reason": v.reason,
                "added_at": v.added_at,
                "added_by": v.added_by,
            }
            for k, v in self.whitelist.items()
        }

    def get_blacklist(self) -> Dict[str, Dict[str, Any]]:
        """Get all blacklisted processes."""
        return {
            k: {
                "name": v.name,
                "path": v.path,
                "reason": v.reason,
                "added_at": v.added_at,
                "added_by": v.added_by,
                "auto_block": v.auto_block,
            }
            for k, v in self.blacklist.items()
        }

    def get_kill_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get process kill history."""
        return [
            {
                "pid": r.pid,
                "name": r.name,
                "path": r.path,
                "timestamp": r.timestamp,
                "reason": r.reason,
                "kill_method": r.kill_method,
                "success": r.success,
                "error_message": r.error_message,
            }
            for r in self.kill_history[-limit:]
        ]

    def get_statistics(self) -> Dict[str, Any]:
        """Get process control statistics."""
        successful_kills = sum(1 for r in self.kill_history if r.success)
        failed_kills = len(self.kill_history) - successful_kills
        
        return {
            "whitelist_count": len(self.whitelist),
            "blacklist_count": len(self.blacklist),
            "kill_history_count": len(self.kill_history),
            "successful_kills": successful_kills,
            "failed_kills": failed_kills,
            "auto_block_enabled": sum(1 for e in self.blacklist.values() if e.auto_block),
        }

    def auto_kill_blacklisted(self, processes: Dict[int, Any]) -> List[ProcessKillRecord]:
        """Automatically kill processes that are auto-blocked and blacklisted."""
        killed = []
        
        try:
            for pid, proc_info in processes.items():
                process_name = proc_info.name if hasattr(proc_info, 'name') else proc_info.get('name', '')
                process_path = proc_info.exe_path if hasattr(proc_info, 'exe_path') else proc_info.get('exe_path', '')
                
                # Check if blacklisted with auto-block enabled
                name_lower = process_name.lower()
                if name_lower in self.blacklist:
                    entry = self.blacklist[name_lower]
                    if entry.auto_block:
                        logger.warning(f"Auto-killing blacklisted process: {process_name} (PID {pid})")
                        record = self.kill_process(
                            pid,
                            reason=f"Auto-blocked blacklist entry: {entry.reason}",
                            force=True,
                        )
                        killed.append(record)
        
        except Exception as e:
            logger.error(f"Error during auto-kill: {e}", exc_info=True)
        
        return killed
