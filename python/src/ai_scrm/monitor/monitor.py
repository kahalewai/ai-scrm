"""
AI-SCRM Monitor - Continuous validation of AI systems.

Provides tiered validation:
- Fast hash checks (default: 60 seconds)
- MCP heartbeat checks (default: 5 minutes)
- Full re-scan (default: 30 minutes)

Emits RADE events on drift detection.

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""

import hashlib
import json
import logging
import os
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class MonitorState(Enum):
    """Monitor state."""
    STOPPED = "stopped"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"


@dataclass
class MonitorConfig:
    """Monitor configuration."""
    
    # Validation intervals (seconds)
    hash_check_interval: int = 60       # Fast integrity checks
    mcp_heartbeat_interval: int = 300   # MCP server health checks  
    full_scan_interval: int = 1800      # Complete re-discovery
    
    # Behavior
    fail_on_critical: bool = False      # Raise exception on critical events
    auto_approve_known: bool = False    # Auto-approve components in ABOM
    
    # Paths
    model_dirs: List[str] = field(default_factory=lambda: ["."])
    
    # Skip list
    skip_components: List[str] = field(default_factory=list)


@dataclass
class MonitorStatus:
    """Current monitor status."""
    state: MonitorState
    last_hash_check: Optional[str] = None
    last_mcp_heartbeat: Optional[str] = None
    last_full_scan: Optional[str] = None
    components_checked: int = 0
    drift_events: int = 0
    violations: int = 0
    uptime_seconds: float = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "last_hash_check": self.last_hash_check,
            "last_mcp_heartbeat": self.last_mcp_heartbeat,
            "last_full_scan": self.last_full_scan,
            "components_checked": self.components_checked,
            "drift_events": self.drift_events,
            "violations": self.violations,
            "uptime_seconds": self.uptime_seconds,
        }


class Monitor:
    """
    Continuous validation monitor for AI systems.
    
    Provides tiered validation at configurable intervals:
    - Hash checks: Verify file integrity
    - MCP heartbeat: Check MCP server availability
    - Full scan: Discover new/removed components
    
    Example:
        >>> monitor = Monitor(
        ...     abom_path="abom-signed.json",
        ...     on_drift=lambda e: print(f"DRIFT: {e}")
        ... )
        >>> monitor.start()  # Runs in background
        >>> # ... later ...
        >>> monitor.stop()
    """
    
    def __init__(
        self,
        abom_path: Optional[str] = None,
        abom: Optional[Any] = None,
        config: Optional[MonitorConfig] = None,
        on_drift: Optional[Callable] = None,
        on_violation: Optional[Callable] = None,
        on_attestation: Optional[Callable] = None,
        emitter: Optional[Any] = None,
        system_name: Optional[str] = None,
        environment: str = "production",
        **kwargs
    ):
        """
        Initialize monitor.
        
        Args:
            abom_path: Path to signed ABOM file
            abom: ABOM object (alternative to path)
            config: Monitor configuration
            on_drift: Callback for drift events
            on_violation: Callback for violation events
            on_attestation: Callback for attestation events
            emitter: RADEEmitter for event handling
            system_name: System name for events
            environment: Environment name
            **kwargs: Additional config overrides
        """
        # Lazy imports to avoid circular dependencies
        from ..abom import ABOM
        from ..validation import DriftDetector, RADEEmitter
        
        # Load ABOM
        if abom:
            self.abom = abom
        elif abom_path:
            self.abom = ABOM.from_file(abom_path)
        else:
            raise ValueError("Either abom_path or abom must be provided")
        
        self.abom_path = abom_path
        
        # Configuration
        self.config = config or MonitorConfig()
        
        # Apply kwargs overrides
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        
        # Event handling
        self.on_drift = on_drift
        self.on_violation = on_violation
        self.on_attestation = on_attestation
        
        # Emitter
        sys_name = system_name or self.abom.metadata.get_property("ai.system.name") or "unknown"
        self.emitter = emitter or RADEEmitter(
            system_name=sys_name,
            environment=environment,
            fail_on_critical=self.config.fail_on_critical
        )
        
        # Detector
        self.detector = DriftDetector(
            abom=self.abom,
            system_name=sys_name,
            environment=environment
        )
        
        # State
        self._state = MonitorState.STOPPED
        self._start_time: Optional[float] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Statistics
        self._stats = {
            "hash_checks": 0,
            "mcp_heartbeats": 0,
            "full_scans": 0,
            "drift_events": 0,
            "violations": 0,
            "attestations": 0,
        }
        
        # Timestamps
        self._last_hash_check: Optional[datetime] = None
        self._last_mcp_heartbeat: Optional[datetime] = None
        self._last_full_scan: Optional[datetime] = None
        
        # Component hash cache for fast checks
        self._hash_cache: Dict[str, str] = {}
        self._build_hash_cache()
    
    def _build_hash_cache(self) -> None:
        """Build cache of expected component hashes."""
        for comp in self.abom.components:
            if comp.hashes:
                self._hash_cache[comp.bom_ref] = comp.hashes[0].content
            
            path_prop = comp.get_property("ai.artifact.path")
            if path_prop and comp.hashes:
                self._hash_cache[path_prop] = comp.hashes[0].content
    
    def start(self, daemon: bool = True) -> None:
        """
        Start the monitor.
        
        Args:
            daemon: Run as daemon thread (terminates with main program)
        """
        if self._state == MonitorState.RUNNING:
            logger.warning("Monitor already running")
            return
        
        self._state = MonitorState.RUNNING
        self._start_time = time.time()
        self._stop_event.clear()
        
        self._thread = threading.Thread(target=self._run_loop, daemon=daemon)
        self._thread.start()
        
        logger.info("Monitor started")
    
    def stop(self) -> None:
        """Stop the monitor."""
        if self._state != MonitorState.RUNNING:
            return
        
        self._stop_event.set()
        self._state = MonitorState.STOPPED
        
        if self._thread:
            self._thread.join(timeout=5)
        
        logger.info("Monitor stopped")
    
    def pause(self) -> None:
        """Pause monitoring (can be resumed)."""
        if self._state == MonitorState.RUNNING:
            self._state = MonitorState.PAUSED
            logger.info("Monitor paused")
    
    def resume(self) -> None:
        """Resume monitoring."""
        if self._state == MonitorState.PAUSED:
            self._state = MonitorState.RUNNING
            logger.info("Monitor resumed")
    
    def get_status(self) -> MonitorStatus:
        """Get current monitor status."""
        uptime = 0.0
        if self._start_time:
            uptime = time.time() - self._start_time
        
        return MonitorStatus(
            state=self._state,
            last_hash_check=self._last_hash_check.isoformat() if self._last_hash_check else None,
            last_mcp_heartbeat=self._last_mcp_heartbeat.isoformat() if self._last_mcp_heartbeat else None,
            last_full_scan=self._last_full_scan.isoformat() if self._last_full_scan else None,
            components_checked=self._stats["hash_checks"],
            drift_events=self._stats["drift_events"],
            violations=self._stats["violations"],
            uptime_seconds=uptime,
        )
    
    def _run_loop(self) -> None:
        """Main monitoring loop."""
        last_hash = 0.0
        last_heartbeat = 0.0
        last_scan = 0.0
        
        while not self._stop_event.is_set():
            try:
                if self._state == MonitorState.PAUSED:
                    time.sleep(1)
                    continue
                
                now = time.time()
                
                # Hash checks (most frequent)
                if now - last_hash >= self.config.hash_check_interval:
                    self._do_hash_check()
                    last_hash = now
                
                # MCP heartbeat
                if now - last_heartbeat >= self.config.mcp_heartbeat_interval:
                    self._do_mcp_heartbeat()
                    last_heartbeat = now
                
                # Full scan (least frequent)
                if now - last_scan >= self.config.full_scan_interval:
                    self._do_full_scan()
                    last_scan = now
                
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                self._state = MonitorState.ERROR
                time.sleep(5)
                self._state = MonitorState.RUNNING
    
    def _do_hash_check(self) -> None:
        """Perform fast hash integrity checks."""
        logger.debug("Running hash check")
        self._stats["hash_checks"] += 1
        self._last_hash_check = datetime.utcnow()
        
        for comp in self.abom.components:
            if comp.bom_ref in self.config.skip_components:
                continue
            
            path_prop = comp.get_property("ai.artifact.path")
            if not path_prop:
                continue
            
            path = Path(path_prop).expanduser()
            if not path.exists():
                continue
            
            if comp.hashes:
                expected = comp.hashes[0].content
                actual = self._compute_hash(path)
                
                if actual != expected:
                    event = self.detector.check_component(comp.bom_ref, actual)
                    self._handle_event(event)
    
    def _do_mcp_heartbeat(self) -> None:
        """Check MCP server availability."""
        logger.debug("Running MCP heartbeat")
        self._stats["mcp_heartbeats"] += 1
        self._last_mcp_heartbeat = datetime.utcnow()
        
        mcp_servers = self.abom.get_mcp_servers()
        
        for mcp in mcp_servers:
            if mcp.bom_ref in self.config.skip_components:
                continue
            
            endpoint = mcp.get_property("ai.mcp.endpoint")
            if not endpoint or endpoint.startswith("stdio://"):
                continue
            
            is_alive = self._check_endpoint(endpoint)
            
            if not is_alive:
                from ..validation.events import DriftEvent, Observation
                event = DriftEvent(
                    observation=Observation(
                        type="mcp-unavailable",
                        result="non-compliant",
                        component_ref=mcp.bom_ref,
                        details=f"MCP server {mcp.name} not responding at {endpoint}"
                    ),
                    abom_serial=self.abom.serial_number,
                    severity="high"
                )
                self._handle_event(event)
    
    def _do_full_scan(self) -> None:
        """Perform full system re-scan."""
        logger.debug("Running full scan")
        self._stats["full_scans"] += 1
        self._last_full_scan = datetime.utcnow()
        
        from ..scanner import Scanner
        scanner = Scanner()
        
        result = scanner.scan(
            model_dirs=self.config.model_dirs,
            scan_libraries=False
        )
        
        self._compare_scan_result(result)
    
    def _compare_scan_result(self, result: Any) -> None:
        """Compare scan result against ABOM."""
        from ..validation.events import ViolationEvent, Observation
        
        known_mcp = {c.name for c in self.abom.get_mcp_servers()}
        
        for mcp in result.mcp_servers:
            if mcp.name not in known_mcp:
                event = ViolationEvent(
                    observation=Observation(
                        type="undeclared-mcp",
                        result="non-compliant",
                        component_ref=f"mcp:{mcp.name}",
                        details=f"Undeclared MCP server discovered: {mcp.name} at {mcp.endpoint}",
                        actual=mcp.endpoint,
                        expected="Not in ABOM"
                    ),
                    abom_serial=self.abom.serial_number,
                    severity="critical"
                )
                self._handle_event(event)
    
    def _handle_event(self, event: Any) -> None:
        """Handle a detected event."""
        event_type = getattr(event, 'event_type', 'unknown')
        
        if event_type == "drift":
            self._stats["drift_events"] += 1
            if self.on_drift:
                self.on_drift(event)
        elif event_type == "violation":
            self._stats["violations"] += 1
            if self.on_violation:
                self.on_violation(event)
        elif event_type == "attestation":
            self._stats["attestations"] += 1
            if self.on_attestation:
                self.on_attestation(event)
        
        self.emitter.emit(event)
    
    def _compute_hash(self, filepath: Path) -> str:
        """Compute SHA-256 hash of file."""
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _check_endpoint(self, endpoint: str, timeout: float = 5.0) -> bool:
        """Check if an HTTP endpoint is reachable."""
        try:
            req = urllib.request.Request(endpoint, method="HEAD")
            urllib.request.urlopen(req, timeout=timeout)
            return True
        except Exception:
            try:
                req = urllib.request.Request(endpoint, method="GET")
                urllib.request.urlopen(req, timeout=timeout)
                return True
            except Exception:
                return False
    
    def check_now(self) -> List[Any]:
        """
        Run all checks immediately and return events.
        
        Returns:
            List of events detected
        """
        events = []
        
        original_drift = self.on_drift
        original_violation = self.on_violation
        
        def collect_event(e):
            events.append(e)
        
        self.on_drift = collect_event
        self.on_violation = collect_event
        
        try:
            self._do_hash_check()
            self._do_mcp_heartbeat()
            self._do_full_scan()
        finally:
            self.on_drift = original_drift
            self.on_violation = original_violation
        
        return events
