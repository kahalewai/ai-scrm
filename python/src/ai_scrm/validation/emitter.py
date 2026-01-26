"""
RADE Emitter - AI-SCS Section 7.3 & 7.4 Event Emission

This module implements the event emission requirements from AI-SCS Section 7.3
and the response integration capabilities from Section 7.4.

AI-SCS 7.3 Requirements:
    Systems MUST emit structured events for all validation failures and
    MUST NOT continue normal operation without explicit policy approval after:
    - Verification failures of models, dependencies, or runtime libraries
    - ABOM deviations (undeclared MCP servers, tools, prompts, etc.)
    - Trust expiration of cryptographic or attested artifacts
    - Policy violations (unauthorized execution of tools, agents, services)

AI-SCS 7.4 Response Integration:
    Implementations MAY integrate with:
    - SIEM (Security Information and Event Management)
    - SOAR (Security Orchestration, Automation, and Response)
    - Policy engines
    - Risk scoring systems

Usage:
    >>> from ai_scrm.validation import RADEEmitter, DriftEvent
    >>>
    >>> emitter = RADEEmitter(system_name="my-agent")
    >>> emitter.add_file_handler("./events.jsonl")
    >>> emitter.add_handler(send_to_siem)
    >>>
    >>> event = DriftEvent(...)
    >>> emitter.emit(event)

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import List, Callable, Optional, Union, Any, Dict
from datetime import datetime, timezone

from ai_scrm.validation.events import RADEEvent, DriftEvent, ViolationEvent
from ai_scrm.validation.exceptions import ValidationError

# Configure logging
logger = logging.getLogger(__name__)


class RADEEmitter:
    """
    Emits RADE events to configured handlers.
    
    AI-SCS 7.4 allows integration with SIEM, SOAR, policy engines,
    and risk scoring systems. This class provides a flexible handler
    architecture to support these integrations.
    
    Built-in Handlers:
        - File handler (JSONL format for log aggregation)
        - Stdout handler (for debugging)
        - Callback handler (for custom integrations)
    
    Attributes:
        system_name: Name of the system emitting events
        environment: Deployment environment
        fail_on_critical: Whether to raise exception on critical events
    
    Example:
        >>> emitter = RADEEmitter(system_name="my-agent")
        >>> emitter.add_file_handler("events.jsonl")
        >>> emitter.add_handler(lambda e: send_to_splunk(e.to_dict()))
        >>>
        >>> for event in detector.check(path):
        ...     emitter.emit(event)
    
    Test Cases:
        Input: emit(drift_event) with file handler
        Expected: Event JSON appended to file
        
        Input: emit(critical_event) with fail_on_critical=True
        Expected: ValidationError raised after emission
    """
    
    def __init__(
        self,
        system_name: Optional[str] = None,
        environment: Optional[str] = None,
        fail_on_critical: bool = False
    ) -> None:
        """
        Initialize RADE emitter.
        
        Args:
            system_name: Name of system (added to all events)
            environment: Environment name (production, staging, etc.)
            fail_on_critical: Raise exception on critical events (7.3 compliance)
        """
        self.system_name = system_name
        self.environment = environment
        self.fail_on_critical = fail_on_critical
        self._handlers: List[Callable[[RADEEvent], None]] = []
        self._event_count = 0
        self._drift_count = 0
        self._violation_count = 0
        
        logger.debug(f"RADEEmitter initialized for system={system_name}")
    
    def add_handler(self, handler: Callable[[RADEEvent], None]) -> "RADEEmitter":
        """
        Add custom event handler.
        
        Handlers are called in order for each emitted event.
        Use this for SIEM/SOAR integration per AI-SCS 7.4.
        
        Args:
            handler: Callable that receives RADEEvent
        
        Returns:
            self for method chaining
        
        Example:
            >>> def siem_handler(event):
            ...     requests.post(SIEM_URL, json=event.to_dict())
            >>> emitter.add_handler(siem_handler)
        """
        self._handlers.append(handler)
        logger.debug(f"Handler added: {handler.__name__ if hasattr(handler, '__name__') else 'anonymous'}")
        return self
    
    def add_stdout_handler(self, pretty: bool = True) -> "RADEEmitter":
        """
        Add handler that prints events to stdout.
        
        Args:
            pretty: Format with indentation
        
        Returns:
            self for method chaining
        """
        def stdout_handler(event: RADEEvent) -> None:
            print(event.to_json(pretty=pretty))
        
        self._handlers.append(stdout_handler)
        return self
    
    def add_stderr_handler(self, pretty: bool = False) -> "RADEEmitter":
        """
        Add handler that prints events to stderr.
        
        Useful for separating event output from normal output.
        
        Args:
            pretty: Format with indentation
        
        Returns:
            self for method chaining
        """
        def stderr_handler(event: RADEEvent) -> None:
            print(event.to_json(pretty=pretty), file=sys.stderr)
        
        self._handlers.append(stderr_handler)
        return self
    
    def add_file_handler(
        self,
        path: Union[str, Path],
        append: bool = True,
        rotate_size_mb: Optional[int] = None
    ) -> "RADEEmitter":
        """
        Add handler that writes events to JSONL file.
        
        JSONL (JSON Lines) format is standard for log aggregation
        systems like Splunk, ELK, etc.
        
        Args:
            path: Output file path
            append: Append to existing file (default) or overwrite
            rotate_size_mb: Rotate file when it exceeds this size
        
        Returns:
            self for method chaining
        
        Example:
            >>> emitter.add_file_handler("./logs/rade-events.jsonl")
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        def file_handler(event: RADEEvent) -> None:
            # Check rotation
            if rotate_size_mb and path.exists():
                size_mb = path.stat().st_size / (1024 * 1024)
                if size_mb >= rotate_size_mb:
                    # Rotate file
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    rotated = path.with_suffix(f".{timestamp}.jsonl")
                    path.rename(rotated)
                    logger.info(f"Rotated log file to {rotated}")
            
            mode = "a" if append else "w"
            with open(path, mode, encoding="utf-8") as f:
                f.write(event.to_json(pretty=False) + "\n")
        
        self._handlers.append(file_handler)
        logger.debug(f"File handler added: {path}")
        return self
    
    def add_webhook_handler(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30
    ) -> "RADEEmitter":
        """
        Add handler that POSTs events to a webhook.
        
        Useful for integration with external systems.
        
        Args:
            url: Webhook URL
            headers: Optional HTTP headers
            timeout: Request timeout in seconds
        
        Returns:
            self for method chaining
        
        Note:
            Requires 'requests' package to be installed.
        """
        try:
            import requests
        except ImportError:
            raise ValidationError(
                "requests package required for webhook handler. "
                "Install with: pip install requests"
            )
        
        def webhook_handler(event: RADEEvent) -> None:
            try:
                response = requests.post(
                    url,
                    json=event.to_dict(),
                    headers=headers or {"Content-Type": "application/json"},
                    timeout=timeout
                )
                response.raise_for_status()
            except Exception as e:
                logger.error(f"Webhook delivery failed: {e}")
        
        self._handlers.append(webhook_handler)
        logger.debug(f"Webhook handler added: {url}")
        return self
    
    def add_logging_handler(self, level: int = logging.WARNING) -> "RADEEmitter":
        """
        Add handler that logs events using Python logging.
        
        Args:
            level: Logging level for events
        
        Returns:
            self for method chaining
        """
        def logging_handler(event: RADEEvent) -> None:
            # Map severity to log level
            severity_to_level = {
                "info": logging.INFO,
                "low": logging.INFO,
                "medium": logging.WARNING,
                "high": logging.ERROR,
                "critical": logging.CRITICAL,
            }
            log_level = severity_to_level.get(event.severity, level)
            
            logger.log(
                log_level,
                f"RADE [{event.event_type.upper()}] {event.observation.details}",
                extra={"rade_event": event.to_dict()}
            )
        
        self._handlers.append(logging_handler)
        return self
    
    def emit(self, event: RADEEvent) -> None:
        """
        Emit a RADE event to all handlers.
        
        AI-SCS 7.3: Systems MUST emit structured events for validation failures.
        
        If system_name or environment are set on the emitter, they will be
        added to events that don't have them set.
        
        Args:
            event: RADE event to emit
        
        Raises:
            ValidationError: If fail_on_critical=True and event is critical
        
        Example:
            >>> emitter.emit(drift_event)
        """
        # Set defaults from emitter
        if not event.system_name and self.system_name:
            event.system_name = self.system_name
        if not event.environment and self.environment:
            event.environment = self.environment
        
        # Update statistics
        self._event_count += 1
        if event.event_type == "drift":
            self._drift_count += 1
        elif event.event_type == "violation":
            self._violation_count += 1
        
        # Call all handlers
        for handler in self._handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Handler error: {e}")
        
        # Check for critical events
        if self.fail_on_critical and event.severity == "critical":
            raise ValidationError(
                f"Critical validation failure: {event.observation.details} "
                f"(AI-SCS 7.3: MUST NOT continue without policy approval)"
            )
    
    def emit_all(self, events: List[RADEEvent]) -> None:
        """
        Emit multiple events.
        
        Args:
            events: List of events to emit
        """
        for event in events:
            self.emit(event)
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get emission statistics.
        
        Returns:
            dict: Counts of total, drift, and violation events
        """
        return {
            "total_events": self._event_count,
            "drift_events": self._drift_count,
            "violation_events": self._violation_count,
        }
    
    def reset_statistics(self) -> None:
        """Reset emission statistics."""
        self._event_count = 0
        self._drift_count = 0
        self._violation_count = 0
    
    def clear_handlers(self) -> "RADEEmitter":
        """
        Remove all handlers.
        
        Returns:
            self for method chaining
        """
        self._handlers.clear()
        return self


class PolicyEngine:
    """
    Policy engine for automated response to RADE events.
    
    AI-SCS 7.2.1 requires enforcement capabilities. This class
    provides rule-based automated response to validation events.
    
    Attributes:
        rules: List of (condition, action) tuples
        default_action: Action when no rules match
    
    Example:
        >>> engine = PolicyEngine()
        >>> engine.add_rule(
        ...     lambda e: e.severity == "critical",
        ...     lambda e: block_execution()
        ... )
        >>> engine.add_rule(
        ...     lambda e: e.event_type == "drift",
        ...     lambda e: send_alert(e)
        ... )
        >>> 
        >>> emitter.add_handler(engine.evaluate)
    """
    
    def __init__(
        self,
        default_action: Optional[Callable[[RADEEvent], None]] = None
    ) -> None:
        """
        Initialize policy engine.
        
        Args:
            default_action: Action when no rules match
        """
        self._rules: List[tuple] = []
        self.default_action = default_action
    
    def add_rule(
        self,
        condition: Callable[[RADEEvent], bool],
        action: Callable[[RADEEvent], None]
    ) -> "PolicyEngine":
        """
        Add a policy rule.
        
        Rules are evaluated in order. First matching rule's action is executed.
        
        Args:
            condition: Function that returns True if rule applies
            action: Function to execute when rule matches
        
        Returns:
            self for method chaining
        """
        self._rules.append((condition, action))
        return self
    
    def evaluate(self, event: RADEEvent) -> None:
        """
        Evaluate event against policy rules.
        
        Args:
            event: Event to evaluate
        """
        for condition, action in self._rules:
            try:
                if condition(event):
                    action(event)
                    return
            except Exception as e:
                logger.error(f"Policy rule error: {e}")
        
        # No rule matched, use default
        if self.default_action:
            self.default_action(event)
