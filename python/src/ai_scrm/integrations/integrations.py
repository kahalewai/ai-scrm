"""
AI-SCRM Framework Integrations.

Provides one-liner integrations for common frameworks:
- LangChain agent guard
- FastAPI middleware
- Generic decorator

Example:
    >>> from ai_scrm.integrations import guard
    >>> @guard(tool="web-search")
    ... def search_web(query):
    ...     return results

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""

import functools
import logging
from typing import Any, Callable, List, Optional, Union
from pathlib import Path

logger = logging.getLogger(__name__)


# Global detector cache
_detector_cache = {}


def _get_detector(abom_path: str):
    """Get or create a cached detector."""
    if abom_path not in _detector_cache:
        from ..abom import ABOM
        from ..validation import DriftDetector
        
        abom = ABOM.from_file(abom_path)
        _detector_cache[abom_path] = DriftDetector(abom=abom)
    
    return _detector_cache[abom_path]


def guard(
    tool: Optional[str] = None,
    mcp: Optional[str] = None,
    component: Optional[str] = None,
    abom_path: str = "./abom-signed.json",
    on_violation: Optional[Callable] = None,
    raise_on_violation: bool = True
):
    """
    Decorator to guard function execution with AI-SCRM validation.
    
    Args:
        tool: Tool name to authorize
        mcp: MCP server name to authorize
        component: Component bom-ref to verify
        abom_path: Path to signed ABOM
        on_violation: Callback on violation (receives event)
        raise_on_violation: Whether to raise SecurityError
    
    Example:
        >>> @guard(tool="web-search")
        ... def search_web(query):
        ...     return search_api.search(query)
        
        >>> @guard(mcp="filesystem-mcp")
        ... def read_file(path):
        ...     return open(path).read()
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            detector = _get_detector(abom_path)
            event = None
            
            # Check authorization
            if tool:
                event = detector.check_tool_authorized(tool)
            elif mcp:
                event = detector.check_mcp_authorized(mcp)
            elif component:
                # For component, need actual hash
                actual_hash = kwargs.get('_hash')
                if actual_hash:
                    event = detector.check_component(component, actual_hash)
            
            # Handle result
            if event and not event.is_compliant():
                if on_violation:
                    on_violation(event)
                
                if raise_on_violation:
                    raise SecurityError(
                        f"AI-SCRM authorization failed: {event.observation.details}"
                    )
                
                return None
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


class SecurityError(Exception):
    """Raised when AI-SCRM authorization fails."""
    pass


def langchain_guard(
    agent: Any,
    abom_path: str = "./abom-signed.json",
    on_violation: Optional[Callable] = None
) -> Any:
    """
    Wrap a LangChain agent with AI-SCRM validation.
    
    Intercepts tool calls and validates against ABOM.
    
    Args:
        agent: LangChain agent/executor
        abom_path: Path to signed ABOM
        on_violation: Callback on violation
    
    Returns:
        Wrapped agent with validation
    
    Example:
        >>> from langchain.agents import create_react_agent
        >>> agent = create_react_agent(llm, tools, prompt)
        >>> secure_agent = langchain_guard(agent)
    """
    detector = _get_detector(abom_path)
    
    # Store original invoke
    original_invoke = agent.invoke
    
    def secure_invoke(input_data, config=None, **kwargs):
        # Get tools from agent if available
        tools = getattr(agent, 'tools', [])
        
        # Validate all tools before execution
        for tool in tools:
            tool_name = getattr(tool, 'name', str(tool))
            event = detector.check_tool_authorized(tool_name)
            
            if not event.is_compliant():
                if on_violation:
                    on_violation(event)
                raise SecurityError(
                    f"Unauthorized tool: {tool_name} - {event.observation.details}"
                )
        
        return original_invoke(input_data, config, **kwargs)
    
    # Replace invoke method
    agent.invoke = secure_invoke
    
    return agent


class FastAPIMiddleware:
    """
    FastAPI middleware for AI-SCRM validation.
    
    Validates requests against ABOM based on path patterns.
    
    Example:
        >>> from fastapi import FastAPI
        >>> from ai_scrm.integrations import FastAPIMiddleware
        >>> 
        >>> app = FastAPI()
        >>> app.add_middleware(FastAPIMiddleware, abom_path="abom.json")
    """
    
    def __init__(
        self,
        app: Any,
        abom_path: str = "./abom-signed.json",
        mcp_path_prefix: str = "/mcp/",
        on_violation: Optional[Callable] = None
    ):
        """
        Initialize middleware.
        
        Args:
            app: FastAPI application
            abom_path: Path to signed ABOM
            mcp_path_prefix: URL prefix for MCP endpoints
            on_violation: Callback on violation
        """
        self.app = app
        self.detector = _get_detector(abom_path)
        self.mcp_path_prefix = mcp_path_prefix
        self.on_violation = on_violation
    
    async def __call__(self, scope: dict, receive: Callable, send: Callable):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        path = scope.get("path", "")
        
        # Check MCP endpoints
        if path.startswith(self.mcp_path_prefix):
            mcp_name = path[len(self.mcp_path_prefix):].split("/")[0]
            event = self.detector.check_mcp_authorized(mcp_name)
            
            if not event.is_compliant():
                if self.on_violation:
                    self.on_violation(event)
                
                # Return 403 Forbidden
                response = {
                    "error": "Forbidden",
                    "detail": f"Unauthorized MCP: {event.observation.details}"
                }
                
                await send({
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [[b"content-type", b"application/json"]],
                })
                await send({
                    "type": "http.response.body",
                    "body": str(response).encode(),
                })
                return
        
        await self.app(scope, receive, send)


class EmergencyBypass:
    """
    Context manager for emergency bypass of AI-SCRM checks.
    
    All checks are disabled within the context, but activity is logged.
    
    Example:
        >>> from ai_scrm.integrations import emergency_bypass
        >>> 
        >>> with emergency_bypass(reason="Production incident #1234"):
        ...     # All checks disabled, but fully logged
        ...     do_emergency_fix()
    """
    
    _active = False
    _reason: Optional[str] = None
    _original_check_methods = {}
    
    def __init__(
        self,
        reason: str,
        log_callback: Optional[Callable] = None
    ):
        """
        Initialize bypass.
        
        Args:
            reason: Reason for bypass (logged)
            log_callback: Custom logging callback
        """
        self.reason = reason
        self.log_callback = log_callback or self._default_log
    
    def _default_log(self, message: str):
        logger.warning(f"EMERGENCY BYPASS: {message}")
    
    def __enter__(self):
        EmergencyBypass._active = True
        EmergencyBypass._reason = self.reason
        
        self.log_callback(f"Bypass activated - Reason: {self.reason}")
        
        # Patch detector methods to allow all
        from ..validation import DriftDetector
        
        for method_name in ['check_tool_authorized', 'check_mcp_authorized', 'check_component']:
            if hasattr(DriftDetector, method_name):
                original = getattr(DriftDetector, method_name)
                self._original_check_methods[method_name] = original
                
                def bypass_method(self, *args, **kwargs):
                    from ..validation.events import AttestationEvent, Observation
                    return AttestationEvent(
                        observation=Observation(
                            type="emergency-bypass",
                            result="compliant",
                            details=f"Bypassed: {EmergencyBypass._reason}"
                        ),
                        abom_serial="bypassed"
                    )
                
                setattr(DriftDetector, method_name, bypass_method)
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        EmergencyBypass._active = False
        EmergencyBypass._reason = None
        
        self.log_callback("Bypass deactivated")
        
        # Restore original methods
        from ..validation import DriftDetector
        
        for method_name, original in self._original_check_methods.items():
            setattr(DriftDetector, method_name, original)
        
        self._original_check_methods.clear()
        
        return False


# Convenience function
def emergency_bypass(reason: str, log_callback: Optional[Callable] = None) -> EmergencyBypass:
    """
    Create emergency bypass context.
    
    Args:
        reason: Reason for bypass
        log_callback: Custom logging callback
    
    Returns:
        Context manager
    """
    return EmergencyBypass(reason, log_callback)


def is_bypass_active() -> bool:
    """Check if emergency bypass is currently active."""
    return EmergencyBypass._active


def get_bypass_reason() -> Optional[str]:
    """Get reason for current bypass, if active."""
    return EmergencyBypass._reason
