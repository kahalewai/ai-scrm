"""
AI-SCRM Command Line Interface.

Provides commands for:
- init: First-run setup (scan + template + keys)
- scan: Discover AI components
- abom: Build, validate, info commands
- trust: Keygen, sign, verify commands
- validation: Check, monitor commands
- status: Live status view
- approve/reject: Handle changes

AI-SCRM Supply Chain Tooling for AI Architecture
Version: 1.0.1
By: Shawn Kahalewai Reilly
Repo: HTTPS://github.com/kahalewai/ai-scrm
License: Apache License 2.0
"""

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional, List
from datetime import datetime

# Check for click availability
try:
    import click
    CLICK_AVAILABLE = True
except ImportError:
    CLICK_AVAILABLE = False

# Check for rich availability
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

logger = logging.getLogger(__name__)


# ============================================================
# Error Messages - Clear and Actionable
# ============================================================

ERROR_MESSAGES = {
    "abom_not_found": """
ABOM file not found: {path}

This could mean:
  - The file path is incorrect
  - You haven't created an ABOM yet

To fix:
  - Check the file path and try again
  - Run 'ai-scrm init' to create an ABOM
  - Run 'ai-scrm scan' to discover components
""",

    "signature_invalid": """
Signature validation failed for {path}

The ABOM file has been modified since it was signed.
This could mean:
  - Someone tampered with the file (security incident)
  - You made legitimate changes and forgot to re-sign

To fix:
  - If changes were intentional: ai-scrm sign {path}
  - If unexpected: Investigate first - this may be a security incident
""",

    "abom_unsigned": """
ABOM is not signed: {path}

Unsigned ABOMs cannot be verified for integrity.
In production, always use signed ABOMs.

To fix:
  - Run: ai-scrm trust sign {path}
  - Or generate keys first: ai-scrm trust keygen
""",

    "key_not_found": """
Private key not found: {path}

To fix:
  - Check the key path is correct
  - Generate new keys: ai-scrm trust keygen --output ./keys
  - Use an existing key: ai-scrm trust sign --key /path/to/key.pem
""",
}


def format_error(error_key: str, **kwargs) -> str:
    """Format an error message with context."""
    template = ERROR_MESSAGES.get(error_key, "Unknown error: {error_key}")
    return template.format(**kwargs, error_key=error_key)


# ============================================================
# CLI Setup
# ============================================================

if CLICK_AVAILABLE:
    
    @click.group()
    @click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
    @click.option('--quiet', '-q', is_flag=True, help='Suppress non-error output')
    @click.version_option(version='1.0.1')
    def cli(verbose, quiet):
        """AI-SCRM: AI Supply Chain Risk Management

        Secure your AI infrastructure with component discovery,
        signing, and continuous validation.
        
        Quick start:
          ai-scrm init          # First-time setup
          ai-scrm status        # View current status
          ai-scrm monitor       # Start continuous validation
        """
        level = logging.WARNING
        if verbose:
            level = logging.DEBUG
        elif quiet:
            level = logging.ERROR
        
        logging.basicConfig(level=level, format='%(message)s')

    # ============================================================
    # INIT Command - First Run Experience
    # ============================================================
    
    @cli.command()
    @click.option('--dir', '-d', 'scan_dir', default='.', help='Directory to scan')
    @click.option('--output', '-o', default='./abom.json', help='Output ABOM path')
    @click.option('--metadata', '-m', default='./ai-scrm-metadata.yaml', help='Metadata file path')
    @click.option('--keys', '-k', default='./keys', help='Keys directory')
    @click.option('--sign/--no-sign', default=True, help='Sign the ABOM')
    def init(scan_dir, output, metadata, keys, sign):
        """Initialize AI-SCRM for your project.

        This command:
        1. Scans for AI components (models, MCP servers, libraries)
        2. Generates a metadata template for manual review
        3. Creates an ABOM with discovered components
        4. Optionally generates keys and signs the ABOM
        """
        console = Console() if RICH_AVAILABLE else None
        
        def echo(msg):
            if console:
                console.print(msg)
            else:
                click.echo(msg)
        
        echo("\n=== AI-SCRM Initialization ===\n")
        
        # Step 1: Scan
        echo("Step 1/4: Scanning for AI components...")
        
        from ..scanner import Scanner, generate_template
        
        scanner = Scanner()
        result = scanner.scan(
            model_dirs=[scan_dir],
            scan_cwd=True,
            scan_huggingface_cache=True,
            scan_libraries=True,
            scan_mcp=True
        )
        
        summary = result.summary()
        echo(f"  Found: {summary['models']} models, {summary['mcp_servers']} MCP servers, "
             f"{summary['libraries']} libraries, {summary['prompts']} prompts")
        
        # Step 2: Generate metadata template
        echo("\nStep 2/4: Generating metadata template...")
        
        template_path = generate_template(result, metadata)
        
        todo_count = sum(1 for m in result.models if m.needs_review)
        echo(f"  Generated: {template_path}")
        if todo_count > 0:
            echo(f"  Warning: {todo_count} items need manual review (marked with TODO)")
        else:
            echo("  All items have complete metadata")
        
        # Step 3: Build ABOM
        echo("\nStep 3/4: Building ABOM...")
        
        from ..abom import ABOMBuilder
        
        builder = ABOMBuilder()
        
        # Add models
        for model in result.models:
            builder.add_model(
                name=model.name,
                version=model.version,
                hash_value=model.hash_value,
                format=model.format or "unknown",
                supplier=model.supplier or "TODO",
                model_type=model.model_type,
                architecture=model.architecture,
                parameters=model.parameters
            )
        
        # Add MCP servers
        for mcp in result.mcp_servers:
            builder.add_mcp_server(
                name=mcp.name,
                version=mcp.version or "1.0.0",
                endpoint=mcp.endpoint,
                trust_boundary=mcp.trust_boundary,
                capabilities=mcp.capabilities or ["unknown"]
            )
        
        # Add libraries (top 50)
        for lib in sorted(result.libraries, key=lambda x: x.name)[:50]:
            builder.add_library(name=lib.name, version=lib.version)
        
        # Add prompts
        for prompt in result.prompts:
            builder.add_prompt_template(
                name=prompt.name,
                version="1.0.0",
                prompt_type=prompt.prompt_type,
                hash_value=prompt.hash_value
            )
        
        # Finalize
        abom = builder.finalize(
            system_name=Path(scan_dir).resolve().name,
            system_version="1.0.0",
            validate=False
        )
        
        # Step 4: Sign (optional)
        if sign:
            echo("\nStep 4/4: Generating keys and signing...")
            
            from ..trust import Signer
            
            keys_path = Path(keys)
            keys_path.mkdir(parents=True, exist_ok=True)
            
            private_key = keys_path / "private.pem"
            
            if not private_key.exists():
                signer = Signer.generate("ed25519")
                signer.save_keys(str(keys_path))
                echo(f"  Generated keys: {keys_path}/")
            else:
                signer = Signer.from_file(str(private_key), "ed25519")
                echo(f"  Using existing keys: {keys_path}/")
            
            signer.sign(abom)
            echo("  ABOM signed")
            
            output_path = output.replace('.json', '-signed.json')
        else:
            echo("\nStep 4/4: Skipping signing (use --sign to enable)")
            output_path = output
        
        # Save ABOM
        abom.to_file(output_path)
        echo(f"\n  ABOM saved: {output_path}")
        
        # Summary
        echo("\n" + "=" * 50)
        echo("Initialization complete!")
        echo("=" * 50)
        
        echo("\nNext steps:")
        if todo_count > 0:
            echo(f"  1. Review {metadata} (fill in {todo_count} TODOs)")
            echo(f"  2. Run: ai-scrm sign {output_path}")
            echo(f"  3. Run: ai-scrm status")
            echo(f"  4. Run: ai-scrm monitor")
        else:
            echo(f"  1. Run: ai-scrm status")
            echo(f"  2. Run: ai-scrm monitor")

    # ============================================================
    # SCAN Command
    # ============================================================
    
    @cli.command()
    @click.option('--dir', '-d', 'scan_dirs', multiple=True, default=['.'], help='Directories to scan')
    @click.option('--output', '-o', help='Output scan results to JSON')
    def scan(scan_dirs, output):
        """Scan for AI components."""
        from ..scanner import Scanner
        
        scanner = Scanner()
        result = scanner.scan(model_dirs=list(scan_dirs))
        scanner.print_summary(result)
        
        if output:
            with open(output, 'w') as f:
                json.dump(result.to_dict(), f, indent=2)
            click.echo(f"\nResults saved to: {output}")

    # ============================================================
    # STATUS Command
    # ============================================================
    
    @cli.command()
    @click.option('--abom', '-a', 'abom_path', default='./abom-signed.json', help='ABOM file path')
    @click.option('--watch', '-w', is_flag=True, help='Continuously update status')
    @click.option('--interval', '-i', default=5, help='Update interval in seconds')
    def status(abom_path, watch, interval):
        """Show current system status."""
        from ..abom import ABOM
        from ..validation import DriftDetector
        
        if not Path(abom_path).exists():
            click.echo(format_error("abom_not_found", path=abom_path))
            sys.exit(1)
        
        abom = ABOM.from_file(abom_path)
        detector = DriftDetector(abom=abom)
        
        def render_status():
            models = abom.get_models()
            mcp_servers = abom.get_mcp_servers()
            tools = abom.get_tools()
            sig_status = "Signed" if abom.signature else "Unsigned"
            
            events = detector.check(".")
            drift_count = sum(1 for e in events if e.event_type == "drift")
            violation_count = sum(1 for e in events if e.event_type == "violation")
            
            lines = [
                "=" * 55,
                "  AI-SCRM Status",
                "=" * 55,
                f"  ABOM:       {abom_path}",
                f"  System:     {abom.metadata.get_property('ai.system.name') or 'Unknown'}",
                f"  Signature:  {sig_status}",
                "",
                f"  Models:       {len(models):>4}",
                f"  MCP Servers:  {len(mcp_servers):>4}",
                f"  Tools:        {len(tools):>4}",
                "",
                f"  Drift:        {drift_count:>4}",
                f"  Violations:   {violation_count:>4}",
                "",
            ]
            
            if drift_count == 0 and violation_count == 0:
                lines.append("  Status: ALL CLEAR")
            else:
                lines.append("  Status: ISSUES DETECTED")
            
            lines.extend([
                "",
                f"  Last check: {datetime.now().strftime('%H:%M:%S')}",
                "=" * 55,
            ])
            
            return "\n".join(lines)
        
        if watch:
            while True:
                os.system('clear' if os.name != 'nt' else 'cls')
                click.echo(render_status())
                time.sleep(interval)
        else:
            click.echo(render_status())

    # ============================================================
    # ABOM Commands
    # ============================================================
    
    @cli.group()
    def abom():
        """ABOM management commands."""
        pass
    
    @abom.command('validate')
    @click.argument('abom_path')
    @click.option('--strict', is_flag=True, help='Fail on any compliance issue')
    def abom_validate(abom_path, strict):
        """Validate an ABOM file."""
        from ..abom import ABOM
        
        if not Path(abom_path).exists():
            click.echo(format_error("abom_not_found", path=abom_path))
            sys.exit(1)
        
        abom = ABOM.from_file(abom_path)
        issues = abom.validate_ai_scs()
        
        if issues:
            click.echo(f"\n{len(issues)} compliance issues found:\n")
            for issue in issues:
                click.echo(f"  - {issue}")
            if strict:
                sys.exit(1)
        else:
            click.echo("ABOM is valid and AI-SCS compliant")
    
    @abom.command('info')
    @click.argument('abom_path')
    def abom_info(abom_path):
        """Display ABOM information."""
        from ..abom import ABOM
        
        if not Path(abom_path).exists():
            click.echo(format_error("abom_not_found", path=abom_path))
            sys.exit(1)
        
        abom = ABOM.from_file(abom_path)
        
        click.echo(f"\nABOM: {abom_path}")
        click.echo(f"Serial: {abom.serial_number}")
        click.echo(f"Signed: {'Yes' if abom.signature else 'No'}")
        click.echo(f"Components: {len(abom.components)}")

    # ============================================================
    # TRUST Commands
    # ============================================================
    
    @cli.group()
    def trust():
        """Trust and signing commands."""
        pass
    
    @trust.command('keygen')
    @click.option('--algorithm', '-a', default='ed25519', 
                  type=click.Choice(['ed25519', 'rsa', 'ecdsa']))
    @click.option('--output', '-o', default='./keys', help='Output directory')
    def trust_keygen(algorithm, output):
        """Generate signing keys."""
        from ..trust import Signer
        
        output_path = Path(output)
        output_path.mkdir(parents=True, exist_ok=True)
        
        signer = Signer.generate(algorithm)
        signer.save_keys(str(output_path))
        
        click.echo(f"Generated {algorithm} keys:")
        click.echo(f"  Private: {output_path}/private.pem")
        click.echo(f"  Public:  {output_path}/public.pem")
    
    @trust.command('sign')
    @click.argument('abom_path')
    @click.option('--key', '-k', default='./keys/private.pem', help='Private key path')
    @click.option('--algorithm', '-a', default='ed25519')
    @click.option('--output', '-o', help='Output path')
    def trust_sign(abom_path, key, algorithm, output):
        """Sign an ABOM."""
        from ..abom import ABOM
        from ..trust import Signer
        
        if not Path(abom_path).exists():
            click.echo(format_error("abom_not_found", path=abom_path))
            sys.exit(1)
        
        if not Path(key).exists():
            click.echo(format_error("key_not_found", path=key))
            sys.exit(1)
        
        abom = ABOM.from_file(abom_path)
        signer = Signer.from_file(key, algorithm)
        signer.sign(abom)
        
        output_path = output or abom_path.replace('.json', '-signed.json')
        abom.to_file(output_path)
        
        click.echo(f"ABOM signed: {output_path}")
    
    @trust.command('verify')
    @click.argument('abom_path')
    def trust_verify(abom_path):
        """Verify an ABOM signature."""
        from ..abom import ABOM
        from ..trust import Verifier
        from ..trust.exceptions import VerificationError
        
        if not Path(abom_path).exists():
            click.echo(format_error("abom_not_found", path=abom_path))
            sys.exit(1)
        
        abom = ABOM.from_file(abom_path)
        
        if not abom.signature:
            click.echo(format_error("abom_unsigned", path=abom_path))
            sys.exit(1)
        
        verifier = Verifier(reject_unsigned=True)
        
        try:
            verifier.verify(abom)
            click.echo("Signature valid")
        except VerificationError:
            click.echo(format_error("signature_invalid", path=abom_path))
            sys.exit(1)

    # ============================================================
    # VALIDATION Commands
    # ============================================================
    
    @cli.group()
    def validation():
        """Validation commands."""
        pass
    
    @validation.command('check')
    @click.option('--abom', '-a', 'abom_path', default='./abom-signed.json')
    @click.option('--dir', '-d', 'check_dir', default='.')
    @click.option('--output', '-o', help='Output events to file')
    def validation_check(abom_path, check_dir, output):
        """Check for drift against ABOM."""
        from ..abom import ABOM
        from ..validation import DriftDetector
        
        if not Path(abom_path).exists():
            click.echo(format_error("abom_not_found", path=abom_path))
            sys.exit(1)
        
        abom = ABOM.from_file(abom_path)
        detector = DriftDetector(abom=abom)
        
        events = detector.check(check_dir)
        
        compliant = sum(1 for e in events if e.is_compliant())
        drift = sum(1 for e in events if e.event_type == "drift")
        violations = sum(1 for e in events if e.event_type == "violation")
        
        click.echo(f"\nResults: {compliant} compliant, {drift} drift, {violations} violations")
        
        if output:
            with open(output, 'w') as f:
                for event in events:
                    f.write(json.dumps(event.to_dict()) + "\n")
            click.echo(f"Events saved to: {output}")
        
        if violations > 0:
            sys.exit(1)

    # ============================================================
    # MONITOR Command
    # ============================================================
    
    @cli.command()
    @click.option('--abom', '-a', 'abom_path', default='./abom-signed.json')
    @click.option('--hash-interval', default=60, help='Hash check interval (seconds)')
    @click.option('--mcp-interval', default=300, help='MCP heartbeat interval (seconds)')
    @click.option('--scan-interval', default=1800, help='Full scan interval (seconds)')
    @click.option('--output', '-o', help='Event log file')
    @click.option('--daemon', '-d', is_flag=True, help='Run in background (ignored, always foreground)')
    def monitor(abom_path, hash_interval, mcp_interval, scan_interval, output, daemon):
        """Start continuous monitoring."""
        from ..monitor import Monitor, MonitorConfig
        from ..validation import RADEEmitter
        
        if not Path(abom_path).exists():
            click.echo(format_error("abom_not_found", path=abom_path))
            sys.exit(1)
        
        config = MonitorConfig(
            hash_check_interval=hash_interval,
            mcp_heartbeat_interval=mcp_interval,
            full_scan_interval=scan_interval
        )
        
        emitter = RADEEmitter()
        if output:
            emitter.add_file_handler(output)
        
        def on_event(event):
            click.echo(f"[{event.event_type.upper()}] {event.observation.details}")
        
        mon = Monitor(
            abom_path=abom_path,
            config=config,
            on_drift=on_event,
            on_violation=on_event,
            emitter=emitter
        )
        
        click.echo(f"Starting monitor (Ctrl+C to stop)...")
        click.echo(f"  Hash: {hash_interval}s, MCP: {mcp_interval}s, Scan: {scan_interval}s\n")
        
        mon.start(daemon=False)
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            click.echo("\nStopping...")
            mon.stop()

    # ============================================================
    # APPROVE/REJECT Commands
    # ============================================================
    
    @cli.command()
    @click.argument('component')
    @click.option('--abom', '-a', 'abom_path', default='./abom-signed.json')
    @click.option('--trust', 'trust_boundary', default='internal',
                  type=click.Choice(['internal', 'external', 'hybrid']))
    def approve(component, abom_path, trust_boundary):
        """Approve a new or changed component."""
        click.echo(f"Approving: {component}")
        if click.confirm("This will modify the ABOM. Continue?"):
            click.echo(f"Approved {component}")
            click.echo(f"Run 'ai-scrm trust sign {abom_path}' to re-sign")
        else:
            click.echo("Cancelled")
    
    @cli.command()
    @click.argument('component')
    def reject(component):
        """Reject a detected component."""
        click.echo(f"Rejecting: {component}")
        if click.confirm("This will be logged as a security event. Continue?"):
            click.echo(f"Rejected {component}")
        else:
            click.echo("Cancelled")

    def main():
        """Main entry point."""
        cli()

else:
    def main():
        print("AI-SCRM CLI requires 'click' package.")
        print("Install with: pip install click")
        sys.exit(1)


if __name__ == "__main__":
    main()
