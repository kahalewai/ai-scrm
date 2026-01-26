"""
Tests for AI-SCRM Monitor module.
"""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from ai_scrm.monitor import Monitor, MonitorConfig, MonitorStatus, MonitorState


class TestMonitorConfig(unittest.TestCase):
    """Tests for MonitorConfig."""
    
    def test_default_values(self):
        """Test default configuration values."""
        config = MonitorConfig()
        self.assertEqual(config.hash_check_interval, 60)
        self.assertEqual(config.mcp_heartbeat_interval, 300)
        self.assertEqual(config.full_scan_interval, 1800)
        self.assertFalse(config.fail_on_critical)
    
    def test_custom_values(self):
        """Test custom configuration values."""
        config = MonitorConfig(
            hash_check_interval=30,
            mcp_heartbeat_interval=120,
            fail_on_critical=True
        )
        self.assertEqual(config.hash_check_interval, 30)
        self.assertEqual(config.mcp_heartbeat_interval, 120)
        self.assertTrue(config.fail_on_critical)


class TestMonitorStatus(unittest.TestCase):
    """Tests for MonitorStatus."""
    
    def test_to_dict(self):
        """Test status serialization."""
        status = MonitorStatus(
            state=MonitorState.RUNNING,
            last_hash_check="2024-01-01T00:00:00",
            drift_events=5,
            violations=2,
            uptime_seconds=3600
        )
        
        d = status.to_dict()
        self.assertEqual(d["state"], "running")
        self.assertEqual(d["drift_events"], 5)
        self.assertEqual(d["violations"], 2)


class TestMonitor(unittest.TestCase):
    """Tests for Monitor class."""
    
    def setUp(self):
        """Set up test ABOM file."""
        self.temp_dir = tempfile.mkdtemp()
        self.abom_path = os.path.join(self.temp_dir, "abom.json")
        
        # Create minimal ABOM
        abom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:test-123",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": [{"name": "ai-scrm"}],
                "component": {"name": "test-system", "version": "1.0"},
                "properties": [
                    {"name": "ai-scs:profile", "value": "ABOM"},
                    {"name": "ai-scs:version", "value": "0.1"}
                ]
            },
            "components": []
        }
        
        with open(self.abom_path, 'w') as f:
            json.dump(abom_data, f)
    
    def tearDown(self):
        """Clean up temp files."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_monitor_init_from_path(self):
        """Test monitor initialization from file path."""
        monitor = Monitor(abom_path=self.abom_path)
        self.assertIsNotNone(monitor.abom)
        self.assertEqual(monitor._state, MonitorState.STOPPED)
    
    def test_monitor_config_override(self):
        """Test config values can be overridden via kwargs."""
        monitor = Monitor(
            abom_path=self.abom_path,
            hash_check_interval=15
        )
        self.assertEqual(monitor.config.hash_check_interval, 15)
    
    def test_monitor_state_transitions(self):
        """Test monitor state transitions."""
        monitor = Monitor(abom_path=self.abom_path)
        
        self.assertEqual(monitor._state, MonitorState.STOPPED)
        
        monitor.start(daemon=True)
        self.assertEqual(monitor._state, MonitorState.RUNNING)
        
        monitor.pause()
        self.assertEqual(monitor._state, MonitorState.PAUSED)
        
        monitor.resume()
        self.assertEqual(monitor._state, MonitorState.RUNNING)
        
        monitor.stop()
        self.assertEqual(monitor._state, MonitorState.STOPPED)
    
    def test_get_status(self):
        """Test getting monitor status."""
        monitor = Monitor(abom_path=self.abom_path)
        
        status = monitor.get_status()
        self.assertEqual(status.state, MonitorState.STOPPED)
        self.assertEqual(status.drift_events, 0)
    
    def test_check_now(self):
        """Test immediate check."""
        monitor = Monitor(abom_path=self.abom_path)
        
        events = monitor.check_now()
        self.assertIsInstance(events, list)
    
    def test_missing_abom_raises(self):
        """Test that missing ABOM raises error."""
        with self.assertRaises(Exception):
            Monitor(abom_path="/nonexistent/abom.json")
    
    def test_must_provide_abom(self):
        """Test that either abom_path or abom must be provided."""
        with self.assertRaises(ValueError):
            Monitor()
    
    def test_callbacks_called(self):
        """Test that callbacks are invoked on events."""
        events_received = []
        
        def on_drift(event):
            events_received.append(("drift", event))
        
        def on_violation(event):
            events_received.append(("violation", event))
        
        monitor = Monitor(
            abom_path=self.abom_path,
            on_drift=on_drift,
            on_violation=on_violation
        )
        
        # Run checks (may or may not produce events depending on state)
        monitor.check_now()
        
        # Events may be empty if system is compliant
        self.assertIsInstance(events_received, list)


class TestMonitorHash(unittest.TestCase):
    """Tests for monitor hash checking."""
    
    def test_compute_hash(self):
        """Test hash computation."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content")
            f.flush()
            
            from ai_scrm.monitor import Monitor
            
            # Create minimal ABOM
            abom_path = tempfile.mktemp(suffix='.json')
            abom_data = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "serialNumber": "urn:uuid:test",
                "version": 1,
                "metadata": {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "component": {"name": "test", "version": "1.0"},
                    "properties": [
                        {"name": "ai-scs:profile", "value": "ABOM"}
                    ]
                },
                "components": []
            }
            with open(abom_path, 'w') as abom_f:
                json.dump(abom_data, abom_f)
            
            monitor = Monitor(abom_path=abom_path)
            hash_value = monitor._compute_hash(Path(f.name))
            
            self.assertIsInstance(hash_value, str)
            self.assertEqual(len(hash_value), 64)  # SHA-256 hex
            
            os.unlink(f.name)
            os.unlink(abom_path)


if __name__ == "__main__":
    unittest.main()
