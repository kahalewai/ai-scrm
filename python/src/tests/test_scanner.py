"""
Tests for AI-SCRM Scanner module.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from ai_scrm.scanner import (
    Scanner,
    ScanResult,
    DiscoveredModel,
    DiscoveredMCP,
    DiscoveredLibrary,
    MCPDiscovery,
    TrustBoundaryClassifier,
    infer_model_info,
    infer_format_from_extension,
    infer_quantization,
)


class TestModelInference(unittest.TestCase):
    """Tests for model name inference."""
    
    def test_infer_llama_model(self):
        """Test Llama model inference."""
        info = infer_model_info("llama-3-8b-instruct.safetensors")
        self.assertIsNotNone(info)
        self.assertEqual(info.supplier, "Meta")
        self.assertEqual(info.architecture, "llama")
        self.assertEqual(info.model_type, "fine-tuned")  # 'instruct' indicates fine-tuned
    
    def test_infer_mistral_model(self):
        """Test Mistral model inference."""
        info = infer_model_info("mistral-7b-v0.1.gguf")
        self.assertIsNotNone(info)
        self.assertEqual(info.supplier, "Mistral AI")
        self.assertEqual(info.architecture, "mistral")
    
    def test_infer_gpt_model(self):
        """Test GPT model inference."""
        info = infer_model_info("gpt-4-turbo.onnx")
        self.assertIsNotNone(info)
        self.assertEqual(info.supplier, "OpenAI")
        self.assertEqual(info.family, "GPT-4 Turbo")
    
    def test_infer_claude_model(self):
        """Test Claude model inference."""
        info = infer_model_info("claude-3-sonnet.bin")
        self.assertIsNotNone(info)
        self.assertEqual(info.supplier, "Anthropic")
    
    def test_infer_embedding_model(self):
        """Test embedding model inference."""
        info = infer_model_info("text-embedding-ada-002.onnx")
        self.assertIsNotNone(info)
        self.assertEqual(info.supplier, "OpenAI")
        self.assertEqual(info.model_type, "embedding")
    
    def test_infer_parameters(self):
        """Test parameter extraction from filename."""
        info = infer_model_info("llama-3-70b.safetensors")
        self.assertIsNotNone(info)
        self.assertEqual(info.parameters, "70B")
    
    def test_infer_unknown_model(self):
        """Test unknown model returns None."""
        info = infer_model_info("totally-unknown-model.bin")
        self.assertIsNone(info)
    
    def test_infer_lora_adapter(self):
        """Test LoRA adapter detection."""
        info = infer_model_info("llama-3-8b-lora-adapter.safetensors")
        self.assertIsNotNone(info)
        self.assertEqual(info.model_type, "adapter")


class TestFormatInference(unittest.TestCase):
    """Tests for format inference from file extension."""
    
    def test_safetensors(self):
        self.assertEqual(infer_format_from_extension("model.safetensors"), "safetensors")
    
    def test_gguf(self):
        self.assertEqual(infer_format_from_extension("model.gguf"), "gguf")
    
    def test_pytorch(self):
        self.assertEqual(infer_format_from_extension("model.pt"), "pytorch")
        self.assertEqual(infer_format_from_extension("model.pth"), "pytorch")
    
    def test_onnx(self):
        self.assertEqual(infer_format_from_extension("model.onnx"), "onnx")
    
    def test_unknown(self):
        self.assertIsNone(infer_format_from_extension("model.xyz"))


class TestQuantizationInference(unittest.TestCase):
    """Tests for quantization inference."""
    
    def test_q4_k_m(self):
        self.assertEqual(infer_quantization("model-q4_k_m.gguf"), "GGUF-Q4_K_M")
    
    def test_q8_0(self):
        self.assertEqual(infer_quantization("model-q8_0.gguf"), "GGUF-Q8_0")
    
    def test_awq(self):
        self.assertEqual(infer_quantization("model-awq.safetensors"), "AWQ")
    
    def test_no_quant(self):
        self.assertIsNone(infer_quantization("model.safetensors"))


class TestTrustBoundaryClassifier(unittest.TestCase):
    """Tests for trust boundary classification."""
    
    def setUp(self):
        self.classifier = TrustBoundaryClassifier(default_boundary="external")
    
    def test_localhost_internal(self):
        """Localhost should be internal."""
        self.assertEqual(
            self.classifier.classify("http://localhost:3000"),
            "internal"
        )
    
    def test_127_0_0_1_internal(self):
        """127.0.0.1 should be internal."""
        self.assertEqual(
            self.classifier.classify("http://127.0.0.1:8080"),
            "internal"
        )
    
    def test_private_ip_internal(self):
        """Private IP ranges should be internal."""
        self.assertEqual(
            self.classifier.classify("http://192.168.1.100:3000"),
            "internal"
        )
        self.assertEqual(
            self.classifier.classify("http://10.0.0.50:3000"),
            "internal"
        )
    
    def test_external_url(self):
        """Public URLs should be external."""
        self.assertEqual(
            self.classifier.classify("https://api.example.com/mcp"),
            "external"
        )
    
    def test_stdio_internal(self):
        """stdio:// should be internal."""
        self.assertEqual(
            self.classifier.classify("stdio://npx server-filesystem"),
            "internal"
        )
    
    def test_custom_pattern(self):
        """Custom patterns should work."""
        self.classifier.add_pattern("*.mycompany.com", "internal")
        self.assertEqual(
            self.classifier.classify("http://api.mycompany.com:3000"),
            "internal"
        )
    
    def test_default_boundary(self):
        """Unknown endpoints should get default boundary."""
        self.assertEqual(
            self.classifier.classify("http://unknown-server.io/mcp"),
            "external"
        )


class TestMCPDiscovery(unittest.TestCase):
    """Tests for MCP server discovery."""
    
    def test_parse_claude_desktop_config(self):
        """Test parsing Claude Desktop config format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config = {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                    },
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "env": {"GITHUB_TOKEN": "xxx"}
                    }
                }
            }
            json.dump(config, f)
            f.flush()
            
            discovery = MCPDiscovery(config_paths=[f.name])
            servers = discovery.discover_from_file(f.name)
            
            self.assertEqual(len(servers), 2)
            
            names = {s.name for s in servers}
            self.assertIn("filesystem", names)
            self.assertIn("github", names)
            
            os.unlink(f.name)
    
    def test_parse_generic_config(self):
        """Test parsing generic MCP config format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config = {
                "servers": [
                    {"name": "database", "endpoint": "http://localhost:3001"},
                    {"name": "search", "endpoint": "http://localhost:3002", "capabilities": ["search"]}
                ]
            }
            json.dump(config, f)
            f.flush()
            
            discovery = MCPDiscovery(config_paths=[f.name])
            servers = discovery.discover_from_file(f.name)
            
            self.assertEqual(len(servers), 2)
            
            search = next(s for s in servers if s.name == "search")
            self.assertEqual(search.capabilities, ["search"])
            
            os.unlink(f.name)
    
    def test_discover_from_env(self):
        """Test discovery from environment variables."""
        with patch.dict(os.environ, {"MCP_DATABASE_URL": "http://localhost:5432"}):
            discovery = MCPDiscovery(config_paths=[])
            discovery._discover_from_env()
            
            self.assertIn("database", discovery._discovered)


class TestScanner(unittest.TestCase):
    """Tests for the main Scanner class."""
    
    def test_scan_empty_directory(self):
        """Test scanning an empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = Scanner()
            result = scanner.scan(model_dirs=[tmpdir], scan_libraries=False, scan_mcp=False)
            
            self.assertIsInstance(result, ScanResult)
            self.assertEqual(len(result.models), 0)
    
    def test_scan_finds_model_file(self):
        """Test that scanner finds model files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake model file (>1MB)
            model_path = Path(tmpdir) / "llama-3-8b.safetensors"
            with open(model_path, 'wb') as f:
                f.write(b'0' * 1_500_000)  # 1.5MB
            
            scanner = Scanner()
            result = scanner.scan(
                model_dirs=[tmpdir], 
                scan_libraries=False, 
                scan_mcp=False,
                scan_huggingface_cache=False
            )
            
            self.assertEqual(len(result.models), 1)
            model = result.models[0]
            self.assertIn("llama", model.name.lower())
            self.assertEqual(model.supplier, "Meta")  # Inferred
            self.assertIsNotNone(model.hash_value)
    
    def test_scan_skips_small_files(self):
        """Test that scanner skips small files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a small file
            model_path = Path(tmpdir) / "tiny.safetensors"
            with open(model_path, 'wb') as f:
                f.write(b'0' * 1000)  # 1KB - too small
            
            scanner = Scanner()
            result = scanner.scan(
                model_dirs=[tmpdir], 
                scan_libraries=False, 
                scan_mcp=False,
                scan_huggingface_cache=False
            )
            
            self.assertEqual(len(result.models), 0)
    
    def test_scan_result_summary(self):
        """Test ScanResult summary."""
        result = ScanResult(
            models=[DiscoveredModel(name="test", path="/test", hash_value="abc")],
            mcp_servers=[DiscoveredMCP(name="test-mcp", endpoint="http://localhost")],
            libraries=[DiscoveredLibrary(name="test-lib", version="1.0")],
        )
        
        summary = result.summary()
        self.assertEqual(summary["models"], 1)
        self.assertEqual(summary["mcp_servers"], 1)
        self.assertEqual(summary["libraries"], 1)
    
    def test_scan_quick(self):
        """Test quick scan method."""
        scanner = Scanner()
        # Just verify it doesn't crash
        result = scanner.scan_quick()
        self.assertIsInstance(result, ScanResult)


class TestDiscoveredModel(unittest.TestCase):
    """Tests for DiscoveredModel dataclass."""
    
    def test_to_dict(self):
        """Test serialization to dict."""
        model = DiscoveredModel(
            name="test-model",
            path="/path/to/model",
            hash_value="abc123",
            format="safetensors",
            supplier="Test Corp"
        )
        
        d = model.to_dict()
        self.assertEqual(d["name"], "test-model")
        self.assertEqual(d["hash_value"], "abc123")
        self.assertEqual(d["supplier"], "Test Corp")
    
    def test_needs_review_tracking(self):
        """Test tracking of fields needing review."""
        model = DiscoveredModel(
            name="unknown-model",
            path="/path",
            hash_value="xyz",
            needs_review=["supplier"]
        )
        
        self.assertIn("supplier", model.needs_review)


class TestDiscoveredMCP(unittest.TestCase):
    """Tests for DiscoveredMCP dataclass."""
    
    def test_to_dict(self):
        """Test serialization to dict."""
        mcp = DiscoveredMCP(
            name="filesystem",
            endpoint="http://localhost:3000",
            capabilities=["read", "write"],
            trust_boundary="internal"
        )
        
        d = mcp.to_dict()
        self.assertEqual(d["name"], "filesystem")
        self.assertEqual(d["trust_boundary"], "internal")
        self.assertEqual(len(d["capabilities"]), 2)


if __name__ == "__main__":
    unittest.main()
